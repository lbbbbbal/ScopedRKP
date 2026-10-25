// SPDX-License-Identifier: GPL-3.0-only
#include "policy.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <cstdio>
using Callback=void (*)(void *,const char *,const char *,uint32_t);
using Read=void (*)(const prop_info *,Callback,void *);
using CallerUid=uid_t (*)();
extern "C" { __attribute__((visibility("default"))) constinit SrkpState srkp_state; }
static std::atomic<bool> installed{false};
static std::atomic_flag entering=ATOMIC_FLAG_INIT;
static CallerUid calling_uid;
static void **patched_slot;
struct Frame {Callback callback;void *cookie;uint32_t uid;};
static void callback_view(void *cookie,const char *name,const char *value,uint32_t serial) {
    auto *f=static_cast<Frame *>(cookie);
    f->callback(f->cookie,name,srkp_applies(srkp_state,f->uid,name,value)?"GLOBAL":value,serial);
}
static void read_view(const prop_info *pi,Callback callback,void *cookie) {
    if(!callback || !srkp_state.enabled.load()) {__system_property_read_callback(pi,callback,cookie);return;}
    Frame f{callback,cookie,static_cast<uint32_t>(calling_uid())};
    __system_property_read_callback(pi,callback_view,&f);
}
static bool target_matches() {
    char exe[512]{};
    const auto n=readlink("/proc/self/exe",exe,sizeof(exe)-1);
    if(n<=0 || n>=ssize_t(sizeof(exe)-1)) return false;
#ifdef SRKP_FIXTURE
    const char *base=strrchr(exe,'/');return base && !strcmp(base+1,"srkp_fixture");
#else
    return getuid()==1017 && !strcmp(exe,"/system/bin/keystore2");
#endif
}
struct Image { uintptr_t base; const ElfW(Phdr) *phdr; size_t count; };
static int find_main(dl_phdr_info *info, size_t, void *cookie) {
    if (reinterpret_cast<uintptr_t>(info->dlpi_phdr) != getauxval(AT_PHDR)) return 0;
    *static_cast<Image *>(cookie) = {info->dlpi_addr, info->dlpi_phdr, info->dlpi_phnum};
    return 1;
}
static bool contains(const Image &i, uintptr_t address, size_t bytes) {
    for (size_t n = 0; n < i.count; ++n) {
        const auto &p = i.phdr[n];
        if (p.p_type != PT_LOAD || p.p_memsz < bytes) continue;
        const uintptr_t start = i.base + p.p_vaddr;
        if (address >= start && address - start <= p.p_memsz - bytes) return true;
    }
    return false;
}
static uintptr_t address_of(const Image &i, uintptr_t value, size_t bytes) {
    if (contains(i, value, bytes)) return value;
    if (value <= UINTPTR_MAX - i.base && contains(i, i.base + value, bytes)) return i.base + value;
    return 0;
}

static void **find_read_slot(const Image &i) {
    const ElfW(Dyn) *dynamic = nullptr;
    size_t dynamic_count = 0;
    for (size_t n = 0; n < i.count; ++n) if (i.phdr[n].p_type == PT_DYNAMIC) {
        const uintptr_t address = i.base + i.phdr[n].p_vaddr;
        if (!contains(i, address, i.phdr[n].p_memsz)) return nullptr;
        dynamic = reinterpret_cast<const ElfW(Dyn) *>(address);
        dynamic_count = i.phdr[n].p_memsz / sizeof(*dynamic);
    }
    if (!dynamic || dynamic_count > 4096) return nullptr;
    uintptr_t strings = 0, symbols = 0, relocs = 0;
    size_t string_bytes = 0, reloc_bytes = 0, symbol_size = 0;
    long reloc_type = 0;
    for (size_t n = 0; n < dynamic_count && dynamic[n].d_tag != DT_NULL; ++n) {
        const auto &d = dynamic[n];
        switch (d.d_tag) {
            case DT_STRTAB: strings = d.d_un.d_ptr; break;
            case DT_STRSZ: string_bytes = d.d_un.d_val; break;
            case DT_SYMTAB: symbols = d.d_un.d_ptr; break;
            case DT_SYMENT: symbol_size = d.d_un.d_val; break;
            case DT_JMPREL: relocs = d.d_un.d_ptr; break;
            case DT_PLTRELSZ: reloc_bytes = d.d_un.d_val; break;
            case DT_PLTREL: reloc_type = d.d_un.d_val; break;
        }
    }
    if (symbol_size != sizeof(ElfW(Sym)) || reloc_type != DT_RELA || !string_bytes || string_bytes > 2000000
        || reloc_bytes % sizeof(ElfW(Rela)) || reloc_bytes / sizeof(ElfW(Rela)) > 8192) return nullptr;
    strings = address_of(i, strings, string_bytes);
    symbols = address_of(i, symbols, sizeof(ElfW(Sym)));
    relocs = address_of(i, relocs, reloc_bytes);
    if (!strings || !symbols || !relocs) return nullptr;
    void **found = nullptr;
    const auto *entries = reinterpret_cast<const ElfW(Rela) *>(relocs);
    for (size_t n = 0; n < reloc_bytes / sizeof(*entries); ++n) {
        const auto &r = entries[n];
        if (ELF64_R_TYPE(r.r_info) != R_AARCH64_JUMP_SLOT) continue;
        const size_t index = ELF64_R_SYM(r.r_info);
        if (index > 100000 || !contains(i, symbols + index * sizeof(ElfW(Sym)), sizeof(ElfW(Sym)))) return nullptr;
        const auto &s = reinterpret_cast<const ElfW(Sym) *>(symbols)[index];
        if (s.st_name >= string_bytes) return nullptr;
        const char *name = reinterpret_cast<const char *>(strings + s.st_name);
        if (!memchr(name, 0, string_bytes - s.st_name)) return nullptr;
        if (strcmp(name, "__system_property_read_callback") != 0) continue;
        const uintptr_t slot = address_of(i, r.r_offset, sizeof(void *));
        if (!slot || slot % alignof(void *) || found) return nullptr;
        found = reinterpret_cast<void **>(slot);
    }
    return found;
}

static int mapping_permissions(uintptr_t address) {
    FILE *file = fopen("/proc/self/maps", "re");
    if (!file) return -1;
    char line[1024];
    int result = -1;
    while (fgets(line, sizeof(line), file)) {
        unsigned long start, end;
        char permissions[5]{};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, permissions) == 3 && address >= start && address < end) {
            result = (permissions[0] == 'r' ? PROT_READ : 0) | (permissions[1] == 'w' ? PROT_WRITE : 0)
                | (permissions[2] == 'x' ? PROT_EXEC : 0);
            break;
        }
    }
    fclose(file);
    return result;
}

static bool install_once() {
    if (installed.load(std::memory_order_acquire)) return patched_slot &&
        __atomic_load_n(patched_slot, __ATOMIC_ACQUIRE) == reinterpret_cast<void *>(read_view);
    Image image{};
    dl_iterate_phdr(find_main, &image);
    if (!image.phdr || !target_matches()) return false;
    auto uid = reinterpret_cast<CallerUid>(dlsym(RTLD_DEFAULT, "AIBinder_getCallingUid"));
    if (!uid) {
        void *binder = dlopen("libbinder_ndk.so", RTLD_NOW | RTLD_NOLOAD);
        if (binder) {
            uid = reinterpret_cast<CallerUid>(dlsym(binder, "AIBinder_getCallingUid"));
            // Balance our temporary lookup reference; the main image already
            // depends on this library, so its function remains loaded.
            dlclose(binder);
        }
    }
    auto real = reinterpret_cast<Read>(dlsym(RTLD_DEFAULT, "__system_property_read_callback"));
    void **slot = find_read_slot(image);
    if (!uid || !real || !slot || __atomic_load_n(slot, __ATOMIC_ACQUIRE) != reinterpret_cast<void *>(real)) return false;
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 4096 || page_size > 65536 || (page_size & (page_size - 1))) return false;
    const uintptr_t page = reinterpret_cast<uintptr_t>(slot) & ~(static_cast<uintptr_t>(page_size) - 1);
    const int permissions = mapping_permissions(reinterpret_cast<uintptr_t>(slot));
    if (permissions < 0 || !(permissions & PROT_READ) || (permissions & PROT_EXEC)) return false;
    calling_uid = uid;
    if (mprotect(reinterpret_cast<void *>(page), page_size, permissions | PROT_WRITE) != 0) return false;
    __atomic_store_n(slot, reinterpret_cast<void *>(read_view), __ATOMIC_RELEASE);
    if (mprotect(reinterpret_cast<void *>(page), page_size, permissions) != 0) {
        __atomic_store_n(slot, reinterpret_cast<void *>(real), __ATOMIC_RELEASE);
        const int restored = mprotect(reinterpret_cast<void *>(page), page_size, permissions);
        __android_log_print(ANDROID_LOG_ERROR, "ScopedRKP", "GOT protection restore failed; passthrough restored; protection retry=%d", restored);
        return false;
    }
    patched_slot = slot;
    installed.store(true, std::memory_order_release);
    return true;
}


extern "C" __attribute__((visibility("default"))) uintptr_t srkp_enable(void *p) {
    if(entering.test_and_set(std::memory_order_acquire)) return 0;
    const auto *input=static_cast<const SrkpActivation *>(p);
    bool ok=srkp_activation_valid(input);
    SrkpActivation copy;
    if(ok) {copy=*input;ok=srkp_activation_valid(&copy);}
    if(ok) ok=install_once();
    if(ok) srkp_publish(srkp_state,copy);
    entering.clear(std::memory_order_release);
    return ok?UINT64_C(0x53524b5000000102):0;
}
extern "C" __attribute__((visibility("default"))) uintptr_t srkp_disable(void *) {
    if(entering.test_and_set(std::memory_order_acquire)) return 0;
    srkp_stop(srkp_state);entering.clear(std::memory_order_release);
    return UINT64_C(0x53524b5000000100);
}
