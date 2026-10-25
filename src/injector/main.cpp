// Modified locally for Scoped RKP. Derived from JingMatrix/TEESimulator 06f9f2ee11b86c5144a1f345f70f8fb23cae4493. GPL-3.0.
#include <android/dlext.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "inj"
#include "logging.hpp" // Custom logging utilities
#include "lsplt.hpp"   // Library for scanning memory maps
#include "utils.hpp"
#include "aux_registers.hpp"
#include "activation.h"
#include "owned_elf.h"
#include <cstddef>   // Utility functions for ptrace, remote memory, etc.

using namespace std::string_literals;

namespace inject {

// Milliseconds on CLOCK_MONOTONIC, so an injection can say how long it took and a stall in the
// ptrace dance stands apart from a fast success.
struct Elapsed {
    static unsigned long long NowMs() {
        struct timespec ts {};
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<unsigned long long>(ts.tv_sec) * 1000ull + ts.tv_nsec / 1000000ull;
    }
    unsigned long long t0 = NowMs();
    unsigned long long Ms() const { return NowMs() - t0; }
};

// Namespace for constants used throughout the injection process.
namespace constants {
constexpr size_t kMagicLength = 16;
// Length of the random magic string for socket paths.

constexpr size_t kMaxPathLength = PATH_MAX;
// Maximum length for file paths.

constexpr const char *kLibcModule = "libc.so";
// Name of the C standard library.

constexpr const char *kLibdlModule = "libdl.so";
// Name of the dynamic linker library.
} // namespace constants

class RemoteLibraryHandle {
public:
    
    RemoteLibraryHandle(int pid, int fd, uintptr_t handle = 0) : pid_(pid), fd_(fd), handle_(handle) {}

    ~RemoteLibraryHandle() {
        if (fd_ == -1) {
            return;
        }
        // Only attempt to close if a valid FD exists.

        LOGD("~RemoteLibraryHandle: closing remote fd=%d in pid=%d", fd_, pid_);

        struct user_regs_struct regs{};
        // We need current registers to perform a remote call.
        if (!get_regs(pid_, regs)) {
            LOGW("~RemoteLibraryHandle: get registers failed; remote fd left open");
            return;
        }

        // Scan maps to find the remote 'close' function address.
        std::vector<lsplt::MapInfo> local_map = lsplt::MapInfo::Scan();
        std::vector<lsplt::MapInfo> remote_map = lsplt::MapInfo::Scan(std::to_string(pid_));

        if (auto close_addr = find_func_addr(local_map, remote_map, constants::kLibcModule, "close")) {
            std::vector<uintptr_t> args = {static_cast<uintptr_t>(fd_)};
            // Perform a remote call to close the file descriptor.
            remote_call(pid_, regs, reinterpret_cast<uintptr_t>(close_addr), libc_return_addr_, args);
        } else {
            LOGW("~RemoteLibraryHandle: no remote close(); remote fd left open");
        }
    }

    // Delete copy constructor and assignment operator to prevent unintended copying.
    RemoteLibraryHandle(const RemoteLibraryHandle &) = delete;
    RemoteLibraryHandle &operator=(const RemoteLibraryHandle &) = delete;

    RemoteLibraryHandle(RemoteLibraryHandle &&other) noexcept
        : pid_(other.pid_), fd_(other.fd_), handle_(other.handle_) {
        // Invalidate the 'other' object to prevent it from closing the FD.
        other.fd_ = -1;
        other.handle_ = 0;
    }

    void set_handle(uintptr_t handle) {
        handle_ = handle;
    }

    uintptr_t handle() const {
        return handle_;
    }

    void set_libc_return_addr(uintptr_t addr) {
        libc_return_addr_ = addr;
    }

    int fd() const {
        return fd_;
    }

private:
    int pid_;                          // Target process ID.
    int fd_;                           // File descriptor in the remote process.
    uintptr_t handle_;                 // Handle returned by remote dlopen.
    uintptr_t libc_return_addr_ = 0x0; // Return address for remote calls.
};

static std::optional<int> transfer_fd_to_remote(int pid, const char *lib_path,
    struct user_regs_struct &regs, const std::vector<lsplt::MapInfo> &local_map,
    const std::vector<lsplt::MapInfo> &remote_map, uintptr_t return_address) {
    // Queue the FD before recvmsg. No running target is left waiting for IPC.
    auto socket_fn = find_func_addr(local_map, remote_map, "libc.so", "socket");
    auto bind_fn = find_func_addr(local_map, remote_map, "libc.so", "bind");
    auto recv_fn = find_func_addr(local_map, remote_map, "libc.so", "recvmsg");
    auto close_fn = find_func_addr(local_map, remote_map, "libc.so", "close");
    if (!socket_fn || !bind_fn || !recv_fn || !close_fn) return std::nullopt;
    UniqueFd sender = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    UniqueFd library = open(lib_path, O_RDONLY | O_CLOEXEC);
    if (sender == -1 || library == -1) return std::nullopt;
    std::vector<uintptr_t> args = {AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0};
    const int remote_socket = static_cast<int>(remote_call(pid, regs, reinterpret_cast<uintptr_t>(socket_fn), return_address, args));
    if (remote_socket < 0) return std::nullopt;
    struct CloseRemote {
        int pid, fd; user_regs_struct &regs; uintptr_t close_fn, ret;
        ~CloseRemote() { std::vector<uintptr_t> args{static_cast<uintptr_t>(fd)}; remote_call(pid, regs, close_fn, ret, args); }
    } close_remote{pid, remote_socket, regs, reinterpret_cast<uintptr_t>(close_fn), return_address};
    sockaddr_un address{}; address.sun_family = AF_UNIX;
    const auto magic = generateMagic(24);
    memcpy(address.sun_path + 1, magic.data(), magic.size());
    const socklen_t address_size = offsetof(sockaddr_un, sun_path) + 1 + magic.size();
    const uintptr_t remote_address = push_memory(pid, regs, &address, sizeof(address));
    if (!remote_address) return std::nullopt;
    args = {static_cast<uintptr_t>(remote_socket), remote_address, address_size};
    if (remote_call(pid, regs, reinterpret_cast<uintptr_t>(bind_fn), return_address, args) != 0) return std::nullopt;
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    char byte = 'R';
    iovec send_iov{&byte, 1};
    msghdr send_header{};
    send_header.msg_name = &address; send_header.msg_namelen = address_size;
    send_header.msg_iov = &send_iov; send_header.msg_iovlen = 1;
    send_header.msg_control = control; send_header.msg_controllen = sizeof(control);
    auto *cmsg = CMSG_FIRSTHDR(&send_header);
    cmsg->cmsg_level = SOL_SOCKET; cmsg->cmsg_type = SCM_RIGHTS; cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    const int library_fd = library;
    memcpy(CMSG_DATA(cmsg), &library_fd, sizeof(library_fd));
    if (sendmsg(sender, &send_header, MSG_DONTWAIT | MSG_NOSIGNAL) != 1) return std::nullopt;
    memset(control, 0, sizeof(control));
    const uintptr_t remote_control = push_memory(pid, regs, control, sizeof(control));
    const uintptr_t remote_byte = push_memory(pid, regs, &byte, 1);
    if (!remote_control || !remote_byte) return std::nullopt;
    iovec receive_iov{reinterpret_cast<void *>(remote_byte), 1};
    const uintptr_t remote_iov = push_memory(pid, regs, &receive_iov, sizeof(receive_iov));
    msghdr receive_header{};
    receive_header.msg_iov = reinterpret_cast<iovec *>(remote_iov); receive_header.msg_iovlen = 1;
    receive_header.msg_control = reinterpret_cast<void *>(remote_control); receive_header.msg_controllen = sizeof(control);
    const uintptr_t remote_header = push_memory(pid, regs, &receive_header, sizeof(receive_header));
    if (!remote_iov || !remote_header) return std::nullopt;
    args = {static_cast<uintptr_t>(remote_socket), remote_header, MSG_DONTWAIT | MSG_CMSG_CLOEXEC};
    if (remote_call(pid, regs, reinterpret_cast<uintptr_t>(recv_fn), return_address, args) != 1) return std::nullopt;
    if (read_proc(pid, remote_header, &receive_header, sizeof(receive_header)) != sizeof(receive_header)
        || (receive_header.msg_flags & MSG_CTRUNC) || receive_header.msg_controllen < CMSG_LEN(sizeof(int))) return std::nullopt;
    if (read_proc(pid, remote_control, control, sizeof(control)) != sizeof(control)) return std::nullopt;
    msghdr parsed{}; parsed.msg_control = control; parsed.msg_controllen = sizeof(control);
    cmsg = CMSG_FIRSTHDR(&parsed);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) return std::nullopt;
    int received = -1; memcpy(&received, CMSG_DATA(cmsg), sizeof(received));
    return received >= 0 ? std::optional<int>(received) : std::nullopt;
}

static std::optional<uintptr_t> remote_dlopen(int pid, struct user_regs_struct &regs,
    const std::vector<lsplt::MapInfo> &local_map, const std::vector<lsplt::MapInfo> &remote_map,
    int lib_fd, const char *lib_path, uintptr_t return_address, bool existing_only) {
    auto function = find_func_addr(local_map, remote_map, "libdl.so", "android_dlopen_ext");
    if (!function) return std::nullopt;
    android_dlextinfo info{};
    info.flags = ANDROID_DLEXT_USE_LIBRARY_FD; info.library_fd = lib_fd;
    const uintptr_t remote_info = push_memory(pid, regs, &info, sizeof(info));
    const uintptr_t remote_path = push_string(pid, regs, lib_path);
    if (!remote_info || !remote_path) return std::nullopt;
    std::vector<uintptr_t> args{remote_path, static_cast<uintptr_t>(RTLD_NOW | (existing_only ? RTLD_NOLOAD : 0)), remote_info};
    const uintptr_t handle = remote_call(pid, regs, reinterpret_cast<uintptr_t>(function), return_address, args);
    return handle && !srkp_remote_fault ? std::optional<uintptr_t>(handle) : std::nullopt;
}

static bool remote_call_entry(int pid, struct user_regs_struct &regs, uintptr_t entry_addr,
        uintptr_t remote_handle, uintptr_t return_address, const SrkpActivation *scope) {
        (void)remote_handle;
        uintptr_t argument = 0;
        if (scope) {
            if (!srkp_activation_valid(scope)) return false;
            argument = push_memory(pid, regs, scope, sizeof(*scope));
            if (!argument) return false;
        }
        std::vector<uintptr_t> args{argument};
        const uintptr_t result = remote_call(pid, regs, entry_addr, return_address, args);
        return result == (scope ? UINT64_C(0x53524b5000000102) : UINT64_C(0x53524b5000000100));
    }

class PtraceAttachment {
public:
    
    explicit PtraceAttachment(int target_pid) : pid_(target_pid), attached_(false) {
        if (ptrace(PTRACE_ATTACH, pid_, 0, 0) == -1) {
            PLOGE("PtraceAttachment: PTRACE_ATTACH pid=%d", pid_);
            return;
        }
        attached_ = true;
    }

    ~PtraceAttachment() {
        if (attached_) {
            if (ptrace(PTRACE_DETACH, pid_, 0, srkp_cleanup_failed ? SIGSTOP : 0) == -1) {
                srkp_cleanup_failed = true;
                PLOGE("~PtraceAttachment: PTRACE_DETACH pid=%d (manual cleanup may be needed)", pid_);
            } else {
                LOGI("~PtraceAttachment: detached pid=%d", pid_);
            }
        }
    }

    bool is_attached() const {
        return attached_;
    }

    // Delete copy constructor and assignment operator. Ptrace attachments are unique.
    PtraceAttachment(const PtraceAttachment &) = delete;
    PtraceAttachment &operator=(const PtraceAttachment &) = delete;

private:
    int pid_;       // The PID of the attached process.
    bool attached_; // Flag indicating current attachment status.
};

// RAII Class to ensure registers are always restored
class RegisterRestorer {
public:
    RegisterRestorer(int pid, const struct user_regs_struct& original_regs)
        : pid_(pid), regs_(original_regs) {}

    ~RegisterRestorer() {
        // Always restore registers when this object goes out of scope
        if (set_regs(pid_, regs_)) {
            LOGD("~RegisterRestorer: registers restored pid=%d", pid_);
        } else {
            srkp_cleanup_failed = true;
            PLOGE("~RegisterRestorer: restore registers pid=%d", pid_);
        }
    }
private:
    int pid_;
    struct user_regs_struct regs_;
};

bool inject_library(int pid, const char *lib_path, const char *entry_name, const SrkpActivation *scope) {
    const bool activate=!strcmp(entry_name,"srkp_enable");
    if(activate && !srkp_activation_valid(scope)) return false;
    SrkpOwnedElf image(lib_path);
    const auto symbol=image.symbol(entry_name,STT_FUNC);
    auto loaded=image.mapping(pid);
    if(!symbol || !loaded.scanned || loaded.conflict || (!activate && !loaded.base)) {
        LOGE("Owned image/entry unavailable or old image still mapped; no attach. A full process restart may be required."); return false;
    }
    SrkpSignalBlock signals; if(!signals.valid) return false;
    PtraceAttachment attachment(pid); if(!attachment.is_attached()) return false;
    int status=0;
    if(!wait_for_trace(pid,&status,__WALL) || !WIFSTOPPED(status) || WSTOPSIG(status)!=SIGSTOP) return false;
#ifndef SRKP_INJECT_LIBRARY_ONLY
    if(get_program(pid)!="/system/bin/keystore2") return false;
#endif
    user_regs_struct regs{},backup{};
    if(!get_regs(pid,regs)) return false;
    backup=regs;
    RegisterRestorer restore(pid,backup);
    SrkpAuxRegisters auxiliary(pid); if(!auxiliary.valid) return false;
    auto remote_map=lsplt::MapInfo::Scan(std::to_string(pid));
    auto local_map=lsplt::MapInfo::Scan();
    auto ret=find_module_return_addr(remote_map,constants::kLibcModule);
    if(!ret) return false;
    auto errno_fn=find_func_addr(local_map,remote_map,constants::kLibcModule,"__errno");
    if(!errno_fn) return false;
    std::vector<uintptr_t> noargs;
    const uintptr_t errno_address=remote_call(pid,regs,reinterpret_cast<uintptr_t>(errno_fn),reinterpret_cast<uintptr_t>(ret),noargs);
    int original_errno=0;
    if(!errno_address || (errno_address&3) || read_proc(pid,errno_address,&original_errno,sizeof(original_errno))!=sizeof(original_errno)) return false;
    SrkpErrnoRestorer errno_restore{pid,errno_address,original_errno};
    loaded=image.mapping(pid);
    if(!loaded.scanned || loaded.conflict) return false;
    std::optional<RemoteLibraryHandle> fd_guard;
    bool first_load=false;
    if(!loaded.base) {
        if(!activate) return false;
        const auto descriptor=transfer_fd_to_remote(pid,lib_path,regs,local_map,remote_map,reinterpret_cast<uintptr_t>(ret));
        if(!descriptor) return false;
        fd_guard.emplace(pid,*descriptor);
        fd_guard->set_libc_return_addr(reinterpret_cast<uintptr_t>(ret));
        const auto handle=remote_dlopen(pid,regs,local_map,remote_map,*descriptor,lib_path,reinterpret_cast<uintptr_t>(ret),false);
        if(!handle) return false;
        fd_guard->set_handle(*handle);
        loaded=image.mapping(pid);
        if(!loaded.scanned || loaded.conflict || !loaded.base) return false;
        // Exactly one intentionally pinned reference: the GOT may point here.
        first_load=true;
#ifdef SRKP_INJECT_LIBRARY_ONLY
        srkp_image_load_count.fetch_add(1);
#endif
    }
#ifdef SRKP_INJECT_LIBRARY_ONLY
    if(!first_load) srkp_image_reuse_count.fetch_add(1);
#endif
    const uintptr_t entry=loaded.base+symbol->value;
    return remote_call_entry(pid,regs,entry,0,reinterpret_cast<uintptr_t>(ret),scope);
}

} // namespace inject


#ifndef SRKP_INJECT_LIBRARY_ONLY
#include "policy.hpp"
static int status_only(int pid,const char *path) {
    SrkpOwnedElf image(path);const auto map=image.mapping(pid);
    if(!image.valid || !map.scanned) return 6;
    if(map.conflict) {puts("{\"loaded\":true,\"compatible\":false,\"restart_required\":true}");return 0;}
    if(!map.base) {puts("{\"loaded\":false,\"compatible\":true,\"enabled\":false}");return 0;}
    const auto symbol=image.symbol("srkp_state",STT_OBJECT);
    if(!symbol || symbol->size!=sizeof(SrkpState)) return 7;
    SrkpState state;uint64_t before,after;
    auto read=[&](uintptr_t address,void *p,size_t n){return read_proc(pid,address,p,n)==ssize_t(n);};
    const auto address=map.base+symbol->value;
    if(!read(address+offsetof(SrkpState,epoch),&before,sizeof(before)) || (before&1) ||
       !read(address,&state,sizeof(state)) || !read(address+offsetof(SrkpState,epoch),&after,sizeof(after)) ||
       before!=after || state.epoch.load()!=before || state.magic!=SRKP_STATE_MAGIC || state.abi!=4 ||
       state.capacity!=SRKP_MAX_UIDS || state.count.load()>SRKP_MAX_UIDS || state.enabled.load()>1) return 8;
    printf("{\"loaded\":true,\"compatible\":true,\"enabled\":%s,\"scope_count\":%u}\n",state.enabled.load()?"true":"false",state.count.load());return 0;
}
int main(int argc,char **argv) {
    if(getuid()!=0 || argc<4) {fputs("Usage: srkp_engine status|enable|disable PID LIB [UID,...]\n",stderr);return 2;}
    const bool enable=!strcmp(argv[1],"enable"),disable=!strcmp(argv[1],"disable"),status=!strcmp(argv[1],"status");
    if((!enable && !disable && !status) || argc!=(enable?5:4)) return 2;
    char *end=nullptr;errno=0;const long number=strtol(argv[2],&end,10);
    if(errno || !end || *end || number<=1 || number>INT_MAX) return 3;
    const int pid=static_cast<int>(number);
    if(get_program(pid)!="/system/bin/keystore2") return 4;
    char library[PATH_MAX]{};if(!realpath(argv[3],library)) return 5;
    const char *base=strrchr(library,'/');if(!base || strcmp(base+1,"libscoped_rkp.so")) return 5;
    if(status) return status_only(pid,library);
    SrkpActivation scope;
    if(enable) {
        const char *p=argv[4];
        while(*p) {
            if(*p<'0' || *p>'9' || scope.count>=SRKP_MAX_UIDS) return 11;
            errno=0;char *next=nullptr;const auto uid=strtoull(p,&next,10);
            if(errno || !next || uid>UINT32_MAX) return 11;
            scope.uids[scope.count++]=static_cast<uint32_t>(uid);
            if(!*next) break;
            if(*next!=',' || !next[1]) return 11;p=next+1;
        }
        if(!srkp_activation_valid(&scope)) return 11;
    }
    SrkpOwnedElf image(library);const auto map=image.mapping(pid);
    if(!image.valid || !map.scanned || map.conflict) {fputs("A different module image is mapped; full reboot required.\n",stderr);return 6;}
    if(disable && !map.base) return 0;
    bool ok=false;
    try {ok=inject::inject_library(pid,library,enable?"srkp_enable":"srkp_disable",enable?&scope:nullptr);}
    catch(const std::exception &e) {fprintf(stderr,"Load error: %s\n",e.what());return 10;}
    return srkp_cleanup_failed?9:(ok?0:8);
}
#endif
