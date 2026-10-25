// Isolated test executable. It never calls Keystore, KeyMint, RKP or Google.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <string>
#include <sys/system_properties.h>
#include <thread>
#include <vector>
#include <unistd.h>
#include <cerrno>
#include "activation.h"
#include "policy.hpp"
static long resident_kib() {
    FILE *f=fopen("/proc/self/status","re"); if(!f) return -1;
    char line[256]; long value=-1;
    while(fgets(line,sizeof(line),f)) if(sscanf(line,"VmRSS: %ld kB",&value)==1) break;
    fclose(f); return value;
}

static thread_local uid_t test_uid = 10001;
extern "C" __attribute__((visibility("default"))) uid_t AIBinder_getCallingUid() { return test_uid; }
static std::string read_value(const char *name) {
    const prop_info *p = __system_property_find(name);
    std::string value;
    if (p) __system_property_read_callback(p, [](void *c, const char *, const char *v, uint32_t) {
        *static_cast<std::string *>(c) = v;
    }, &value);
    return value;
}
static int suite(const char *library) {
    char global[PROP_VALUE_MAX]{};
    __system_property_get("ro.boot.hwc", global);
    if (strcmp(global, "CN") != 0) { fprintf(stderr, "Fixture requires a CN property; no property is changed.\n"); return 3; }
    void *h = dlopen(library, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "Fixture dlopen: %s\n", dlerror()); return 4; }
    using Entry = uintptr_t (*)(void *);
    auto enable = reinterpret_cast<Entry>(dlsym(h, "srkp_enable"));
    auto off = reinterpret_cast<Entry>(dlsym(h, "srkp_disable"));
    if (!enable || !off) return 5;
    SrkpActivation policy{SRKP_ACTIVATION_MAGIC, 4, 4, {10001,10002,10003,10004}};
    constexpr uintptr_t magic = 0x53524b5000000000ull;
    if ((enable(&policy) & ~uintptr_t(0x1ff)) != magic) return 7;
    for (uid_t uid : {uid_t(10001), uid_t(10002), uid_t(10003), uid_t(10004)}) {
        test_uid = uid;
        if (read_value("ro.boot.hwc") != "GLOBAL") return 8;
    }
    for (uid_t uid : {uid_t(0), uid_t(1017), uid_t(10005), uid_t(110001)}) {
        test_uid = uid;
        if (read_value("ro.boot.hwc") != "CN") return 9;
    }
    test_uid = 10001;
    __system_property_get("ro.boot.hwc", global);
    if (strcmp(global, "CN") != 0) return 10;
    const std::string fingerprint = read_value("ro.build.fingerprint");
    char original_fingerprint[PROP_VALUE_MAX]{};
    __system_property_get("ro.build.fingerprint", original_fingerprint);
    if (fingerprint != original_fingerprint) return 11;
    std::atomic<unsigned> errors{0};
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 8; ++i) threads.emplace_back([&, i] {
        test_uid = i & 1 ? 10001 : 10005;
        const char *expected = i & 1 ? "GLOBAL" : "CN";
        for (unsigned j = 0; j < 1000; ++j) if (read_value("ro.boot.hwc") != expected) ++errors;
    });
    for (auto &thread : threads) thread.join();
    if (errors.load()) return 12;
    if (!enable(&policy) || read_value("ro.boot.hwc") != "GLOBAL") return 14;
    // Reload a completely different set without restarting or rebuilding.
    SrkpActivation alternate{SRKP_ACTIVATION_MAGIC, 4, 1, {10004}};
    if (!enable(&alternate) || read_value("ro.boot.hwc") != "CN") return 20;
    test_uid = 10004;
    if (read_value("ro.boot.hwc") != "GLOBAL") return 21;
    SrkpActivation unrelated{SRKP_ACTIVATION_MAGIC, 4, 1, {54321}};
    if (!enable(&unrelated) || read_value("ro.boot.hwc") != "CN") return 22;
    test_uid = 54321;
    if (read_value("ro.boot.hwc") != "GLOBAL") return 23;
    unrelated.count = 0;
    if (enable(&unrelated) || read_value("ro.boot.hwc") != "GLOBAL") return 24;
    if (!enable(&policy)) return 25;
    // Warm all paths before measuring fixed-size policy reloads.
    test_uid=10001;
    for(unsigned i=0;i<100;i++) { if(!enable(&policy) || read_value("ro.boot.hwc")!="GLOBAL") return 27; }
    const long rss_before=resident_kib();
    for(unsigned i=0;i<10000;i++) { if(!enable(&policy) || read_value("ro.boot.hwc")!="GLOBAL") return 28; }
    const long rss_after=resident_kib();
    if(rss_before<0 || rss_after<0 || rss_after-rss_before>256) return 29;
    for(unsigned i=0;i<100000;i++) { if(!enable(&policy) || read_value("ro.boot.hwc")!="GLOBAL") return 31; }
    const long rss_final=resident_kib();
    if(rss_final<0 || rss_final-rss_after>64) return 32;
    std::atomic<bool> running{true};
    std::thread outsider([&] {
        test_uid=10005;
        while(running.load()) if(read_value("ro.boot.hwc")!="CN") errors.fetch_add(1);
    });
    for(unsigned i=0;i<1000;i++) if(!enable(i&1?&policy:&alternate)) errors.fetch_add(1);
    running.store(false); outsider.join();
    if(errors.load()) return 30;
    if ((off(h) & ~uintptr_t(0x1ff)) != magic || read_value("ro.boot.hwc") != "CN") return 15;
    printf("{\"ok\":true,\"fixture_only\":true,\"got_hook_tested\":true,\"parallel_requests\":8000,\"global_hwc_unchanged\":true,\"persistent_until_off\":true,\"dynamic_scope_reload\":true,\"alternate_scope_tested\":true,\"arbitrary_new_uid_tested\":true,\"invalid_empty_scope_rejected\":true,\"policy_stress_reloads\":110000,\"rss_before_kib\":%ld,\"rss_after_10000_kib\":%ld,\"rss_after_110000_kib\":%ld,\"concurrent_scope_reloads\":1000}\n",rss_before,rss_after,rss_final);
    return 0; // Do not dlclose a library whose GOT hook is still resident.
}
int main(int argc, char **argv) {
    if (argc != 3 || (strcmp(argv[1], "--local-test") && strcmp(argv[1], "--wait"))) return 2;
    if (!strcmp(argv[1], "--wait")) {
        char greeting[64]{};
        const int greeting_bytes = snprintf(greeting, sizeof(greeting), "READY %d\n", getpid());
        char command[8]{};
        alignas(16) const uint64_t patterns[6] = {
            0x1122334455667788ull, 0x8877665544332211ull,
            0x0123456789abcdefull, 0xfedcba9876543210ull,
            0x55aa55aa55aa55aaull, 0xaa55aa55aa55aa55ull};
        alignas(16) uint64_t after[6]{};
        long received = 0;
        errno = E2BIG;
        // READY is emitted only after the vector patterns are live. The raw
        // blocked read then makes the register-preservation check meaningful.
        asm volatile(
            "ldr q0, [%[pattern]]\n"
            "ldr q8, [%[pattern], #16]\n"
            "ldr q31, [%[pattern], #32]\n"
            "mov x8, #64\nmov x0, #1\nmov x1, %[greeting]\nmov x2, %[length]\nsvc #0\n"
            "mov x8, #63\nmov x0, #0\nmov x1, %[command]\nmov x2, #4\nsvc #0\n"
            "str q0, [%[after]]\nstr q8, [%[after], #16]\nstr q31, [%[after], #32]\n"
            "mov %[received], x0\n"
            : [received] "=r" (received)
            : [pattern] "r" (patterns), [greeting] "r" (greeting), [length] "r" (long(greeting_bytes)),
              [command] "r" (command), [after] "r" (after)
            : "x0", "x1", "x2", "x8", "v0", "v8", "v31", "memory", "cc");
        if (memcmp(patterns, after, sizeof(patterns))) {
            fprintf(stderr, "Fixture vector registers changed across injection.\n"); return 17;
        }
        if (errno != E2BIG) { fprintf(stderr, "Fixture thread errno changed across injection.\n"); return 19; }
        if (received != 4 || strcmp(command, "RUN\n")) {
            fprintf(stderr, "Fixture blocked read result=%ld; syscall resume requires review.\n", received); return 18;
        }
        printf("{\"vector_registers_preserved\":true,\"thread_errno_preserved\":true,\"blocked_read_resumed\":true}\n");
    }
    return suite(argv[2]);
}
