// Modified locally for Scoped RKP. Derived from JingMatrix/TEESimulator 06f9f2ee11b86c5144a1f345f70f8fb23cae4493. GPL-3.0.
#include "utils.hpp"

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sched.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/random.h>
#include <string>
#include <string_view>
#include <vector>

// The subsystem every line from this file is stamped with; see injector/include/logging.hpp.
#define LOG_SUB "inj"
#include "logging.hpp"
#include "aux_registers.hpp"

// Anonymous namespace for file-local constants and helper functions.
namespace {

// Remote address -> "module!symbol", filled in by find_func_addr as each symbol is resolved, so a
// fault inside a remote call names the function rather than a bare address. The injector is
// single-threaded ptrace code driving one target at a time, so a plain map and a "call in flight"
// address are all this needs.
constexpr size_t kMaxPathLengthInternal = PATH_MAX; // Internal max path length.
constexpr size_t kMsgBufferSize = 64;               // Buffer size for generic messages.
constexpr size_t kStatusBufferSize = 128;           // Buffer size for wait status parsing.
constexpr int kInvalidFd = -1;                      // Represents an invalid file descriptor.
constexpr uintptr_t kStackAlignment = 0xf;          // Stack alignment requirement (16 bytes for many architectures).
constexpr int kMaxRegisterArgs = 8;                 // Maximum number of arguments passed via registers (e.g., AArch64).

// Permission characters used in memory map parsing.
constexpr char kReadPerm = 'r';
constexpr char kWritePerm = 'w';
constexpr char kExecPerm = 'x';
constexpr char kNoPerm = '-';

// Characters used for generating random magic strings.
constexpr std::string_view kRandomChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

#if defined(__x86_64__)
// Helper function to set x86_64 specific registers for remote calls.
void setup_x86_64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in RDI, RSI, RDX, RCX, R8, R9.
    if (args.size() >= 1)
        regs.rdi = args[0];
    if (args.size() >= 2)
        regs.rsi = args[1];
    if (args.size() >= 3)
        regs.rdx = args[2];
    if (args.size() >= 4)
        regs.rcx = args[3];
    if (args.size() >= 5)
        regs.r8 = args[4];
    if (args.size() >= 6)
        regs.r9 = args[5];
}
#elif defined(__aarch64__)
// Helper function to set AArch64 specific registers for remote calls.
void setup_aarch64_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in x0-x7.
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(kMaxRegisterArgs)); i++) {
        regs.regs[i] = args[i];
    }
}
#elif defined(__arm__)
// Helper function to set ARM specific registers for remote calls.
void setup_arm_args(struct user_regs_struct &regs, const std::vector<uintptr_t> &args) {
    // Arguments are passed in R0-R3.
    for (size_t i = 0; i < std::min(args.size(), static_cast<size_t>(4)); i++) { // ARM has 4 register arguments (R0-R3)
        regs.uregs[i] = args[i];
    }
}
#endif
} // namespace


ssize_t write_proc(int pid, uintptr_t address, const void *buffer, size_t length, bool use_proc_mem) {
        if (!buffer || !length || use_proc_mem) { errno = EINVAL; return -1; }
        iovec local{const_cast<void *>(buffer), length};
        iovec remote{reinterpret_cast<void *>(address), length};
        return process_vm_writev(pid, &local, 1, &remote, 1, 0);
    }

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len) {
    if (!buf || len == 0) {
        LOGE("read_proc: invalid arguments (null buffer or zero length)");
        return -1;
    }

    LOGV("read_proc: %zu byte(s) from pid=%d at 0x%" PRIxPTR, len, pid, remote_addr);

    // Setup iovec structures for local and remote memory.
    struct iovec local_iov = {.iov_base = buf, .iov_len = len};
    struct iovec remote_iov = {.iov_base = reinterpret_cast<void *>(remote_addr), .iov_len = len};

    ssize_t bytes_read = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes_read == -1) {
        PLOGE("read_proc: process_vm_readv at 0x%" PRIxPTR, remote_addr);
    } else if (static_cast<size_t>(bytes_read) != len) {
        LOGW("read_proc: partial read %zd of %zu byte(s) pid=%d at 0x%" PRIxPTR, bytes_read, len, pid,
             remote_addr);
    }

    return bytes_read;
}

bool get_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    // For x86/x86_64, PTRACE_GETREGS is used directly with `struct
    // user_regs_struct`.
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        PLOGE("get_regs: PTRACE_GETREGS pid=%d", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    // For ARM/AArch64, PTRACE_GETREGSET is used with `NT_PRSTATUS` and an iovec.
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("get_regs: PTRACE_GETREGSET pid=%d", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
            PLOGE("get_regs: fallback PTRACE_GETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in get_regs."
#endif

    return true;
}

bool set_regs(int pid, struct user_regs_struct &regs) {
#if defined(__x86_64__) || defined(__i386__)
    // For x86/x86_64, PTRACE_SETREGS is used directly.
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        PLOGE("set_regs: PTRACE_SETREGS pid=%d", pid);
        return false;
    }
#elif defined(__aarch64__) || defined(__arm__)
    // For ARM/AArch64, PTRACE_SETREGSET is used.
    struct iovec reg_iov = {.iov_base = &regs, .iov_len = sizeof(struct user_regs_struct)};
    if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &reg_iov) == -1) {
        PLOGE("set_regs: PTRACE_SETREGSET pid=%d", pid);
#if defined(__arm__)
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
            PLOGE("set_regs: fallback PTRACE_SETREGS");
            return false;
        }
#else
        return false;
#endif
    }
#else
#    error "Unsupported architecture for register access in set_regs."
#endif

    return true;
}

std::string get_addr_mem_region(const std::vector<lsplt::MapInfo> &map_info, uintptr_t addr) {
    for (const auto &map : map_info) {
        if (map.start <= addr && map.end > addr) {
            std::string perms_str;
            perms_str.reserve(4); // "rwx" + null or '-'

            perms_str += (map.perms & PROT_READ) ? kReadPerm : kNoPerm;
            perms_str += (map.perms & PROT_WRITE) ? kWritePerm : kNoPerm;
            perms_str += (map.perms & PROT_EXEC) ? kExecPerm : kNoPerm;

            return map.path + ' ' + perms_str;
        }
    }
    return "<unknown>";
}

void *find_module_base(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        // A module's base is typically its first segment with offset 0.
        //
        // No log line here: this runs twice (local, then remote) for every symbol resolved, and
        // find_func_addr already reports both bases together, once per module.
        if (map.offset == 0 && map.path.ends_with(module_suffix)) {
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGD("find_module_base: no base for suffix '%.*s'", static_cast<int>(module_suffix.length()),
         module_suffix.data());
    return nullptr;
}

void *find_func_addr(const std::vector<lsplt::MapInfo> &local_map_info,
                     const std::vector<lsplt::MapInfo> &remote_map_info, std::string_view module_name,
                     std::string_view function_name) {
    // 1. Open the module locally to find the symbol.
    // RTLD_NOW ensures all undefined symbols are resolved immediately.
    void *lib_handle = dlopen(module_name.data(), RTLD_NOW);
    if (!lib_handle) {
        LOGE("find_func_addr: dlopen local '%.*s' failed: %s", static_cast<int>(module_name.length()), module_name.data(),
             dlerror());
        return nullptr;
    }

    // Use a lambda for RAII-like dlclose to ensure handle is closed.
    auto lib_closer = [lib_handle]() {
        dlclose(lib_handle);
    };

    // 2. Find the function's address in the *local* module.
    auto *symbol_addr = reinterpret_cast<uint8_t *>(dlsym(lib_handle, function_name.data()));
    if (!symbol_addr) {
        LOGE("find_func_addr: no local symbol '%.*s' in '%.*s': %s", static_cast<int>(function_name.length()),
             function_name.data(), static_cast<int>(module_name.length()), module_name.data(), dlerror());
        lib_closer(); // Ensure local handle is closed before returning.
        return nullptr;
    }
    // 3. Find the module's base address in the *local* process.
    auto *local_base = reinterpret_cast<uint8_t *>(find_module_base(local_map_info, module_name));
    if (!local_base) {
        LOGE("find_func_addr: no local base for '%.*s'", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    // 4. Find the module's base address in the *remote* process.
    auto *remote_base = reinterpret_cast<uint8_t *>(find_module_base(remote_map_info, module_name));
    if (!remote_base) {
        LOGE("find_func_addr: no remote base for '%.*s'", static_cast<int>(module_name.length()),
             module_name.data());
        lib_closer();
        return nullptr;
    }

    // 5. Calculate the offset and derive the remote function address.
    ptrdiff_t symbol_offset = symbol_addr - local_base;
    auto *remote_symbol_addr = remote_base + symbol_offset;

    lib_closer(); // Close local handle.
    return remote_symbol_addr;
}

void align_stack(struct user_regs_struct &regs, uintptr_t preserve_bytes) {
    // Decrement stack pointer by preserve_bytes, then align it down to the nearest multiple of (kStackAlignment + 1).
    regs.REG_SP = (regs.REG_SP - preserve_bytes) & ~kStackAlignment;
}

uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length) {
    if (!data || length == 0) {
        LOGE("push_memory: invalid arguments data=%p length=%zu", data, length);
        return 0;
    }

    // Decrement stack pointer to make space for the data.
    regs.REG_SP -= length;
    // Align the stack.
    // This might shift REG_SP further down if not already aligned.
    // If multiple small pushes happen, it's better to align once at the end or before a call.
    // For a single block, aligning after decrement is fine.
    align_stack(regs);

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    // Write the data to the remote stack.
    if (write_proc(pid, stack_addr, data, length) != static_cast<ssize_t>(length)) {
        LOGE("push_memory: write %zu byte(s) at 0x%" PRIxPTR " failed", length, stack_addr);
        return 0;
    }

    LOGV("push_memory: %zu byte(s) at 0x%" PRIxPTR, length, stack_addr);
    return stack_addr;
}

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str) {
    if (!str) {
        LOGE("push_string: null string");
        return 0;
    }

    size_t str_length = strlen(str) + 1; // Include null terminator.

    // Decrement stack pointer and align it.
    regs.REG_SP -= str_length;
    align_stack(regs); // Align the stack after making space.

    auto stack_addr = static_cast<uintptr_t>(regs.REG_SP);

    // Write the string to the remote stack.
    if (write_proc(pid, stack_addr, str, str_length) != static_cast<ssize_t>(str_length)) {
        LOGE("push_string: write '%s' (%zu byte(s)) at 0x%" PRIxPTR " failed", str, str_length, stack_addr);
        return 0;
    }

    LOGV("push_string: '%s' (%zu byte(s)) at 0x%" PRIxPTR, str, str_length, stack_addr);
    return stack_addr;
}

bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args) {
    // Ensure stack is aligned before modifying it for function arguments.
    align_stack(regs);

    // Remembered for remote_post_call, which logs the whole call as one line once its result is
    // known, named through the symbol map ("libc.so!recvmsg") rather than as a bare address.

#if defined(__x86_64__)
    // x86_64 Calling Convention (System V AMD64 ABI):
    // Arguments: RDI, RSI, RDX, RCX, R8, R9.
    // Additional arguments on stack (right-to-left).
    // Return Address: Pushed onto stack by CALL instruction.
    // Return Value: RAX.
    setup_x86_64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) { // kMaxRegisterArgs for x86_64 is 6
        // Push excess arguments onto the stack.
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);
        // Align stack while reserving space for args.

        // Write stack arguments from `args.data() + kMaxRegisterArgs` (the elements beyond registers).
        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("remote_pre_call: push stack arguments (x86_64) failed");
            return false;
        }
    }

    // Push the return address onto the stack. This simulates what a `call` instruction would do.
    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) !=
        sizeof(return_addr)) {
        LOGE("remote_pre_call: write return address (x86_64) failed");
        return false;
    }

    regs.REG_IP = func_addr; // Set instruction pointer to the target function.

#elif defined(__i386__)
    // i386 Calling Convention (cdecl):
    // Arguments: All pushed onto stack (right-to-left).
    // Return Address: Pushed onto stack by CALL instruction.
    // Return Value: EAX.
    if (args.size() > 0) {
        size_t stack_args_size = args.size() * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        // i386 cdecl expects arguments pushed Right-to-Left (stack grows down).
        // Since `write_proc` writes to increasing addresses (up), a linear write
        // starting at the new SP places the first argument at the lowest address.
        // This matches the ABI memory layout without needing to reverse the vector.
        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data(), stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("remote_pre_call: push arguments (i386) failed");
            return false;
        }
    }

    // Push the return address onto the stack.
    regs.REG_SP -= sizeof(uintptr_t);
    if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), &return_addr, sizeof(return_addr)) !=
        sizeof(return_addr)) {
        LOGE("remote_pre_call: write return address (i386) failed");
        return false;
    }

    regs.REG_IP = func_addr; // Set instruction pointer.

#elif defined(__aarch64__)
    // AArch64 Calling Convention (Procedure Call Standard for the ARM 64-bit Architecture):
    // Arguments: x0-x7.
    // Additional arguments on stack.
    // Return Address: x30 (Link Register, LR).
    // Return Value: x0.
    setup_aarch64_args(regs, args);

    if (args.size() > kMaxRegisterArgs) { // kMaxRegisterArgs for AArch64 is 8
        size_t stack_args_size = (args.size() - kMaxRegisterArgs) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + kMaxRegisterArgs, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("remote_pre_call: push stack arguments (AArch64) failed");
            return false;
        }
    }

    regs.regs[30] = return_addr; // Set Link Register (LR) to return address.
    regs.REG_IP = func_addr;     // Set Program Counter (PC) to target function.

#elif defined(__arm__)
    // ARM Calling Convention (ARM Procedure Call Standard - AAPCS):
    // Arguments: R0-R3. Additional arguments on stack.
    // Return Address: R14 (Link Register, LR).
    // Return Value: R0.
    setup_arm_args(regs, args);

    if (args.size() > 4) { // ARM has 4 register arguments (R0-R3).
        size_t stack_args_size = (args.size() - 4) * sizeof(uintptr_t);
        align_stack(regs, stack_args_size);

        if (write_proc(pid, static_cast<uintptr_t>(regs.REG_SP), args.data() + 4, stack_args_size) !=
            static_cast<ssize_t>(stack_args_size)) {
            LOGE("remote_pre_call: push stack arguments (ARM) failed");
            return false;
        }
    }

    regs.uregs[14] = return_addr; // Set Link Register (R14) to return address.
    regs.REG_IP = func_addr;      // Set Program Counter (R15) to target function.

    // Handle Thumb mode for ARM.
    // If func_addr is odd, it indicates Thumb instruction set.
    // Clear the LSB of PC and set the T bit in CPSR (R16).
    constexpr auto CPSR_T_MASK = 1lu << 5;
    if ((regs.REG_IP & 1) != 0) {
        regs.REG_IP = regs.REG_IP & ~1;                // Clear LSB for actual address.
        regs.uregs[16] = regs.uregs[16] | CPSR_T_MASK; // Set T bit.
    } else {
        regs.uregs[16] = regs.uregs[16] & ~CPSR_T_MASK; // Clear T bit for ARM mode.
    }

#else
#    error "Unsupported architecture for remote function calls in remote_pre_call."
#endif

    // Set the modified registers in the target process.
    if (!set_regs(pid, regs)) {
        LOGE("remote_pre_call: set registers pid=%d failed", pid);
        return false;
    }

    // Continue the target process execution.
    if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
        PLOGE("remote_pre_call: PTRACE_CONT pid=%d", pid);
        return false;
    }

    return true;
}

uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected) {
    int status = 0;
    if (!wait_for_trace(pid, &status, __WALL) || !get_regs(pid, regs)
        || !WIFSTOPPED(status) || (WSTOPSIG(status) != SIGSEGV && WSTOPSIG(status) != SIGTRAP)
        || static_cast<uintptr_t>(regs.REG_IP) != expected) {
        srkp_remote_fault = true; srkp_cleanup_failed = true;
        LOGE("Remote call did not return at its expected stop; refusing further target calls.");
        return 0;
    }
    return regs.REG_RET;
}

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t function,
    uintptr_t return_address, std::vector<uintptr_t> &args) {
    if (srkp_remote_fault) return 0;
    if (!remote_pre_call(pid, regs, function, return_address, args)) {
        srkp_remote_fault = true; srkp_cleanup_failed = true; return 0;
    }
    return remote_post_call(pid, regs, return_address);
}

bool wait_for_trace(int pid, int *status, int flags) {
    if (!status) {
        LOGE("wait_for_trace: null status pointer");
        return false;
    }

    while (true) {
        pid_t result = waitpid(pid, status, flags);
        if (result == -1) {
            if (errno == EINTR) {
                LOGV("wait_for_trace: waitpid pid=%d interrupted, retrying", pid);
                continue; // Retry on EINTR.
            } else {
                PLOGE("wait_for_trace: waitpid pid=%d", pid);
                return false;
            }
        }

        // If waitpid returns a valid PID, check if the process actually stopped.
        if (!WIFSTOPPED(*status)) {
            LOGE("wait_for_trace: pid=%d not stopped for trace: %s", pid, parse_status(*status).c_str());
            return false;
        }

        // No line for a successful stop: every remote call ends in one, and each caller reports the
        // stop it did not expect.
        return true;
    }
}

std::string parse_status(int status) {
    char status_buf[kStatusBufferSize];

    if (WIFEXITED(status)) {
        // Process exited normally.
        snprintf(status_buf, sizeof(status_buf), "0x%x exited with code %d", status, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        // Process terminated by a signal.
        snprintf(status_buf, sizeof(status_buf), "0x%x terminated by signal %s(%d)", status,
                 sigabbrev_np(WTERMSIG(status)), WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        // Process stopped by a signal (e.g., ptrace, job control).
        int stop_signal = WSTOPSIG(status);
        snprintf(status_buf, sizeof(status_buf), "0x%x stopped by signal=%s(%d), event=%s", status,
                 sigabbrev_np(stop_signal), stop_signal, parse_ptrace_event(status));
    } else {
        // Unknown status.
        snprintf(status_buf, sizeof(status_buf), "0x%x unknown status", status);
    }

    return std::string(status_buf);
}

std::string get_program(int pid) {
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    char resolved_path[kMaxPathLengthInternal + 1]; // +1 for null terminator.

    ssize_t link_size = readlink(exe_path.c_str(), resolved_path, kMaxPathLengthInternal);
    if (link_size == -1) {
        PLOGE("get_program: readlink pid=%d %s", pid, exe_path.c_str());
        return "";
    }

    resolved_path[link_size] = '\0'; // Null-terminate the string.
    return std::string(resolved_path);
}

void *find_module_return_addr(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix) {
    for (const auto &map : map_info) {
        // Look for a readable, non-executable segment of the module.
        // This is a common heuristic for finding a safe return address for ptrace.
        if (!(map.perms & PROT_EXEC) && (map.perms & PROT_READ) && map.path.ends_with(module_suffix)) {
            return reinterpret_cast<void *>(map.start);
        }
    }

    LOGV("find_module_return_addr: no region for suffix '%.*s'", static_cast<int>(module_suffix.length()),
         module_suffix.data());
    return nullptr;
}

std::string generateMagic(size_t length) {
    if(!length || length>64) return {};
    unsigned char bytes[64];size_t done=0;
    while(done<length) {
        const auto n=getrandom(bytes+done,length-done,0);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return {};
        done+=n;
    }
    std::string result(length,'0');
    for(size_t i=0;i<length;i++) result[i]=kRandomChars[bytes[i]%kRandomChars.size()];
    return result;
}
