// Modified locally for Scoped RKP. Derived from JingMatrix/TEESimulator 06f9f2ee11b86c5144a1f345f70f8fb23cae4493. GPL-3.0.
#pragma once

#include <algorithm> // For std::swap in UniqueFd
#include <limits.h>  // For PATH_MAX
#include <string>
#include <string_view>
#include <sys/ptrace.h>
#include <unistd.h>
#include <vector>

#include "lsplt.hpp"

// Macros for syscall error checking. These are typically used after remote
// syscall emulation.
#define SYSCALL_IS_ERR(e) (((unsigned long)e) > -4096UL) // Checks if a syscall return value indicates an error.
#define SYSCALL_ERR(e) (-(int)(e))                       // Converts a syscall error value to a negative errno.

// Architecture-specific register definitions.
// These macros abstract away the differences in register names across architectures,
// allowing for generic code that manipulates `struct user_regs_struct`.
#if defined(__x86_64__)
#    define REG_SP rsp       // Stack pointer register
#    define REG_IP rip       // Instruction pointer register
#    define REG_RET rax      // Return value register
#    define REG_NR orig_rax  // Syscall number register
#    define REG_SYS_ARG0 rdi // First syscall argument register
#elif defined(__i386__)
#    define REG_SP esp
#    define REG_IP eip
#    define REG_RET eax
#    define REG_NR orig_eax
#    define REG_SYS_ARG0 ebx
#elif defined(__aarch64__)
#    define REG_SP sp            // Stack pointer register (AArch64)
#    define REG_IP pc            // Program counter register (AArch64)
#    define REG_RET regs[0]      // Return value register (x0)
#    define REG_NR regs[8]       // Syscall number register (x8)
#    define REG_SYS_ARG0 regs[0] // First syscall argument register (x0)
#elif defined(__arm__)
#    define REG_SP uregs[13]           // Stack pointer register (R13)
#    define REG_IP uregs[15]           // Program counter register (R15)
#    define REG_RET uregs[0]           // Return value register (R0)
#    define REG_NR uregs[7]            // Syscall number register (R7)
#    define REG_SYS_ARG0 uregs[0]      // First syscall argument register (R0)
#    define user_regs_struct user_regs // ARM's equivalent to user_regs_struct is user_regs
#    define SYS_mmap SYS_mmap2         // ARM uses mmap2 syscall
#endif

// --- Remote Memory Operations ---

ssize_t write_proc(int pid, uintptr_t remote_addr, const void *buf, size_t len, bool use_proc_mem = false);

ssize_t read_proc(int pid, uintptr_t remote_addr, void *buf, size_t len);

// --- Remote Register Operations ---

bool get_regs(int pid, struct user_regs_struct &regs);

bool set_regs(int pid, struct user_regs_struct &regs);

// --- Module and Symbol Resolution ---

std::string get_addr_mem_region(const std::vector<lsplt::MapInfo> &map_info, uintptr_t addr);

void *find_module_base(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix);

void *find_func_addr(const std::vector<lsplt::MapInfo> &local_map_info,
                     const std::vector<lsplt::MapInfo> &remote_map_info, std::string_view module_name,
                     std::string_view function_name);

void *find_module_return_addr(const std::vector<lsplt::MapInfo> &map_info, std::string_view module_suffix);

// --- Remote Stack Manipulation ---

void align_stack(struct user_regs_struct &regs, uintptr_t preserve_bytes = 0);

uintptr_t push_memory(int pid, struct user_regs_struct &regs, const void *data, size_t length);

uintptr_t push_string(int pid, struct user_regs_struct &regs, const char *str);

// --- Remote Function Call Emulation ---

bool remote_pre_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                     std::vector<uintptr_t> &args);

uintptr_t remote_post_call(int pid, struct user_regs_struct &regs, uintptr_t expected_return_addr);

uintptr_t remote_call(int pid, struct user_regs_struct &regs, uintptr_t func_addr, uintptr_t return_addr,
                      std::vector<uintptr_t> &args);

// --- Process Management and Ptrace Utilities ---

bool wait_for_trace(int pid, int *status, int flags);

std::string parse_status(int status);

std::string get_program(int pid);

// --- Miscellaneous Utilities ---

constexpr size_t kMaxPathLength = PATH_MAX; // Max path length, consistent with main.cpp
constexpr size_t kDefaultMagicLength = 16;  // Default length for generated magic strings.

std::string generateMagic(size_t length);

class UniqueFd {
    using Fd = int; // Alias for file descriptor type.

public:
    
    UniqueFd() = default;

    UniqueFd(Fd fd) : fd_(fd) {}

    ~UniqueFd() {
        if (fd_ >= 0)
            close(fd_);
    }

    // Delete copy constructor and assignment operator to prevent double-free issues.
    UniqueFd(const UniqueFd &) = delete;
    UniqueFd &operator=(const UniqueFd &) = delete;

    UniqueFd(UniqueFd &&other) noexcept {
        std::swap(fd_, other.fd_);
    }

    UniqueFd &operator=(UniqueFd &&other) noexcept {
        if (this != &other) { // Handle self-assignment
            if (fd_ >= 0)
                close(fd_); // Close current FD before taking ownership
            fd_ = -1;       // Invalidate current FD before swap
            std::swap(fd_, other.fd_);
        }
        return *this;
    }

    UniqueFd &operator=(Fd fd) {
        if (fd_ >= 0) {
            close(fd_);
        }
        fd_ = fd;
        return *this;
    }

    operator const Fd &() const {
        return fd_;
    }

private:
    Fd fd_ = -1; // The managed file descriptor, initialized to invalid.
};

// --- Ptrace Event and Signal Parsing ---

#define WPTEVENT(x) (x >> 16) // Macro to extract the ptrace event code from wait status.
#define CASE_CONST_RETURN(x) \
    case x:                  \
        return #x; // Helper macro for switch-case to return string literal.

inline const char *parse_ptrace_event(int status) {
    status = WPTEVENT(status); // Extract the event code.
    switch (status) {
        CASE_CONST_RETURN(PTRACE_EVENT_FORK)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK)
        CASE_CONST_RETURN(PTRACE_EVENT_CLONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXEC)
        CASE_CONST_RETURN(PTRACE_EVENT_VFORK_DONE)
        CASE_CONST_RETURN(PTRACE_EVENT_EXIT)
        CASE_CONST_RETURN(PTRACE_EVENT_SECCOMP)
        CASE_CONST_RETURN(PTRACE_EVENT_STOP) // Not a standard event, but sometimes
                                             // seen for special stops
    default:
        return "(no event)"; // Default for unknown or no event.
    }
}

inline const char *sigabbrev_np(int sig) {
    // NSIG is the total number of signals, sys_signame array is indexed by signal
    // number. Note: sys_signame is part of glibc and may require _GNU_SOURCE or
    // similar.
    if (sig > 0 && sig < NSIG)
        return sys_signame[sig];
    return "(unknown)";
}
