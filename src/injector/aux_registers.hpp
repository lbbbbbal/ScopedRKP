// Register backups stay in phone memory and are never printed or saved.
#pragma once
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <vector>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#include <signal.h>
inline bool srkp_cleanup_failed = false;
inline bool srkp_remote_fault = false;

struct SrkpSignalBlock {
    sigset_t previous{};
    bool valid = false;
    SrkpSignalBlock() {
        sigset_t block;
        sigemptyset(&block);
        sigaddset(&block, SIGINT); sigaddset(&block, SIGTERM);
        sigaddset(&block, SIGHUP); sigaddset(&block, SIGQUIT);
        valid = sigprocmask(SIG_BLOCK, &block, &previous) == 0;
    }
    ~SrkpSignalBlock() { if (valid) sigprocmask(SIG_SETMASK, &previous, nullptr); }
};

struct SrkpErrnoRestorer {
    int pid;
    uintptr_t address;
    int original;
    ~SrkpErrnoRestorer() {
        iovec local{&original, sizeof(original)};
        iovec remote{reinterpret_cast<void *>(address), sizeof(original)};
        if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != sizeof(original)) {
            srkp_cleanup_failed = true;
            LOGE("target thread errno restore failed");
        }
    }
};

struct SrkpAuxRegisters {
    struct State { unsigned note; std::vector<unsigned char> bytes; };
    int pid;
    bool valid = false;
    std::vector<State> states;
    static void wipe(std::vector<unsigned char> &bytes) {
        volatile unsigned char *p = bytes.data();
        for (size_t i = 0; i < bytes.size(); ++i) p[i] = 0;
    }
    explicit SrkpAuxRegisters(int target) : pid(target) {
        // FPSIMD is mandatory. Preserve additional vector state when exposed.
        for (unsigned note : {unsigned(NT_PRFPREG), 0x405u, 0x40cu, 0x40du}) {
            State state{note, std::vector<unsigned char>(1024 * 1024)};
            iovec iov{state.bytes.data(), state.bytes.size()};
            if (ptrace(PTRACE_GETREGSET, pid, note, &iov) == -1) {
                const int error = errno;
                wipe(state.bytes);
                if (note == NT_PRFPREG || (error != EINVAL && error != ENODEV && error != EIO)) return;
                continue;
            }
            if (!iov.iov_len || iov.iov_len >= state.bytes.size()) { wipe(state.bytes); return; }
            state.bytes.resize(iov.iov_len);
            states.push_back(std::move(state));
        }
        valid = !states.empty();
    }
    ~SrkpAuxRegisters() {
        // FPSIMD first, then SVE/SME: a later FPSIMD write could clear wide state.
        for (auto it = states.begin(); it != states.end(); ++it) {
            if (valid) {
                iovec iov{it->bytes.data(), it->bytes.size()};
                if (ptrace(PTRACE_SETREGSET, pid, it->note, &iov) == -1) {
                    srkp_cleanup_failed = true;
                    LOGE("aux register restore failed note=%u", it->note);
                }
            }
            wipe(it->bytes);
        }
    }
};
