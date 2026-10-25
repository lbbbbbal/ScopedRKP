// Parent-owned child only; no PID argument and no system-service targets.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include "activation.h"
#include "owned_elf.h"
#include "policy.hpp"
#include <sys/uio.h>
#include <dirent.h>
static unsigned child_fds(pid_t p) {
    char path[64]; snprintf(path,sizeof(path),"/proc/%d/fd",p);
    DIR *d=opendir(path); if(!d) return UINT_MAX;
    unsigned n=0; while(auto *e=readdir(d)) if(strcmp(e->d_name,".") && strcmp(e->d_name,"..")) ++n;
    closedir(d); return n;
}
namespace inject { bool inject_library(int, const char *, const char *, const SrkpActivation *); }
static volatile sig_atomic_t owned_child = 0;
static void own_test_timeout(int) {
    const pid_t child = owned_child;
    if (child > 1) kill(child, SIGKILL);
    const char message[] = "Owned-child test timed out; only its own fixture was terminated.\n";
    write(STDERR_FILENO, message, sizeof(message)-1);
    _exit(124);
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char directory[PATH_MAX]{};
    if (!realpath(argv[1], directory)) return 3;
    const std::string base(directory), executable = base + "/srkp_fixture", library = base + "/libsrkp_fixture.so";
    int command[2], output[2];
    if (pipe(command) || pipe(output)) return 4;
    const pid_t child = fork();
    if (child == -1) return 5;
    if (!child) {
        dup2(command[0], 0); dup2(output[1], 1);
        close(command[0]); close(command[1]); close(output[0]); close(output[1]);
        execl(executable.c_str(), executable.c_str(), "--wait", library.c_str(), nullptr);
        _exit(127);
    }
    owned_child = child;
    signal(SIGALRM, own_test_timeout);
    alarm(30);
    close(command[0]); close(output[1]);
    pollfd fd{output[0], POLLIN, 0};
    bool ready = poll(&fd, 1, 10000) > 0;
    char greeting[128]{};
    ssize_t length = ready ? read(output[0], greeting, sizeof(greeting)-1) : -1;
    int declared_pid = 0;
    ready = length > 0 && sscanf(greeting, "READY %d", &declared_pid) == 1 && declared_pid == child;
    if (!ready) { kill(child, SIGKILL); waitpid(child, nullptr, 0); return 6; }
    // This PID was created by this process, with a fixed fixture executable.
    const SrkpActivation policy{SRKP_ACTIVATION_MAGIC, 4, 4, {10001,10002,10003,10004}};
    unsigned warm_fds=0;
    for(unsigned i=0;i<100;i++) {
        const bool injected=inject::inject_library(child,library.c_str(),"srkp_enable",&policy);
        if(!injected) { kill(child,SIGKILL); waitpid(child,nullptr,0); return 7; }
        if(i==0) warm_fds=child_fds(child);
        if(child_fds(child)!=warm_fds) { kill(child,SIGKILL); waitpid(child,nullptr,0); return 11; }
    }
    if(srkp_image_load_count.load()!=1 || srkp_image_reuse_count.load()!=99) { kill(child,SIGKILL); waitpid(child,nullptr,0); return 12; }
    SrkpOwnedElf image(library.c_str());
    const auto mapping=image.mapping(child);
    const auto diagnostic=image.symbol("srkp_state",STT_OBJECT);
    SrkpState data;
    if(!diagnostic || diagnostic->size!=sizeof(data) || !mapping.base || mapping.conflict) return 13;
    iovec local{&data,sizeof(data)},remote{reinterpret_cast<void *>(mapping.base+diagnostic->value),sizeof(data)};
    if(process_vm_readv(child,&local,1,&remote,1,0)!=sizeof(data) || data.magic!=SRKP_STATE_MAGIC
        || data.abi!=4 || data.count.load()!=4 || data.enabled.load()!=1) return 14;
    printf("{\"injector_reloads\":100,\"initial_library_loads\":1,\"existing_image_reuses\":99,\"target_fd_count_stable\":true,\"target_fds\":%u}\n",warm_fds);
    puts("{\"readonly_diagnostic_schema_verified\":true,\"persistent_policy_verified\":true}");
    if (write(command[1], "RUN\n", 4) != 4) { kill(child, SIGKILL); waitpid(child, nullptr, 0); return 8; }
    close(command[1]);
    char buffer[1024];
    while (poll(&fd, 1, 10000) > 0) {
        length = read(output[0], buffer, sizeof(buffer));
        if (length <= 0) break;
        fwrite(buffer, 1, length, stdout); fflush(stdout);
    }
    int status = 0;
    for (unsigned i = 0; i < 100; ++i) {
        if (waitpid(child, &status, WNOHANG) == child) {
            owned_child = 0; alarm(0);
            const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
            printf("{\"owned_child_injector_test\":%s,\"system_service_touched\":false}\n", ok ? "true" : "false");
            return ok ? 0 : 9;
        }
        usleep(10000);
    }
    kill(child, SIGKILL); waitpid(child, nullptr, 0);
    return 10;
}
