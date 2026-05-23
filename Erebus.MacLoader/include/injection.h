#pragma once
#include <stddef.h>

/* mmap(MAP_JIT) + pthread_create. Works on both x86_64 and arm64.
 * arm64: uses pthread_jit_write_protect_np + sys_icache_invalidate. */
void erebus_mmap_pthread(const unsigned char *sc, size_t sc_len);

/* Mach vm_allocate + mach_vm_write + thread_create_running (self-task).
 * Allocates RX memory via the Mach VM subsystem, avoids mmap(MAP_JIT)
 * but requires a hardened-runtime entitlement or SIP-disabled system
 * for vm_protect with VM_PROT_EXECUTE on arm64. */
void erebus_mach_thread(const unsigned char *sc, size_t sc_len);
