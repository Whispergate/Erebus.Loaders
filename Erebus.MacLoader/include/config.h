#pragma once

#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE 1
#endif

#ifndef CONFIG_GUARDRAILS_ENABLED
#define CONFIG_GUARDRAILS_ENABLED 0
#endif

/* ptrace(PT_DENY_ATTACH) - raises SIGSEGV/kills any attached debugger. */
#ifndef CONFIG_DENY_ATTACH
#define CONFIG_DENY_ATTACH 1
#endif

/* sysctl KERN_PROC P_TRACED flag check. */
#ifndef CONFIG_CHECK_DEBUG
#define CONFIG_CHECK_DEBUG 1
#endif

/* mach_absolute_time loop timing anomaly check. */
#ifndef CONFIG_CHECK_TIMING
#define CONFIG_CHECK_TIMING 0
#endif

/* Optional C-array initialisers injected by Makefile:
 *   -DCONFIG_BLOCKED_HOSTNAMES='{"sandbox","malware"}'
 *   -DCONFIG_BLOCKED_USERNAMES='{"analyst","user"}'
 */
