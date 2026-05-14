#pragma once

/* ptrace(PT_DENY_ATTACH) - kills any attaching debugger. Call early. */
void erebus_deny_attach(void);

/* sysctl KERN_PROC_PID P_TRACED - returns 1 if debugger is present. */
int erebus_check_debug(void);

/* mach_absolute_time spin loop - returns 1 if timing exceeds threshold. */
int erebus_check_timing(void);

/* Case-insensitive hostname substring check. */
int erebus_check_hostname(const char **blocked, int count);

/* Case-insensitive $USER substring check. */
int erebus_check_username(const char **blocked, int count);

/* Aggregate check - 1 = OK to proceed, 0 = abort. */
int erebus_guardrails_check(void);
