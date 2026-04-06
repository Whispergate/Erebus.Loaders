/**
 * @file test_guardrails.cpp
 * @brief Test suite for all guardrail checks
 *
 * Exercises every guardrail check individually and reports results.
 * This is a diagnostic tool - checks that "fail" are expected when
 * running on a real operator workstation (debugger present, VM, etc.).
 *
 * Build: make test-guardrails
 * Run:   ./erebus_guardrails_test.exe
 */

#include <cstdio>
#include <cstring>
#include <windows.h>

#ifndef _DEBUG
#define _DEBUG 1
#endif

#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE 0
#endif

#include "../include/loader.hpp"

// ============================================
// COLOUR HELPERS
// ============================================

#define PRINT_HEADER(msg) \
    printf(COLOUR_BOLD COLOUR_CYAN "\n========================================\n"); \
    printf("%s\n", msg); \
    printf("========================================" COLOUR_DEFAULT "\n")

#define PRINT_PASS(msg) \
    printf(COLOUR_BOLD COLOUR_GREEN "  [PASS] " COLOUR_DEFAULT "%s\n", msg)

#define PRINT_FAIL(msg, reason) \
    printf(COLOUR_BOLD COLOUR_RED   "  [FAIL] " COLOUR_DEFAULT "%s - %s\n", msg, reason)

#define PRINT_INFO(msg) \
    printf(COLOUR_BOLD COLOUR_BLUE  "  [INFO] " COLOUR_DEFAULT "%s\n", msg)

// ============================================
// INDIVIDUAL CHECK WRAPPERS
// ============================================

static int g_pass = 0;
static int g_fail = 0;

void RunCheck(const char* name, erebus::guardrails::CheckResult result) {
    if (result.passed) {
        PRINT_PASS(name);
        g_pass++;
    } else {
        PRINT_FAIL(name, result.reason ? result.reason : "unknown");
        g_fail++;
    }
}

// ============================================
// ENVIRONMENT INFO
// ============================================

void PrintEnvironment() {
    PRINT_HEADER("ENVIRONMENT INFO");

    char hostname[256] = {};
    char username[256] = {};
    char domain[256] = {};
    char ip[64] = {};

    erebus::guardrails::GetComputerNameString(hostname, sizeof(hostname));
    erebus::guardrails::GetUsernameString(username, sizeof(username));
    erebus::guardrails::GetDomainString(domain, sizeof(domain));
    erebus::guardrails::GetLocalIPAddress(ip, sizeof(ip));

    printf("  Hostname : %s\n", hostname);
    printf("  Username : %s\n", username);
    printf("  Domain   : %s\n", domain);
    printf("  IP       : %s\n", ip);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    printf("  CPUs     : %lu\n", si.dwNumberOfProcessors);

    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        printf("  RAM      : %llu MB\n", mem.ullTotalPhys / (1024 * 1024));
    }

    ULARGE_INTEGER totalDisk = {};
    if (GetDiskFreeSpaceExA("C:\\", NULL, &totalDisk, NULL)) {
        printf("  Disk (C:): %llu GB\n", totalDisk.QuadPart / (1024ULL * 1024 * 1024));
    }
}

// ============================================
// ANTI-DEBUGGING TESTS
// ============================================

void TestAntiDebugging() {
    PRINT_HEADER("ANTI-DEBUGGING CHECKS");

    RunCheck("IsDebuggerPresent",
             erebus::guardrails::CheckDebuggerPresent());

    RunCheck("Remote Debugger (ProcessDebugPort)",
             erebus::guardrails::CheckRemoteDebugger());

    RunCheck("Known Debugger Processes",
             erebus::guardrails::CheckDebuggerProcesses());

    RunCheck("Hardware Breakpoints (DR0-DR3)",
             erebus::guardrails::CheckHardwareBreakpoints());

    RunCheck("Timing Anomaly (Sleep jitter)",
             erebus::guardrails::CheckTimingAnomaly());
}

// ============================================
// SANDBOX / VM TESTS
// ============================================

void TestSandboxDetection() {
    PRINT_HEADER("SANDBOX / VM DETECTION");

    RunCheck("Sandbox Environment (combined)",
             erebus::guardrails::CheckSandboxEnvironment());
}

// ============================================
// HOSTNAME CHECKS
// ============================================

void TestHostnameChecks() {
    PRINT_HEADER("HOSTNAME CHECKS");

    // Get current hostname
    char hostname[256] = {};
    erebus::guardrails::GetComputerNameString(hostname, sizeof(hostname));
    printf("  Current hostname: %s\n\n", hostname);

    // Test 1: Allow list containing current hostname - should pass
    const char* allowList[] = { hostname };
    RunCheck("Hostname whitelist (current host - should pass)",
             erebus::guardrails::CheckHostname(allowList, 1, nullptr, 0));

    // Test 2: Allow list NOT containing current hostname - should fail
    const char* wrongAllowList[] = { "NONEXISTENT-HOST-12345" };
    erebus::guardrails::CheckResult r2 = erebus::guardrails::CheckHostname(wrongAllowList, 1, nullptr, 0);
    if (!r2.passed) {
        PRINT_PASS("Hostname whitelist (wrong host - correctly rejected)");
        g_pass++;
    } else {
        PRINT_FAIL("Hostname whitelist (wrong host - should have rejected)", "passed unexpectedly");
        g_fail++;
    }

    // Test 3: Block list containing current hostname - should fail
    const char* blockList[] = { hostname };
    erebus::guardrails::CheckResult r3 = erebus::guardrails::CheckHostname(nullptr, 0, blockList, 1);
    if (!r3.passed) {
        PRINT_PASS("Hostname blocklist (current host - correctly blocked)");
        g_pass++;
    } else {
        PRINT_FAIL("Hostname blocklist (current host - should have blocked)", "passed unexpectedly");
        g_fail++;
    }

    // Test 4: Block list NOT containing current hostname - should pass
    const char* wrongBlockList[] = { "SANDBOX", "MALWARE-ANALYSIS" };
    RunCheck("Hostname blocklist (non-matching - should pass)",
             erebus::guardrails::CheckHostname(nullptr, 0, wrongBlockList, 2));
}

// ============================================
// USERNAME CHECKS
// ============================================

void TestUsernameChecks() {
    PRINT_HEADER("USERNAME CHECKS");

    char username[256] = {};
    erebus::guardrails::GetUsernameString(username, sizeof(username));
    printf("  Current username: %s\n\n", username);

    // Allow current user - should pass
    const char* allowList[] = { username };
    RunCheck("Username whitelist (current user - should pass)",
             erebus::guardrails::CheckUsername(allowList, 1, nullptr, 0));

    // Block current user - should fail
    const char* blockList[] = { username };
    erebus::guardrails::CheckResult r = erebus::guardrails::CheckUsername(nullptr, 0, blockList, 1);
    if (!r.passed) {
        PRINT_PASS("Username blocklist (current user - correctly blocked)");
        g_pass++;
    } else {
        PRINT_FAIL("Username blocklist (current user - should have blocked)", "passed unexpectedly");
        g_fail++;
    }

    // Block analysis usernames - should pass on real machine
    const char* analysisUsers[] = { "analyst", "malware", "sandbox" };
    RunCheck("Username blocklist (analysis names - should pass on real host)",
             erebus::guardrails::CheckUsername(nullptr, 0, analysisUsers, 3));
}

// ============================================
// DOMAIN CHECKS
// ============================================

void TestDomainChecks() {
    PRINT_HEADER("DOMAIN CHECKS");

    char domain[256] = {};
    erebus::guardrails::GetDomainString(domain, sizeof(domain));
    printf("  Current domain: %s\n\n", domain);

    if (strlen(domain) > 0) {
        const char* allowList[] = { domain };
        RunCheck("Domain whitelist (current domain - should pass)",
                 erebus::guardrails::CheckDomain(allowList, 1, nullptr, 0));
    } else {
        PRINT_INFO("No domain joined - skipping domain whitelist test");
    }

    const char* blockList[] = { "SANDBOX.LOCAL", "ANALYSIS.LAB" };
    RunCheck("Domain blocklist (analysis domains - should pass on real host)",
             erebus::guardrails::CheckDomain(nullptr, 0, blockList, 2));
}

// ============================================
// IP ADDRESS CHECKS
// ============================================

void TestIPAddressChecks() {
    PRINT_HEADER("IP ADDRESS CHECKS");

    char ip[64] = {};
    erebus::guardrails::GetLocalIPAddress(ip, sizeof(ip));
    printf("  Current IP: %s\n\n", ip);

    if (strlen(ip) > 0) {
        const char* allowList[] = { ip };
        RunCheck("IP whitelist (current IP - should pass)",
                 erebus::guardrails::CheckIPAddress(allowList, 1, nullptr, 0));
    } else {
        PRINT_INFO("No IP detected - skipping IP whitelist test");
    }

    const char* blockList[] = { "192.168.122.", "10.0.2." };
    RunCheck("IP blocklist (common sandbox ranges - should pass on real host)",
             erebus::guardrails::CheckIPAddress(nullptr, 0, blockList, 2));
}

// ============================================
// FULL PIPELINE TEST
// ============================================

void TestFullPipeline() {
    PRINT_HEADER("FULL GUARDRAILS PIPELINE");

    // Test with all checks enabled
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();
    config.check_debugger_present = true;
    config.check_remote_debugger = true;
    config.check_debugger_processes = true;
    config.check_hardware_breakpoints = true;
    config.check_timing_checks = true;
    config.check_sandbox_environment = true;

    const char* blockHostnames[] = { "SANDBOX", "MALWARE-ANALYSIS" };
    config.blocked_hostnames = blockHostnames;
    config.hostname_count_blocked = 2;

    const char* blockUsers[] = { "analyst", "malware", "sandbox" };
    config.blocked_usernames = blockUsers;
    config.username_count_blocked = 3;

    erebus::guardrails::CheckResult result = erebus::guardrails::RunGuardrails(config);
    RunCheck("Full pipeline (all checks enabled)", result);
}

// ============================================
// MAIN
// ============================================

int main() {
    printf(COLOUR_BOLD COLOUR_CYAN "\n");
    printf("================================================\n");
    printf("    EREBUS LOADER - GUARDRAILS TEST SUITE       \n");
    printf("================================================\n");
    printf(COLOUR_DEFAULT "\n");

    PrintEnvironment();
    TestAntiDebugging();
    TestSandboxDetection();
    TestHostnameChecks();
    TestUsernameChecks();
    TestDomainChecks();
    TestIPAddressChecks();
    TestFullPipeline();

    // Summary
    printf(COLOUR_BOLD COLOUR_CYAN "\n========================================\n");
    printf("GUARDRAILS TEST SUMMARY\n");
    printf("========================================" COLOUR_DEFAULT "\n");
    printf(COLOUR_GREEN "  Passed: %d" COLOUR_DEFAULT "\n", g_pass);
    printf(COLOUR_RED   "  Failed: %d" COLOUR_DEFAULT "\n", g_fail);
    printf("  Total:  %d\n", g_pass + g_fail);
    printf("\n");
    printf(COLOUR_BOLD COLOUR_BLUE "NOTE: " COLOUR_DEFAULT
           "'FAIL' results are expected on dev machines (debugger attached,\n"
           "       VM environment, etc.). The test verifies each check EXECUTES\n"
           "       correctly, not that your machine is 'clean'.\n\n");

    return 0;
}
