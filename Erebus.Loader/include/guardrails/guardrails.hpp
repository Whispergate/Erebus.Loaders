#pragma once

#include <windows.h>

namespace erebus {
namespace guardrails {

/**
 * @brief Environment check result structure
 */
struct CheckResult {
    bool passed;           // True if check passed (environment is safe to run)
    const char* reason;   // Human-readable reason if check failed
};

/**
 * @brief Guardrail configuration structure
 * 
 * Configure which checks to perform and their parameters.
 * Use nullptr for string arrays to skip that check.
 */
struct GuardrailConfig {
    // Hostname checks
    const char** allowed_hostnames;      // Whitelist: only run on these hostnames (nullptr = skip check)
    const char** blocked_hostnames;      // Blacklist: don't run on these hostnames (nullptr = skip check)
    int hostname_count_allowed;
    int hostname_count_blocked;
    
    // Username checks
    const char** allowed_usernames;      // Whitelist: only run for these users (nullptr = skip check)
    const char** blocked_usernames;      // Blacklist: don't run for these users (nullptr = skip check)
    int username_count_allowed;
    int username_count_blocked;
    
    // Domain checks
    const char** allowed_domains;        // Whitelist: only run on these domains (nullptr = skip check)
    const char** blocked_domains;        // Blacklist: don't run on these domains (nullptr = skip check)
    int domain_count_allowed;
    int domain_count_blocked;
    
    // IP address checks (format: "192.168.1.100" or "10.0.0.0/24")
    const char** allowed_ips;            // Whitelist: only run on these IPs/subnets (nullptr = skip check)
    const char** blocked_ips;            // Blacklist: don't run on these IPs/subnets (nullptr = skip check)
    int ip_count_allowed;
    int ip_count_blocked;
    
    // Anti-debugging checks
    bool check_debugger_present;         // Check IsDebuggerPresent
    bool check_remote_debugger;          // Check for remote debugger
    bool check_debugger_processes;       // Check for known debugger processes
    bool check_hardware_breakpoints;     // Check hardware breakpoints in debug registers
    bool check_timing_checks;            // Perform timing-based detection
};

/**
 * @brief Initialize default guardrail configuration (all checks disabled)
 */
GuardrailConfig GetDefaultConfig();

/**
 * @brief Run all configured guardrail checks
 * 
 * @param config Guardrail configuration
 * @return CheckResult with passed=true if all checks passed, false otherwise
 */
CheckResult RunGuardrails(const GuardrailConfig& config);

// Individual check functions
CheckResult CheckHostname(const char** allowed, int allowed_count, 
                         const char** blocked, int blocked_count);
CheckResult CheckUsername(const char** allowed, int allowed_count, 
                         const char** blocked, int blocked_count);
CheckResult CheckDomain(const char** allowed, int allowed_count, 
                       const char** blocked, int blocked_count);
CheckResult CheckIPAddress(const char** allowed, int allowed_count, 
                          const char** blocked, int blocked_count);

// Anti-debugging checks
CheckResult CheckDebuggerPresent();
CheckResult CheckRemoteDebugger();
CheckResult CheckDebuggerProcesses();
CheckResult CheckHardwareBreakpoints();
CheckResult CheckTimingAnomaly();

// Helper functions
bool CheckIfDebugged();                  // Master anti-debug check (runs all enabled checks)
bool IsProcessRunning(const wchar_t* processName);
void GetComputerNameString(char* buffer, DWORD bufferSize);
void GetUsernameString(char* buffer, DWORD bufferSize);
void GetDomainString(char* buffer, DWORD bufferSize);
void GetLocalIPAddress(char* buffer, DWORD bufferSize);

} // namespace guardrails
} // namespace erebus
