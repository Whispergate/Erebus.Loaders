#define _WIN32_WINNT _WIN32_WINNT_VISTA
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include "../../include/guardrails/guardrails.hpp"
#include "../../include/loader.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace erebus {
namespace guardrails {

// String comparison helper (case-insensitive)
static bool StrEqualI(const char* a, const char* b) {
    if (!a || !b) return false;
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? (*a + 32) : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (*b + 32) : *b;
        if (ca != cb) return false;
        a++; b++;
    }
    return *a == *b;
}

// String prefix check for IP subnet matching
static bool StrStartsWith(const char* str, const char* prefix) {
    if (!str || !prefix) return false;
    while (*prefix) {
        if (*str != *prefix) return false;
        str++; prefix++;
    }
    return true;
}

GuardrailConfig GetDefaultConfig() {
    GuardrailConfig config = {};
    config.allowed_hostnames = nullptr;
    config.blocked_hostnames = nullptr;
    config.hostname_count_allowed = 0;
    config.hostname_count_blocked = 0;
    
    config.allowed_usernames = nullptr;
    config.blocked_usernames = nullptr;
    config.username_count_allowed = 0;
    config.username_count_blocked = 0;
    
    config.allowed_domains = nullptr;
    config.blocked_domains = nullptr;
    config.domain_count_allowed = 0;
    config.domain_count_blocked = 0;
    
    config.allowed_ips = nullptr;
    config.blocked_ips = nullptr;
    config.ip_count_allowed = 0;
    config.ip_count_blocked = 0;
    
    config.check_debugger_present = false;
    config.check_remote_debugger = false;
    config.check_debugger_processes = false;
    config.check_hardware_breakpoints = false;
    config.check_timing_checks = false;
    
    return config;
}

CheckResult RunGuardrails(const GuardrailConfig& config) {
    CheckResult result;
    
    // Hostname checks
    if (config.allowed_hostnames || config.blocked_hostnames) {
        result = CheckHostname(config.allowed_hostnames, config.hostname_count_allowed,
                              config.blocked_hostnames, config.hostname_count_blocked);
        if (!result.passed) return result;
    }
    
    // Username checks
    if (config.allowed_usernames || config.blocked_usernames) {
        result = CheckUsername(config.allowed_usernames, config.username_count_allowed,
                              config.blocked_usernames, config.username_count_blocked);
        if (!result.passed) return result;
    }
    
    // Domain checks
    if (config.allowed_domains || config.blocked_domains) {
        result = CheckDomain(config.allowed_domains, config.domain_count_allowed,
                           config.blocked_domains, config.domain_count_blocked);
        if (!result.passed) return result;
    }
    
    // IP address checks
    if (config.allowed_ips || config.blocked_ips) {
        result = CheckIPAddress(config.allowed_ips, config.ip_count_allowed,
                               config.blocked_ips, config.ip_count_blocked);
        if (!result.passed) return result;
    }
    
    // Anti-debugging checks
    if (config.check_debugger_present) {
        result = CheckDebuggerPresent();
        if (!result.passed) return result;
    }
    
    if (config.check_remote_debugger) {
        result = CheckRemoteDebugger();
        if (!result.passed) return result;
    }
    
    if (config.check_debugger_processes) {
        result = CheckDebuggerProcesses();
        if (!result.passed) return result;
    }
    
    if (config.check_hardware_breakpoints) {
        result = CheckHardwareBreakpoints();
        if (!result.passed) return result;
    }
    
    if (config.check_timing_checks) {
        result = CheckTimingAnomaly();
        if (!result.passed) return result;
    }
    
    // All checks passed
    result.passed = true;
    result.reason = "All guardrail checks passed";
    return result;
}

void GetComputerNameString(char* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize == 0) return;
    
    DWORD size = bufferSize;
    if (!GetComputerNameA(buffer, &size)) {
        buffer[0] = '\0';
    }
}

void GetUsernameString(char* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize == 0) return;
    
    DWORD size = bufferSize;
    if (!GetUserNameA(buffer, &size)) {
        buffer[0] = '\0';
    }
}

void GetDomainString(char* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize == 0) return;
    
    DWORD size = bufferSize;
    if (!GetComputerNameExA(ComputerNameDnsDomain, buffer, &size)) {
        // Fallback to workgroup name
        buffer[0] = '\0';
    }
}

void GetLocalIPAddress(char* buffer, DWORD bufferSize) {
    if (!buffer || bufferSize == 0) return;
    buffer[0] = '\0';
    
    // Get adapter addresses
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)::HeapAlloc(::GetProcessHeap(), 0, outBufLen);
    if (!pAddresses) return;
    
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD ret = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    
    if (ret == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            if (pCurrAddresses->OperStatus == IfOperStatusUp) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
                if (pUnicast) {
                    SOCKADDR_IN* sockaddr_ipv4 = (SOCKADDR_IN*)pUnicast->Address.lpSockaddr;
                    if (sockaddr_ipv4->sin_family == AF_INET) {
                        inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), buffer, bufferSize);
                        // Skip loopback
                        if (!StrStartsWith(buffer, "127.")) {
                            break;
                        }
                    }
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    HeapFree(GetProcessHeap(), 0, pAddresses);
}

CheckResult CheckHostname(const char** allowed, int allowed_count, 
                         const char** blocked, int blocked_count) {
    CheckResult result;
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    GetComputerNameString(hostname, sizeof(hostname));
    
    // Check blocked list first
    if (blocked && blocked_count > 0) {
        for (int i = 0; i < blocked_count; i++) {
            if (StrEqualI(hostname, blocked[i])) {
                result.passed = false;
                result.reason = "Hostname is blocked";
                return result;
            }
        }
    }
    
    // Check allowed list (if specified, hostname MUST be in list)
    if (allowed && allowed_count > 0) {
        bool found = false;
        for (int i = 0; i < allowed_count; i++) {
            if (StrEqualI(hostname, allowed[i])) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.passed = false;
            result.reason = "Hostname not in allowed list";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "Hostname check passed";
    return result;
}

CheckResult CheckUsername(const char** allowed, int allowed_count, 
                         const char** blocked, int blocked_count) {
    CheckResult result;
    char username[256] = {0};
    GetUsernameString(username, sizeof(username));
    
    // Check blocked list first
    if (blocked && blocked_count > 0) {
        for (int i = 0; i < blocked_count; i++) {
            if (StrEqualI(username, blocked[i])) {
                result.passed = false;
                result.reason = "Username is blocked";
                return result;
            }
        }
    }
    
    // Check allowed list
    if (allowed && allowed_count > 0) {
        bool found = false;
        for (int i = 0; i < allowed_count; i++) {
            if (StrEqualI(username, allowed[i])) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.passed = false;
            result.reason = "Username not in allowed list";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "Username check passed";
    return result;
}

CheckResult CheckDomain(const char** allowed, int allowed_count, 
                       const char** blocked, int blocked_count) {
    CheckResult result;
    char domain[256] = {0};
    GetDomainString(domain, sizeof(domain));
    
    // Check blocked list first
    if (blocked && blocked_count > 0) {
        for (int i = 0; i < blocked_count; i++) {
            if (StrEqualI(domain, blocked[i])) {
                result.passed = false;
                result.reason = "Domain is blocked";
                return result;
            }
        }
    }
    
    // Check allowed list
    if (allowed && allowed_count > 0) {
        bool found = false;
        for (int i = 0; i < allowed_count; i++) {
            if (StrEqualI(domain, allowed[i])) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.passed = false;
            result.reason = "Domain not in allowed list";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "Domain check passed";
    return result;
}

CheckResult CheckIPAddress(const char** allowed, int allowed_count, 
                          const char** blocked, int blocked_count) {
    CheckResult result;
    char ipaddr[64] = {0};
    GetLocalIPAddress(ipaddr, sizeof(ipaddr));
    
    // Check blocked list first
    if (blocked && blocked_count > 0) {
        for (int i = 0; i < blocked_count; i++) {
            // Simple string prefix match for subnets (e.g., "192.168.")
            if (StrStartsWith(ipaddr, blocked[i]) || StrEqualI(ipaddr, blocked[i])) {
                result.passed = false;
                result.reason = "IP address is blocked";
                return result;
            }
        }
    }
    
    // Check allowed list
    if (allowed && allowed_count > 0) {
        bool found = false;
        for (int i = 0; i < allowed_count; i++) {
            if (StrStartsWith(ipaddr, allowed[i]) || StrEqualI(ipaddr, allowed[i])) {
                found = true;
                break;
            }
        }
        if (!found) {
            result.passed = false;
            result.reason = "IP address not in allowed list";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "IP address check passed";
    return result;
}

CheckResult CheckDebuggerPresent() {
    CheckResult result;
    
    // IsDebuggerPresent check
    if (IsDebuggerPresent()) {
        result.passed = false;
        result.reason = "Debugger detected (IsDebuggerPresent)";
        return result;
    }
    
    // PEB BeingDebugged flag check
    BOOL beingDebugged = FALSE;
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    
    if (peb && peb->BeingDebugged) {
        result.passed = false;
        result.reason = "Debugger detected (PEB.BeingDebugged)";
        return result;
    }
    
    result.passed = true;
    result.reason = "No debugger detected";
    return result;
}

CheckResult CheckRemoteDebugger() {
    CheckResult result;
    
    typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength
    );
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        result.passed = true;
        result.reason = "Unable to check remote debugger";
        return result;
    }
    
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    
    if (NtQueryInformationProcess) {
        DWORD_PTR debugPort = 0;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            NULL
        );
        
        if (status == 0 && debugPort != 0) {
            result.passed = false;
            result.reason = "Remote debugger detected";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "No remote debugger detected";
    return result;
}

bool IsProcessRunning(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    PROCESSENTRY32W pe32 = {0};
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Case-insensitive comparison
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

CheckResult CheckDebuggerProcesses() {
    CheckResult result;
    
    // List of common debugger process names
    const wchar_t* debuggerProcesses[] = {
        L"x64dbg.exe",
        L"x32dbg.exe",
        L"windbg.exe",
        L"ollydbg.exe",
        L"ida.exe",
        L"ida64.exe",
        L"idag.exe",
        L"idag64.exe",
        L"idaw.exe",
        L"idaw64.exe",
        L"idaq.exe",
        L"idaq64.exe",
        L"idau.exe",
        L"idau64.exe",
        L"scylla.exe",
        L"scylla_x64.exe",
        L"scylla_x86.exe",
        L"protection_id.exe",
        L"x96dbg.exe",
        L"immunitydebugger.exe",
        L"ImportREC.exe",
        L"MegaDumper.exe",
        L"LordPE.exe",
        L"reshacker.exe",
        L"ResourceHacker.exe",
        L"ImportREC.exe",
        L"IMMUNITYDEBUGGER.EXE",
        L"devenv.exe",         // Visual Studio
        L"dnSpy.exe",
        L"dnSpy-x86.exe",
        L"de4dot.exe",
        L"ilspy.exe",
        L"Fiddler.exe",
        L"charles.exe",
        L"Wireshark.exe",
        L"dumpcap.exe",
        L"tcpdump.exe",
        L"ProcessHacker.exe",
        L"procmon.exe",
        L"procexp.exe",
        L"procmon64.exe",
        L"procexp64.exe"
    };
    
    int numDebuggers = sizeof(debuggerProcesses) / sizeof(debuggerProcesses[0]);
    
    for (int i = 0; i < numDebuggers; i++) {
        if (IsProcessRunning(debuggerProcesses[i])) {
            result.passed = false;
            result.reason = "Debugger process detected";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "No debugger processes detected";
    return result;
}

CheckResult CheckHardwareBreakpoints() {
    CheckResult result;
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // Check if any debug registers are set
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            result.passed = false;
            result.reason = "Hardware breakpoints detected";
            return result;
        }
    }
    
    result.passed = true;
    result.reason = "No hardware breakpoints detected";
    return result;
}

CheckResult CheckTimingAnomaly() {
    CheckResult result;
    
    // RDTSC timing check
    DWORD64 start = __rdtsc();
    
    // Perform some simple operations
    volatile int x = 0;
    for (int i = 0; i < 100; i++) {
        x += i;
    }
    
    DWORD64 end = __rdtsc();
    DWORD64 elapsed = end - start;
    
    // If execution took suspiciously long (> 100000 cycles for simple loop)
    // it may indicate single-stepping or breakpoints
    if (elapsed > 100000) {
        result.passed = false;
        result.reason = "Timing anomaly detected (possible debugger)";
        return result;
    }
    
    // GetTickCount timing check
    DWORD tick_start = GetTickCount();
    Sleep(10);
    DWORD tick_end = GetTickCount();
    DWORD tick_elapsed = tick_end - tick_start;
    
    // Sleep(10) should take ~10-20ms, if it's much longer, debugger may be present
    if (tick_elapsed > 100) {
        result.passed = false;
        result.reason = "Sleep timing anomaly detected";
        return result;
    }
    
    result.passed = true;
    result.reason = "No timing anomalies detected";
    return result;
}

bool CheckIfDebugged() {
    // Master check that runs all anti-debug checks
    if (!CheckDebuggerPresent().passed) return true;
    if (!CheckRemoteDebugger().passed) return true;
    if (!CheckHardwareBreakpoints().passed) return true;
    if (!CheckDebuggerProcesses().passed) return true;
    if (!CheckTimingAnomaly().passed) return true;
    
    return false;
}

} // namespace guardrails
} // namespace erebus
