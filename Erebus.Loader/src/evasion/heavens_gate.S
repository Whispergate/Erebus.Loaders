/*
 * heavens_gate.S  -  Heaven's Gate 32→64 syscall thunk (GAS / MinGW x86)
 *
 * Assembled only when CONFIG_SYSCALL_BACKEND=2 and ARCH=x86.
 *
 * ABI contract (stdcall-like, all 32-bit slots on entry):
 *   [esp+4]   ULONG ssn
 *   [esp+8]   arg1  (ULONG / pointer low word)
 *   [esp+12]  arg2
 *   ...
 *   [esp+48]  arg11  (maximum needed by any registered Nt* call)
 *
 * Strategy:
 *   1. Switch to 64-bit code segment 0x33 via a far jump built at runtime.
 *   2. Restore a 64-bit stack frame; widen the 32-bit args to 64-bit QWORDs.
 *   3. Load SSN into EAX, shadow-stack the register args per Win64 ABI,
 *      then issue `syscall`.
 *   4. Far-ret back to CS 0x23 (32-bit compat).
 *   5. Return NTSTATUS in EAX (low 32 bits; caller truncates fine).
 *
 * Segment selectors (fixed on all WoW64 Windows versions):
 *   0x23  32-bit compatibility segment
 *   0x33  64-bit long-mode segment
 */

    .intel_syntax noprefix

    .text

/*
 * HvGateCall(ULONG ssn, arg1 ... arg11)
 *
 * Exported as a C symbol so C++ callers can call it without name mangling.
 */
    .global _HvGateCall
_HvGateCall:

    /* Save caller-saved x86 registers we will clobber. */
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    /* ---------------------------------------------------------------
     * Build the far-call trampoline at runtime on the stack.
     * We need:  [offset32] [selector16]  == two DWORDs in memory.
     * The absolute target address is the label `_hg_64bit_entry`.
     * We write it just below esp so a `call fword ptr [esp-8]` style
     * is used, but we use the classic push/push/retf pattern instead
     * which avoids needing the absolute address before link time.
     * ---------------------------------------------------------------
     * Classic pattern:
     *   push  0x33                ; 64-bit CS selector
     *   push  offset _hg_64bit_target
     *   retf                      ; far return pops EIP:CS -> switches mode
     */
    push    0x33
    call    _hg_get_rip            /* get current EIP into ecx via call trick */
_hg_get_rip:
    pop     ecx
    add     ecx, (_hg_64bit_entry - _hg_get_rip)   /* ecx = address of _hg_64bit_entry */
    push    ecx                    /* low 32 bits of target offset */
    /* Stack now: [target_lo32] [0x33] - a 48-bit far pointer. */
    /* Use retf to do the far jump: pops EIP then CS. */
    retf                           /* -> mode switches to 64-bit, CS=0x33 */

/* ---------------------------------------------------------------
 * 64-bit code island.  From here the CPU is in 64-bit long mode.
 * The assembler is told via .code64 but the surrounding .text
 * section is still 32-bit; GAS emits the right encodings because
 * we're explicitly switching directive context.
 * ---------------------------------------------------------------*/
    .code64
_hg_64bit_entry:

    /* On entry (64-bit view of the WoW64 stack):
     *   RSP+0    = saved return address pushed by the retf above (EIP, 32-bit)
     *             but RSP is still 32-bit-aligned and the high 32 bits of
     *             RSP are the WoW64 TEB-stashed high half.  We must keep
     *             the high RSP word intact.
     *
     * Caller frame (from _HvGateCall entry, all at [EBP+...]):
     *   EBP+8  = SSN
     *   EBP+12 = arg1 (RCX)
     *   EBP+16 = arg2 (RDX)
     *   EBP+20 = arg3 (R8)
     *   EBP+24 = arg4 (R9)
     *   EBP+28 = arg5  [stack]
     *   EBP+32 = arg6  [stack]
     *   ...
     *   EBP+52 = arg11 [stack]
     */

    /* Restore the real 64-bit RSP from WoW64's saved value.
     * WoW64 stores the 64-bit stack pointer at fs:[0xC0] (32-bit TEB) /
     * gs:[0x1488] (64-bit TEB).  We read from the 32-bit TEB offset. */
    /* Simpler: we are still on the same physical stack; EBP was pushed
     * and is a valid 32-bit frame pointer.  Zero-extend EBP to RBP. */
    movsx   rbp, ebp               /* sign-extend 32-bit EBP → RBP */
    lea     rsp, [rbp - 0x20]      /* allocate shadow space below frame */
    and     rsp, -16               /* 16-byte align per Win64 ABI */

    /* Load SSN */
    movsx   rax, dword ptr [rbp + 8]

    /* Load register args (zero-extend 32-bit slots to 64-bit) */
    movsx   rcx, dword ptr [rbp + 12]   /* arg1 → RCX */
    movsx   rdx, dword ptr [rbp + 16]   /* arg2 → RDX */
    movsx   r8,  dword ptr [rbp + 20]   /* arg3 → R8  */
    movsx   r9,  dword ptr [rbp + 24]   /* arg4 → R9  */

    /* Stack args 5-11: push in reverse order after shadow space.
     * Win64 ABI: [rsp+0x20]=arg5, [rsp+0x28]=arg6, ... */
    movsx   r10, dword ptr [rbp + 52]   /* arg11 */
    push    r10
    movsx   r10, dword ptr [rbp + 48]   /* arg10 */
    push    r10
    movsx   r10, dword ptr [rbp + 44]   /* arg9  */
    push    r10
    movsx   r10, dword ptr [rbp + 40]   /* arg8  */
    push    r10
    movsx   r10, dword ptr [rbp + 36]   /* arg7  */
    push    r10
    movsx   r10, dword ptr [rbp + 32]   /* arg6  */
    push    r10
    movsx   r10, dword ptr [rbp + 28]   /* arg5  */
    push    r10

    /* Win64 ABI: r10 = rcx copy for syscall ABI */
    mov     r10, rcx

    /* Issue the native 64-bit syscall */
    syscall

    /* Tear down stack args */
    add     rsp, 0x38               /* 7 × 8 bytes */

    /* Return to 32-bit compat mode. Push CS:EIP of the return label. */
    push    0x23                    /* 32-bit compat CS */
    lea     r10, [rip + _hg_return32]
    push    r10
    retfq                           /* pops RIP:CS, switches mode back to 32-bit */

    .code32
_hg_return32:
    /* Back in 32-bit mode.  EAX holds NTSTATUS (low 32 bits of RAX). */
    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret                             /* stdcall return; caller cleans args */
