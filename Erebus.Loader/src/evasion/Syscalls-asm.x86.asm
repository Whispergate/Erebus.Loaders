.686
.XMM
.MODEL flat, c
ASSUME fs:_DATA
.code

EXTERN SW3_GetSyscallNumber: PROC
EXTERN local_is_wow64: PROC
EXTERN internal_cleancall_wow64_gate: PROC
EXTERN SW3_GetSyscallAddress: PROC

Sw3NtAccessCheck PROC
		push ebp
		mov ebp, esp
		push 084194C45h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 084194C45h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_84194C45:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_84194C45
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_84194C45
		call do_sysenter_interrupt_84194C45
		lea esp, [esp+4]
	ret_address_epilog_84194C45:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_84194C45:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheck ENDP

Sw3NtWorkerFactoryWorkerReady PROC
		push ebp
		mov ebp, esp
		push 017AB350Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 017AB350Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_17AB350D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_17AB350D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_17AB350D
		call do_sysenter_interrupt_17AB350D
		lea esp, [esp+4]
	ret_address_epilog_17AB350D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_17AB350D:
		mov edx, esp
		jmp edi
		ret
Sw3NtWorkerFactoryWorkerReady ENDP

Sw3NtAcceptConnectPort PROC
		push ebp
		mov ebp, esp
		push 026B13D1Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 026B13D1Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_26B13D1E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_26B13D1E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_26B13D1E
		call do_sysenter_interrupt_26B13D1E
		lea esp, [esp+4]
	ret_address_epilog_26B13D1E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_26B13D1E:
		mov edx, esp
		jmp edi
		ret
Sw3NtAcceptConnectPort ENDP

Sw3NtMapUserPhysicalPagesScatter PROC
		push ebp
		mov ebp, esp
		push 039A00711h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 039A00711h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_39A00711:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_39A00711
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_39A00711
		call do_sysenter_interrupt_39A00711
		lea esp, [esp+4]
	ret_address_epilog_39A00711:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_39A00711:
		mov edx, esp
		jmp edi
		ret
Sw3NtMapUserPhysicalPagesScatter ENDP

Sw3NtWaitForSingleObject PROC
		push ebp
		mov ebp, esp
		push 01AB45459h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01AB45459h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1AB45459:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1AB45459
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1AB45459
		call do_sysenter_interrupt_1AB45459
		lea esp, [esp+4]
	ret_address_epilog_1AB45459:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1AB45459:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForSingleObject ENDP

Sw3NtCallbackReturn PROC
		push ebp
		mov ebp, esp
		push 03AA018F4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03AA018F4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_3AA018F4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3AA018F4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3AA018F4
		call do_sysenter_interrupt_3AA018F4
		lea esp, [esp+4]
	ret_address_epilog_3AA018F4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3AA018F4:
		mov edx, esp
		jmp edi
		ret
Sw3NtCallbackReturn ENDP

Sw3NtReadFile PROC
		push ebp
		mov ebp, esp
		push 02285D3DFh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02285D3DFh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_2285D3DF:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2285D3DF
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2285D3DF
		call do_sysenter_interrupt_2285D3DF
		lea esp, [esp+4]
	ret_address_epilog_2285D3DF:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2285D3DF:
		mov edx, esp
		jmp edi
		ret
Sw3NtReadFile ENDP

Sw3NtDeviceIoControlFile PROC
		push ebp
		mov ebp, esp
		push 03CE62662h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03CE62662h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_3CE62662:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3CE62662
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3CE62662
		call do_sysenter_interrupt_3CE62662
		lea esp, [esp+4]
	ret_address_epilog_3CE62662:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3CE62662:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeviceIoControlFile ENDP

Sw3NtWriteFile PROC
		push ebp
		mov ebp, esp
		push 0203BBE0Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0203BBE0Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_203BBE0A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_203BBE0A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_203BBE0A
		call do_sysenter_interrupt_203BBE0A
		lea esp, [esp+4]
	ret_address_epilog_203BBE0A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_203BBE0A:
		mov edx, esp
		jmp edi
		ret
Sw3NtWriteFile ENDP

Sw3NtRemoveIoCompletion PROC
		push ebp
		mov ebp, esp
		push 014823411h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 014823411h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_14823411:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_14823411
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_14823411
		call do_sysenter_interrupt_14823411
		lea esp, [esp+4]
	ret_address_epilog_14823411:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_14823411:
		mov edx, esp
		jmp edi
		ret
Sw3NtRemoveIoCompletion ENDP

Sw3NtReleaseSemaphore PROC
		push ebp
		mov ebp, esp
		push 0D847F48Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D847F48Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_D847F48E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D847F48E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D847F48E
		call do_sysenter_interrupt_D847F48E
		lea esp, [esp+4]
	ret_address_epilog_D847F48E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D847F48E:
		mov edx, esp
		jmp edi
		ret
Sw3NtReleaseSemaphore ENDP

Sw3NtReplyWaitReceivePort PROC
		push ebp
		mov ebp, esp
		push 0A4F022E3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A4F022E3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_A4F022E3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A4F022E3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A4F022E3
		call do_sysenter_interrupt_A4F022E3
		lea esp, [esp+4]
	ret_address_epilog_A4F022E3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A4F022E3:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplyWaitReceivePort ENDP

Sw3NtReplyPort PROC
		push ebp
		mov ebp, esp
		push 05C38A756h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05C38A756h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_5C38A756:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5C38A756
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5C38A756
		call do_sysenter_interrupt_5C38A756
		lea esp, [esp+4]
	ret_address_epilog_5C38A756:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5C38A756:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplyPort ENDP

Sw3NtSetInformationThread PROC
		push ebp
		mov ebp, esp
		push 03E06FB3Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03E06FB3Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_3E06FB3F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3E06FB3F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3E06FB3F
		call do_sysenter_interrupt_3E06FB3F
		lea esp, [esp+4]
	ret_address_epilog_3E06FB3F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3E06FB3F:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationThread ENDP

Sw3NtSetEvent PROC
		push ebp
		mov ebp, esp
		push 06F534EE6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06F534EE6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_6F534EE6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6F534EE6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6F534EE6
		call do_sysenter_interrupt_6F534EE6
		lea esp, [esp+4]
	ret_address_epilog_6F534EE6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6F534EE6:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetEvent ENDP

Sw3NtClose PROC
		push ebp
		mov ebp, esp
		push 0D495D53Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D495D53Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_D495D53C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D495D53C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D495D53C
		call do_sysenter_interrupt_D495D53C
		lea esp, [esp+4]
	ret_address_epilog_D495D53C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D495D53C:
		mov edx, esp
		jmp edi
		ret
Sw3NtClose ENDP

Sw3NtQueryObject PROC
		push ebp
		mov ebp, esp
		push 012248724h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 012248724h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_12248724:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_12248724
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_12248724
		call do_sysenter_interrupt_12248724
		lea esp, [esp+4]
	ret_address_epilog_12248724:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_12248724:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryObject ENDP

Sw3NtQueryInformationFile PROC
		push ebp
		mov ebp, esp
		push 0E55C2FE9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E55C2FE9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_E55C2FE9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E55C2FE9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E55C2FE9
		call do_sysenter_interrupt_E55C2FE9
		lea esp, [esp+4]
	ret_address_epilog_E55C2FE9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E55C2FE9:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationFile ENDP

Sw3NtOpenKey PROC
		push ebp
		mov ebp, esp
		push 001142289h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 001142289h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_01142289:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_01142289
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_01142289
		call do_sysenter_interrupt_01142289
		lea esp, [esp+4]
	ret_address_epilog_01142289:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_01142289:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenKey ENDP

Sw3NtEnumerateValueKey PROC
		push ebp
		mov ebp, esp
		push 05DAD5A30h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05DAD5A30h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_5DAD5A30:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5DAD5A30
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5DAD5A30
		call do_sysenter_interrupt_5DAD5A30
		lea esp, [esp+4]
	ret_address_epilog_5DAD5A30:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5DAD5A30:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateValueKey ENDP

Sw3NtFindAtom PROC
		push ebp
		mov ebp, esp
		push 0D4B954A7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D4B954A7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_D4B954A7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D4B954A7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D4B954A7
		call do_sysenter_interrupt_D4B954A7
		lea esp, [esp+4]
	ret_address_epilog_D4B954A7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D4B954A7:
		mov edx, esp
		jmp edi
		ret
Sw3NtFindAtom ENDP

Sw3NtQueryDefaultLocale PROC
		push ebp
		mov ebp, esp
		push 0013E9405h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0013E9405h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_013E9405:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_013E9405
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_013E9405
		call do_sysenter_interrupt_013E9405
		lea esp, [esp+4]
	ret_address_epilog_013E9405:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_013E9405:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDefaultLocale ENDP

Sw3NtQueryKey PROC
		push ebp
		mov ebp, esp
		push 036EFCA98h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 036EFCA98h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_36EFCA98:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_36EFCA98
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_36EFCA98
		call do_sysenter_interrupt_36EFCA98
		lea esp, [esp+4]
	ret_address_epilog_36EFCA98:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_36EFCA98:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryKey ENDP

Sw3NtQueryValueKey PROC
		push ebp
		mov ebp, esp
		push 0D51FE8A8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D51FE8A8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_D51FE8A8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D51FE8A8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D51FE8A8
		call do_sysenter_interrupt_D51FE8A8
		lea esp, [esp+4]
	ret_address_epilog_D51FE8A8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D51FE8A8:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryValueKey ENDP

Sw3NtAllocateVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 01F890917h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01F890917h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_1F890917:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1F890917
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1F890917
		call do_sysenter_interrupt_1F890917
		lea esp, [esp+4]
	ret_address_epilog_1F890917:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1F890917:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateVirtualMemory ENDP

Sw3NtQueryInformationProcess PROC
		push ebp
		mov ebp, esp
		push 09D108090h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09D108090h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_9D108090:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9D108090
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9D108090
		call do_sysenter_interrupt_9D108090
		lea esp, [esp+4]
	ret_address_epilog_9D108090:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9D108090:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationProcess ENDP

Sw3NtWaitForMultipleObjects32 PROC
		push ebp
		mov ebp, esp
		push 0B29C100Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B29C100Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_B29C100C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B29C100C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B29C100C
		call do_sysenter_interrupt_B29C100C
		lea esp, [esp+4]
	ret_address_epilog_B29C100C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B29C100C:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForMultipleObjects32 ENDP

Sw3NtWriteFileGather PROC
		push ebp
		mov ebp, esp
		push 057C02D4Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 057C02D4Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_57C02D4D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_57C02D4D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_57C02D4D
		call do_sysenter_interrupt_57C02D4D
		lea esp, [esp+4]
	ret_address_epilog_57C02D4D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_57C02D4D:
		mov edx, esp
		jmp edi
		ret
Sw3NtWriteFileGather ENDP

Sw3NtCreateKey PROC
		push ebp
		mov ebp, esp
		push 0E912D2A0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E912D2A0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_E912D2A0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E912D2A0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E912D2A0
		call do_sysenter_interrupt_E912D2A0
		lea esp, [esp+4]
	ret_address_epilog_E912D2A0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E912D2A0:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateKey ENDP

Sw3NtFreeVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 001AC0D2Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 001AC0D2Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_01AC0D2B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_01AC0D2B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_01AC0D2B
		call do_sysenter_interrupt_01AC0D2B
		lea esp, [esp+4]
	ret_address_epilog_01AC0D2B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_01AC0D2B:
		mov edx, esp
		jmp edi
		ret
Sw3NtFreeVirtualMemory ENDP

Sw3NtImpersonateClientOfPort PROC
		push ebp
		mov ebp, esp
		push 02CB71778h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02CB71778h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_2CB71778:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2CB71778
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2CB71778
		call do_sysenter_interrupt_2CB71778
		lea esp, [esp+4]
	ret_address_epilog_2CB71778:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2CB71778:
		mov edx, esp
		jmp edi
		ret
Sw3NtImpersonateClientOfPort ENDP

Sw3NtReleaseMutant PROC
		push ebp
		mov ebp, esp
		push 0B731515Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B731515Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_B731515B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B731515B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B731515B
		call do_sysenter_interrupt_B731515B
		lea esp, [esp+4]
	ret_address_epilog_B731515B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B731515B:
		mov edx, esp
		jmp edi
		ret
Sw3NtReleaseMutant ENDP

Sw3NtQueryInformationToken PROC
		push ebp
		mov ebp, esp
		push 00D9EFF9Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00D9EFF9Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0D9EFF9A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0D9EFF9A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0D9EFF9A
		call do_sysenter_interrupt_0D9EFF9A
		lea esp, [esp+4]
	ret_address_epilog_0D9EFF9A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0D9EFF9A:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationToken ENDP

Sw3NtRequestWaitReplyPort PROC
		push ebp
		mov ebp, esp
		push 024B30B20h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 024B30B20h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_24B30B20:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_24B30B20
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_24B30B20
		call do_sysenter_interrupt_24B30B20
		lea esp, [esp+4]
	ret_address_epilog_24B30B20:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_24B30B20:
		mov edx, esp
		jmp edi
		ret
Sw3NtRequestWaitReplyPort ENDP

Sw3NtQueryVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 0FDAF09D3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FDAF09D3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_FDAF09D3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FDAF09D3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FDAF09D3
		call do_sysenter_interrupt_FDAF09D3
		lea esp, [esp+4]
	ret_address_epilog_FDAF09D3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FDAF09D3:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryVirtualMemory ENDP

Sw3NtOpenThreadToken PROC
		push ebp
		mov ebp, esp
		push 00FD77554h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00FD77554h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0FD77554:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0FD77554
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0FD77554
		call do_sysenter_interrupt_0FD77554
		lea esp, [esp+4]
	ret_address_epilog_0FD77554:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0FD77554:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenThreadToken ENDP

Sw3NtQueryInformationThread PROC
		push ebp
		mov ebp, esp
		push 0904C6265h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0904C6265h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_904C6265:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_904C6265
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_904C6265
		call do_sysenter_interrupt_904C6265
		lea esp, [esp+4]
	ret_address_epilog_904C6265:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_904C6265:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationThread ENDP

Sw3NtOpenProcess PROC
		push ebp
		mov ebp, esp
		push 0C636C5A7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C636C5A7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_C636C5A7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C636C5A7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C636C5A7
		call do_sysenter_interrupt_C636C5A7
		lea esp, [esp+4]
	ret_address_epilog_C636C5A7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C636C5A7:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenProcess ENDP

Sw3NtSetInformationFile PROC
		push ebp
		mov ebp, esp
		push 03A3CCE2Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03A3CCE2Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_3A3CCE2A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3A3CCE2A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3A3CCE2A
		call do_sysenter_interrupt_3A3CCE2A
		lea esp, [esp+4]
	ret_address_epilog_3A3CCE2A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3A3CCE2A:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationFile ENDP

Sw3NtMapViewOfSection PROC
		push ebp
		mov ebp, esp
		push 00EA56AB7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00EA56AB7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_0EA56AB7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0EA56AB7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0EA56AB7
		call do_sysenter_interrupt_0EA56AB7
		lea esp, [esp+4]
	ret_address_epilog_0EA56AB7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0EA56AB7:
		mov edx, esp
		jmp edi
		ret
Sw3NtMapViewOfSection ENDP

Sw3NtAccessCheckAndAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 018B7FBF8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 018B7FBF8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_18B7FBF8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_18B7FBF8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_18B7FBF8
		call do_sysenter_interrupt_18B7FBF8
		lea esp, [esp+4]
	ret_address_epilog_18B7FBF8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_18B7FBF8:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckAndAuditAlarm ENDP

Sw3NtUnmapViewOfSection PROC
		push ebp
		mov ebp, esp
		push 034AB3E37h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 034AB3E37h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_34AB3E37:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_34AB3E37
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_34AB3E37
		call do_sysenter_interrupt_34AB3E37
		lea esp, [esp+4]
	ret_address_epilog_34AB3E37:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_34AB3E37:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnmapViewOfSection ENDP

Sw3NtReplyWaitReceivePortEx PROC
		push ebp
		mov ebp, esp
		push 00E1258CCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00E1258CCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0E1258CC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0E1258CC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0E1258CC
		call do_sysenter_interrupt_0E1258CC
		lea esp, [esp+4]
	ret_address_epilog_0E1258CC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0E1258CC:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplyWaitReceivePortEx ENDP

Sw3NtTerminateProcess PROC
		push ebp
		mov ebp, esp
		push 049A54828h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 049A54828h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_49A54828:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_49A54828
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_49A54828
		call do_sysenter_interrupt_49A54828
		lea esp, [esp+4]
	ret_address_epilog_49A54828:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_49A54828:
		mov edx, esp
		jmp edi
		ret
Sw3NtTerminateProcess ENDP

Sw3NtSetEventBoostPriority PROC
		push ebp
		mov ebp, esp
		push 00C9A0418h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C9A0418h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_0C9A0418:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C9A0418
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C9A0418
		call do_sysenter_interrupt_0C9A0418
		lea esp, [esp+4]
	ret_address_epilog_0C9A0418:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C9A0418:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetEventBoostPriority ENDP

Sw3NtReadFileScatter PROC
		push ebp
		mov ebp, esp
		push 0018C0B15h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0018C0B15h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_018C0B15:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_018C0B15
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_018C0B15
		call do_sysenter_interrupt_018C0B15
		lea esp, [esp+4]
	ret_address_epilog_018C0B15:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_018C0B15:
		mov edx, esp
		jmp edi
		ret
Sw3NtReadFileScatter ENDP

Sw3NtOpenThreadTokenEx PROC
		push ebp
		mov ebp, esp
		push 0029D41A6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0029D41A6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_029D41A6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_029D41A6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_029D41A6
		call do_sysenter_interrupt_029D41A6
		lea esp, [esp+4]
	ret_address_epilog_029D41A6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_029D41A6:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenThreadTokenEx ENDP

Sw3NtOpenProcessTokenEx PROC
		push ebp
		mov ebp, esp
		push 07B9B455Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07B9B455Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_7B9B455E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7B9B455E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7B9B455E
		call do_sysenter_interrupt_7B9B455E
		lea esp, [esp+4]
	ret_address_epilog_7B9B455E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7B9B455E:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenProcessTokenEx ENDP

Sw3NtQueryPerformanceCounter PROC
		push ebp
		mov ebp, esp
		push 06FDA3D1Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06FDA3D1Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_6FDA3D1B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6FDA3D1B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6FDA3D1B
		call do_sysenter_interrupt_6FDA3D1B
		lea esp, [esp+4]
	ret_address_epilog_6FDA3D1B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6FDA3D1B:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryPerformanceCounter ENDP

Sw3NtEnumerateKey PROC
		push ebp
		mov ebp, esp
		push 0E53FFC9Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E53FFC9Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_E53FFC9C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E53FFC9C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E53FFC9C
		call do_sysenter_interrupt_E53FFC9C
		lea esp, [esp+4]
	ret_address_epilog_E53FFC9C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E53FFC9C:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateKey ENDP

Sw3NtOpenFile PROC
		push ebp
		mov ebp, esp
		push 0AAA4399Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AAA4399Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_AAA4399F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AAA4399F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AAA4399F
		call do_sysenter_interrupt_AAA4399F
		lea esp, [esp+4]
	ret_address_epilog_AAA4399F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AAA4399F:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenFile ENDP

Sw3NtDelayExecution PROC
		push ebp
		mov ebp, esp
		push 042CC0415h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 042CC0415h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_42CC0415:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_42CC0415
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_42CC0415
		call do_sysenter_interrupt_42CC0415
		lea esp, [esp+4]
	ret_address_epilog_42CC0415:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_42CC0415:
		mov edx, esp
		jmp edi
		ret
Sw3NtDelayExecution ENDP

Sw3NtQueryDirectoryFile PROC
		push ebp
		mov ebp, esp
		push 024B3B68Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 024B3B68Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_24B3B68B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_24B3B68B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_24B3B68B
		call do_sysenter_interrupt_24B3B68B
		lea esp, [esp+4]
	ret_address_epilog_24B3B68B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_24B3B68B:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDirectoryFile ENDP

Sw3NtQuerySystemInformation PROC
		push ebp
		mov ebp, esp
		push 004CC065Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 004CC065Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_04CC065D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_04CC065D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_04CC065D
		call do_sysenter_interrupt_04CC065D
		lea esp, [esp+4]
	ret_address_epilog_04CC065D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_04CC065D:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySystemInformation ENDP

Sw3NtOpenSection PROC
		push ebp
		mov ebp, esp
		push 0356F31FDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0356F31FDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_356F31FD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_356F31FD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_356F31FD
		call do_sysenter_interrupt_356F31FD
		lea esp, [esp+4]
	ret_address_epilog_356F31FD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_356F31FD:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenSection ENDP

Sw3NtQueryTimer PROC
		push ebp
		mov ebp, esp
		push 0086400F9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0086400F9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_086400F9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_086400F9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_086400F9
		call do_sysenter_interrupt_086400F9
		lea esp, [esp+4]
	ret_address_epilog_086400F9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_086400F9:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryTimer ENDP

Sw3NtFsControlFile PROC
		push ebp
		mov ebp, esp
		push 05FB9D499h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05FB9D499h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_5FB9D499:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5FB9D499
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5FB9D499
		call do_sysenter_interrupt_5FB9D499
		lea esp, [esp+4]
	ret_address_epilog_5FB9D499:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5FB9D499:
		mov edx, esp
		jmp edi
		ret
Sw3NtFsControlFile ENDP

Sw3NtWriteVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 0198D3F13h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0198D3F13h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_198D3F13:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_198D3F13
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_198D3F13
		call do_sysenter_interrupt_198D3F13
		lea esp, [esp+4]
	ret_address_epilog_198D3F13:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_198D3F13:
		mov edx, esp
		jmp edi
		ret
Sw3NtWriteVirtualMemory ENDP

Sw3NtCloseObjectAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 002A43E2Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 002A43E2Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_02A43E2A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_02A43E2A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_02A43E2A
		call do_sysenter_interrupt_02A43E2A
		lea esp, [esp+4]
	ret_address_epilog_02A43E2A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_02A43E2A:
		mov edx, esp
		jmp edi
		ret
Sw3NtCloseObjectAuditAlarm ENDP

Sw3NtDuplicateObject PROC
		push ebp
		mov ebp, esp
		push 02B18FD3Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02B18FD3Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_2B18FD3B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2B18FD3B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2B18FD3B
		call do_sysenter_interrupt_2B18FD3B
		lea esp, [esp+4]
	ret_address_epilog_2B18FD3B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2B18FD3B:
		mov edx, esp
		jmp edi
		ret
Sw3NtDuplicateObject ENDP

Sw3NtQueryAttributesFile PROC
		push ebp
		mov ebp, esp
		push 03AF8163Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03AF8163Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3AF8163E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3AF8163E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3AF8163E
		call do_sysenter_interrupt_3AF8163E
		lea esp, [esp+4]
	ret_address_epilog_3AF8163E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3AF8163E:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryAttributesFile ENDP

Sw3NtClearEvent PROC
		push ebp
		mov ebp, esp
		push 0EE8CF305h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0EE8CF305h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_EE8CF305:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_EE8CF305
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_EE8CF305
		call do_sysenter_interrupt_EE8CF305
		lea esp, [esp+4]
	ret_address_epilog_EE8CF305:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_EE8CF305:
		mov edx, esp
		jmp edi
		ret
Sw3NtClearEvent ENDP

Sw3NtReadVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 00D961905h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00D961905h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0D961905:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0D961905
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0D961905
		call do_sysenter_interrupt_0D961905
		lea esp, [esp+4]
	ret_address_epilog_0D961905:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0D961905:
		mov edx, esp
		jmp edi
		ret
Sw3NtReadVirtualMemory ENDP

Sw3NtOpenEvent PROC
		push ebp
		mov ebp, esp
		push 0390A189Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0390A189Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_390A189E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_390A189E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_390A189E
		call do_sysenter_interrupt_390A189E
		lea esp, [esp+4]
	ret_address_epilog_390A189E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_390A189E:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenEvent ENDP

Sw3NtAdjustPrivilegesToken PROC
		push ebp
		mov ebp, esp
		push 0E7BFE923h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E7BFE923h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_E7BFE923:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E7BFE923
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E7BFE923
		call do_sysenter_interrupt_E7BFE923
		lea esp, [esp+4]
	ret_address_epilog_E7BFE923:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E7BFE923:
		mov edx, esp
		jmp edi
		ret
Sw3NtAdjustPrivilegesToken ENDP

Sw3NtDuplicateToken PROC
		push ebp
		mov ebp, esp
		push 040592E9Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 040592E9Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_40592E9A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_40592E9A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_40592E9A
		call do_sysenter_interrupt_40592E9A
		lea esp, [esp+4]
	ret_address_epilog_40592E9A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_40592E9A:
		mov edx, esp
		jmp edi
		ret
Sw3NtDuplicateToken ENDP

Sw3NtContinue PROC
		push ebp
		mov ebp, esp
		push 0E6A6876Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E6A6876Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_E6A6876C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E6A6876C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E6A6876C
		call do_sysenter_interrupt_E6A6876C
		lea esp, [esp+4]
	ret_address_epilog_E6A6876C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E6A6876C:
		mov edx, esp
		jmp edi
		ret
Sw3NtContinue ENDP

Sw3NtQueryDefaultUILanguage PROC
		push ebp
		mov ebp, esp
		push 02DCF286Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02DCF286Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_2DCF286C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2DCF286C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2DCF286C
		call do_sysenter_interrupt_2DCF286C
		lea esp, [esp+4]
	ret_address_epilog_2DCF286C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2DCF286C:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDefaultUILanguage ENDP

Sw3NtQueueApcThread PROC
		push ebp
		mov ebp, esp
		push 038812A0Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 038812A0Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_38812A0F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_38812A0F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_38812A0F
		call do_sysenter_interrupt_38812A0F
		lea esp, [esp+4]
	ret_address_epilog_38812A0F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_38812A0F:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueueApcThread ENDP

Sw3NtYieldExecution PROC
		push ebp
		mov ebp, esp
		push 0C417E2C3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C417E2C3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_C417E2C3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C417E2C3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C417E2C3
		call do_sysenter_interrupt_C417E2C3
		lea esp, [esp+4]
	ret_address_epilog_C417E2C3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C417E2C3:
		mov edx, esp
		jmp edi
		ret
Sw3NtYieldExecution ENDP

Sw3NtAddAtom PROC
		push ebp
		mov ebp, esp
		push 044D1690Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 044D1690Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_44D1690C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_44D1690C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_44D1690C
		call do_sysenter_interrupt_44D1690C
		lea esp, [esp+4]
	ret_address_epilog_44D1690C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_44D1690C:
		mov edx, esp
		jmp edi
		ret
Sw3NtAddAtom ENDP

Sw3NtCreateEvent PROC
		push ebp
		mov ebp, esp
		push 08E0BB54Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08E0BB54Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_8E0BB54C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8E0BB54C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8E0BB54C
		call do_sysenter_interrupt_8E0BB54C
		lea esp, [esp+4]
	ret_address_epilog_8E0BB54C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8E0BB54C:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateEvent ENDP

Sw3NtQueryVolumeInformationFile PROC
		push ebp
		mov ebp, esp
		push 0E87E2058h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E87E2058h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_E87E2058:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E87E2058
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E87E2058
		call do_sysenter_interrupt_E87E2058
		lea esp, [esp+4]
	ret_address_epilog_E87E2058:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E87E2058:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryVolumeInformationFile ENDP

Sw3NtCreateSection PROC
		push ebp
		mov ebp, esp
		push 0DB10DB8Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DB10DB8Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_DB10DB8E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DB10DB8E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DB10DB8E
		call do_sysenter_interrupt_DB10DB8E
		lea esp, [esp+4]
	ret_address_epilog_DB10DB8E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DB10DB8E:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateSection ENDP

Sw3NtFlushBuffersFile PROC
		push ebp
		mov ebp, esp
		push 0FC77D2FCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FC77D2FCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_FC77D2FC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FC77D2FC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FC77D2FC
		call do_sysenter_interrupt_FC77D2FC
		lea esp, [esp+4]
	ret_address_epilog_FC77D2FC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FC77D2FC:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushBuffersFile ENDP

Sw3NtApphelpCacheControl PROC
		push ebp
		mov ebp, esp
		push 00A590EC1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00A590EC1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0A590EC1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0A590EC1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0A590EC1
		call do_sysenter_interrupt_0A590EC1
		lea esp, [esp+4]
	ret_address_epilog_0A590EC1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0A590EC1:
		mov edx, esp
		jmp edi
		ret
Sw3NtApphelpCacheControl ENDP

Sw3NtCreateProcessEx PROC
		push ebp
		mov ebp, esp
		push 0018DDCD9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0018DDCD9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_018DDCD9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_018DDCD9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_018DDCD9
		call do_sysenter_interrupt_018DDCD9
		lea esp, [esp+4]
	ret_address_epilog_018DDCD9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_018DDCD9:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateProcessEx ENDP

Sw3NtCreateThread PROC
		push ebp
		mov ebp, esp
		push 008A4C28Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 008A4C28Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_08A4C28A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_08A4C28A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_08A4C28A
		call do_sysenter_interrupt_08A4C28A
		lea esp, [esp+4]
	ret_address_epilog_08A4C28A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_08A4C28A:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateThread ENDP

Sw3NtIsProcessInJob PROC
		push ebp
		mov ebp, esp
		push 0DDA7BDA1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DDA7BDA1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_DDA7BDA1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DDA7BDA1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DDA7BDA1
		call do_sysenter_interrupt_DDA7BDA1
		lea esp, [esp+4]
	ret_address_epilog_DDA7BDA1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DDA7BDA1:
		mov edx, esp
		jmp edi
		ret
Sw3NtIsProcessInJob ENDP

Sw3NtProtectVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 006932E3Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 006932E3Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_06932E3C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_06932E3C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_06932E3C
		call do_sysenter_interrupt_06932E3C
		lea esp, [esp+4]
	ret_address_epilog_06932E3C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_06932E3C:
		mov edx, esp
		jmp edi
		ret
Sw3NtProtectVirtualMemory ENDP

Sw3NtQuerySection PROC
		push ebp
		mov ebp, esp
		push 002E9027Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 002E9027Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_02E9027B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_02E9027B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_02E9027B
		call do_sysenter_interrupt_02E9027B
		lea esp, [esp+4]
	ret_address_epilog_02E9027B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_02E9027B:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySection ENDP

Sw3NtResumeThread PROC
		push ebp
		mov ebp, esp
		push 06C4EBE7Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06C4EBE7Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_6C4EBE7F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6C4EBE7F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6C4EBE7F
		call do_sysenter_interrupt_6C4EBE7F
		lea esp, [esp+4]
	ret_address_epilog_6C4EBE7F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6C4EBE7F:
		mov edx, esp
		jmp edi
		ret
Sw3NtResumeThread ENDP

Sw3NtTerminateThread PROC
		push ebp
		mov ebp, esp
		push 056E22C5Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 056E22C5Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_56E22C5B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_56E22C5B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_56E22C5B
		call do_sysenter_interrupt_56E22C5B
		lea esp, [esp+4]
	ret_address_epilog_56E22C5B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_56E22C5B:
		mov edx, esp
		jmp edi
		ret
Sw3NtTerminateThread ENDP

Sw3NtReadRequestData PROC
		push ebp
		mov ebp, esp
		push 0934B7F07h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0934B7F07h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_934B7F07:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_934B7F07
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_934B7F07
		call do_sysenter_interrupt_934B7F07
		lea esp, [esp+4]
	ret_address_epilog_934B7F07:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_934B7F07:
		mov edx, esp
		jmp edi
		ret
Sw3NtReadRequestData ENDP

Sw3NtCreateFile PROC
		push ebp
		mov ebp, esp
		push 05EB57672h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05EB57672h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_5EB57672:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5EB57672
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5EB57672
		call do_sysenter_interrupt_5EB57672
		lea esp, [esp+4]
	ret_address_epilog_5EB57672:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5EB57672:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateFile ENDP

Sw3NtQueryEvent PROC
		push ebp
		mov ebp, esp
		push 0E0DA953Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E0DA953Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_E0DA953A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E0DA953A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E0DA953A
		call do_sysenter_interrupt_E0DA953A
		lea esp, [esp+4]
	ret_address_epilog_E0DA953A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E0DA953A:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryEvent ENDP

Sw3NtWriteRequestData PROC
		push ebp
		mov ebp, esp
		push 0A301D18Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A301D18Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_A301D18F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A301D18F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A301D18F
		call do_sysenter_interrupt_A301D18F
		lea esp, [esp+4]
	ret_address_epilog_A301D18F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A301D18F:
		mov edx, esp
		jmp edi
		ret
Sw3NtWriteRequestData ENDP

Sw3NtOpenDirectoryObject PROC
		push ebp
		mov ebp, esp
		push 09BB1A90Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09BB1A90Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_9BB1A90F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9BB1A90F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9BB1A90F
		call do_sysenter_interrupt_9BB1A90F
		lea esp, [esp+4]
	ret_address_epilog_9BB1A90F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9BB1A90F:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenDirectoryObject ENDP

Sw3NtAccessCheckByTypeAndAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 096919038h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 096919038h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 010h
	push_argument_96919038:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_96919038
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_96919038
		call do_sysenter_interrupt_96919038
		lea esp, [esp+4]
	ret_address_epilog_96919038:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_96919038:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckByTypeAndAuditAlarm ENDP

Sw3NtWaitForMultipleObjects PROC
		push ebp
		mov ebp, esp
		push 0AF3399AFh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AF3399AFh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_AF3399AF:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AF3399AF
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AF3399AF
		call do_sysenter_interrupt_AF3399AF
		lea esp, [esp+4]
	ret_address_epilog_AF3399AF:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AF3399AF:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForMultipleObjects ENDP

Sw3NtSetInformationObject PROC
		push ebp
		mov ebp, esp
		push 00E2176ADh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00E2176ADh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0E2176AD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0E2176AD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0E2176AD
		call do_sysenter_interrupt_0E2176AD
		lea esp, [esp+4]
	ret_address_epilog_0E2176AD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0E2176AD:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationObject ENDP

Sw3NtCancelIoFile PROC
		push ebp
		mov ebp, esp
		push 0D870D6E4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D870D6E4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_D870D6E4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D870D6E4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D870D6E4
		call do_sysenter_interrupt_D870D6E4
		lea esp, [esp+4]
	ret_address_epilog_D870D6E4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D870D6E4:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelIoFile ENDP

Sw3NtTraceEvent PROC
		push ebp
		mov ebp, esp
		push 0F84A1E11h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F84A1E11h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_F84A1E11:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F84A1E11
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F84A1E11
		call do_sysenter_interrupt_F84A1E11
		lea esp, [esp+4]
	ret_address_epilog_F84A1E11:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F84A1E11:
		mov edx, esp
		jmp edi
		ret
Sw3NtTraceEvent ENDP

Sw3NtPowerInformation PROC
		push ebp
		mov ebp, esp
		push 01BB1633Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01BB1633Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_1BB1633C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1BB1633C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1BB1633C
		call do_sysenter_interrupt_1BB1633C
		lea esp, [esp+4]
	ret_address_epilog_1BB1633C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1BB1633C:
		mov edx, esp
		jmp edi
		ret
Sw3NtPowerInformation ENDP

Sw3NtSetValueKey PROC
		push ebp
		mov ebp, esp
		push 02E1A51E1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02E1A51E1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_2E1A51E1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2E1A51E1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2E1A51E1
		call do_sysenter_interrupt_2E1A51E1
		lea esp, [esp+4]
	ret_address_epilog_2E1A51E1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2E1A51E1:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetValueKey ENDP

Sw3NtCancelTimer PROC
		push ebp
		mov ebp, esp
		push 0FC4FA465h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FC4FA465h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_FC4FA465:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FC4FA465
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FC4FA465
		call do_sysenter_interrupt_FC4FA465
		lea esp, [esp+4]
	ret_address_epilog_FC4FA465:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FC4FA465:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelTimer ENDP

Sw3NtSetTimer PROC
		push ebp
		mov ebp, esp
		push 09382698Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09382698Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_9382698A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9382698A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9382698A
		call do_sysenter_interrupt_9382698A
		lea esp, [esp+4]
	ret_address_epilog_9382698A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9382698A:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetTimer ENDP

Sw3NtAccessCheckByType PROC
		push ebp
		mov ebp, esp
		push 05CDB22C2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05CDB22C2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_5CDB22C2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5CDB22C2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5CDB22C2
		call do_sysenter_interrupt_5CDB22C2
		lea esp, [esp+4]
	ret_address_epilog_5CDB22C2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5CDB22C2:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckByType ENDP

Sw3NtAccessCheckByTypeResultList PROC
		push ebp
		mov ebp, esp
		push 02D72CA61h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02D72CA61h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_2D72CA61:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2D72CA61
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2D72CA61
		call do_sysenter_interrupt_2D72CA61
		lea esp, [esp+4]
	ret_address_epilog_2D72CA61:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2D72CA61:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckByTypeResultList ENDP

Sw3NtAccessCheckByTypeResultListAndAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 076BAA514h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 076BAA514h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 010h
	push_argument_76BAA514:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_76BAA514
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_76BAA514
		call do_sysenter_interrupt_76BAA514
		lea esp, [esp+4]
	ret_address_epilog_76BAA514:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_76BAA514:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckByTypeResultListAndAuditAlarm ENDP

Sw3NtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
		push ebp
		mov ebp, esp
		push 049D47F46h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 049D47F46h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 011h
	push_argument_49D47F46:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_49D47F46
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_49D47F46
		call do_sysenter_interrupt_49D47F46
		lea esp, [esp+4]
	ret_address_epilog_49D47F46:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_49D47F46:
		mov edx, esp
		jmp edi
		ret
Sw3NtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP

Sw3NtAcquireProcessActivityReference PROC
		push ebp
		mov ebp, esp
		push 0F54CF3D1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F54CF3D1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_F54CF3D1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F54CF3D1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F54CF3D1
		call do_sysenter_interrupt_F54CF3D1
		lea esp, [esp+4]
	ret_address_epilog_F54CF3D1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F54CF3D1:
		mov edx, esp
		jmp edi
		ret
Sw3NtAcquireProcessActivityReference ENDP

Sw3NtAddAtomEx PROC
		push ebp
		mov ebp, esp
		push 02DDCF980h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02DDCF980h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_2DDCF980:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2DDCF980
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2DDCF980
		call do_sysenter_interrupt_2DDCF980
		lea esp, [esp+4]
	ret_address_epilog_2DDCF980:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2DDCF980:
		mov edx, esp
		jmp edi
		ret
Sw3NtAddAtomEx ENDP

Sw3NtAddBootEntry PROC
		push ebp
		mov ebp, esp
		push 0E468ECE7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E468ECE7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_E468ECE7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E468ECE7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E468ECE7
		call do_sysenter_interrupt_E468ECE7
		lea esp, [esp+4]
	ret_address_epilog_E468ECE7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E468ECE7:
		mov edx, esp
		jmp edi
		ret
Sw3NtAddBootEntry ENDP

Sw3NtAddDriverEntry PROC
		push ebp
		mov ebp, esp
		push 04791712Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 04791712Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_4791712E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_4791712E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_4791712E
		call do_sysenter_interrupt_4791712E
		lea esp, [esp+4]
	ret_address_epilog_4791712E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_4791712E:
		mov edx, esp
		jmp edi
		ret
Sw3NtAddDriverEntry ENDP

Sw3NtAdjustGroupsToken PROC
		push ebp
		mov ebp, esp
		push 053965D76h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 053965D76h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_53965D76:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_53965D76
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_53965D76
		call do_sysenter_interrupt_53965D76
		lea esp, [esp+4]
	ret_address_epilog_53965D76:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_53965D76:
		mov edx, esp
		jmp edi
		ret
Sw3NtAdjustGroupsToken ENDP

Sw3NtAdjustTokenClaimsAndDeviceGroups PROC
		push ebp
		mov ebp, esp
		push 01B873517h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01B873517h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 010h
	push_argument_1B873517:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1B873517
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1B873517
		call do_sysenter_interrupt_1B873517
		lea esp, [esp+4]
	ret_address_epilog_1B873517:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1B873517:
		mov edx, esp
		jmp edi
		ret
Sw3NtAdjustTokenClaimsAndDeviceGroups ENDP

Sw3NtAlertResumeThread PROC
		push ebp
		mov ebp, esp
		push 0B417FEB9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B417FEB9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_B417FEB9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B417FEB9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B417FEB9
		call do_sysenter_interrupt_B417FEB9
		lea esp, [esp+4]
	ret_address_epilog_B417FEB9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B417FEB9:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlertResumeThread ENDP

Sw3NtAlertThread PROC
		push ebp
		mov ebp, esp
		push 00C56C6F8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C56C6F8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_0C56C6F8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C56C6F8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C56C6F8
		call do_sysenter_interrupt_0C56C6F8
		lea esp, [esp+4]
	ret_address_epilog_0C56C6F8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C56C6F8:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlertThread ENDP

Sw3NtAlertThreadByThreadId PROC
		push ebp
		mov ebp, esp
		push 0093325B3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0093325B3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_093325B3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_093325B3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_093325B3
		call do_sysenter_interrupt_093325B3
		lea esp, [esp+4]
	ret_address_epilog_093325B3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_093325B3:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlertThreadByThreadId ENDP

Sw3NtAllocateLocallyUniqueId PROC
		push ebp
		mov ebp, esp
		push 09C491F77h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09C491F77h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_9C491F77:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9C491F77
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9C491F77
		call do_sysenter_interrupt_9C491F77
		lea esp, [esp+4]
	ret_address_epilog_9C491F77:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9C491F77:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateLocallyUniqueId ENDP

Sw3NtAllocateReserveObject PROC
		push ebp
		mov ebp, esp
		push 0785718CBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0785718CBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_785718CB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_785718CB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_785718CB
		call do_sysenter_interrupt_785718CB
		lea esp, [esp+4]
	ret_address_epilog_785718CB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_785718CB:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateReserveObject ENDP

Sw3NtAllocateUserPhysicalPages PROC
		push ebp
		mov ebp, esp
		push 009902E20h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 009902E20h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_09902E20:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_09902E20
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_09902E20
		call do_sysenter_interrupt_09902E20
		lea esp, [esp+4]
	ret_address_epilog_09902E20:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_09902E20:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateUserPhysicalPages ENDP

Sw3NtAllocateUuids PROC
		push ebp
		mov ebp, esp
		push 07514A448h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07514A448h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_7514A448:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7514A448
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7514A448
		call do_sysenter_interrupt_7514A448
		lea esp, [esp+4]
	ret_address_epilog_7514A448:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7514A448:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateUuids ENDP

Sw3NtAllocateVirtualMemoryEx PROC
		push ebp
		mov ebp, esp
		push 0189E7A75h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0189E7A75h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_189E7A75:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_189E7A75
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_189E7A75
		call do_sysenter_interrupt_189E7A75
		lea esp, [esp+4]
	ret_address_epilog_189E7A75:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_189E7A75:
		mov edx, esp
		jmp edi
		ret
Sw3NtAllocateVirtualMemoryEx ENDP

Sw3NtAlpcAcceptConnectPort PROC
		push ebp
		mov ebp, esp
		push 06EF57F78h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06EF57F78h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_6EF57F78:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6EF57F78
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6EF57F78
		call do_sysenter_interrupt_6EF57F78
		lea esp, [esp+4]
	ret_address_epilog_6EF57F78:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6EF57F78:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcAcceptConnectPort ENDP

Sw3NtAlpcCancelMessage PROC
		push ebp
		mov ebp, esp
		push 0138E2016h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0138E2016h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_138E2016:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_138E2016
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_138E2016
		call do_sysenter_interrupt_138E2016
		lea esp, [esp+4]
	ret_address_epilog_138E2016:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_138E2016:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCancelMessage ENDP

Sw3NtAlpcConnectPort PROC
		push ebp
		mov ebp, esp
		push 066F15D5Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 066F15D5Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_66F15D5E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_66F15D5E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_66F15D5E
		call do_sysenter_interrupt_66F15D5E
		lea esp, [esp+4]
	ret_address_epilog_66F15D5E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_66F15D5E:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcConnectPort ENDP

Sw3NtAlpcConnectPortEx PROC
		push ebp
		mov ebp, esp
		push 023AEFFFAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 023AEFFFAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_23AEFFFA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_23AEFFFA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_23AEFFFA
		call do_sysenter_interrupt_23AEFFFA
		lea esp, [esp+4]
	ret_address_epilog_23AEFFFA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_23AEFFFA:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcConnectPortEx ENDP

Sw3NtAlpcCreatePort PROC
		push ebp
		mov ebp, esp
		push 0914E96DDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0914E96DDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_914E96DD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_914E96DD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_914E96DD
		call do_sysenter_interrupt_914E96DD
		lea esp, [esp+4]
	ret_address_epilog_914E96DD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_914E96DD:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCreatePort ENDP

Sw3NtAlpcCreatePortSection PROC
		push ebp
		mov ebp, esp
		push 0BF04D386h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BF04D386h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_BF04D386:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BF04D386
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BF04D386
		call do_sysenter_interrupt_BF04D386
		lea esp, [esp+4]
	ret_address_epilog_BF04D386:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BF04D386:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCreatePortSection ENDP

Sw3NtAlpcCreateResourceReserve PROC
		push ebp
		mov ebp, esp
		push 0F2AFBA82h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F2AFBA82h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_F2AFBA82:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F2AFBA82
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F2AFBA82
		call do_sysenter_interrupt_F2AFBA82
		lea esp, [esp+4]
	ret_address_epilog_F2AFBA82:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F2AFBA82:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCreateResourceReserve ENDP

Sw3NtAlpcCreateSectionView PROC
		push ebp
		mov ebp, esp
		push 0DB46EEF8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DB46EEF8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_DB46EEF8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DB46EEF8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DB46EEF8
		call do_sysenter_interrupt_DB46EEF8
		lea esp, [esp+4]
	ret_address_epilog_DB46EEF8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DB46EEF8:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCreateSectionView ENDP

Sw3NtAlpcCreateSecurityContext PROC
		push ebp
		mov ebp, esp
		push 0FE67E3F6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FE67E3F6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_FE67E3F6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FE67E3F6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FE67E3F6
		call do_sysenter_interrupt_FE67E3F6
		lea esp, [esp+4]
	ret_address_epilog_FE67E3F6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FE67E3F6:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcCreateSecurityContext ENDP

Sw3NtAlpcDeletePortSection PROC
		push ebp
		mov ebp, esp
		push 01A2EFD76h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01A2EFD76h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1A2EFD76:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1A2EFD76
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1A2EFD76
		call do_sysenter_interrupt_1A2EFD76
		lea esp, [esp+4]
	ret_address_epilog_1A2EFD76:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1A2EFD76:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcDeletePortSection ENDP

Sw3NtAlpcDeleteResourceReserve PROC
		push ebp
		mov ebp, esp
		push 0632C876Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0632C876Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_632C876D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_632C876D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_632C876D
		call do_sysenter_interrupt_632C876D
		lea esp, [esp+4]
	ret_address_epilog_632C876D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_632C876D:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcDeleteResourceReserve ENDP

Sw3NtAlpcDeleteSectionView PROC
		push ebp
		mov ebp, esp
		push 0173172ACh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0173172ACh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_173172AC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_173172AC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_173172AC
		call do_sysenter_interrupt_173172AC
		lea esp, [esp+4]
	ret_address_epilog_173172AC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_173172AC:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcDeleteSectionView ENDP

Sw3NtAlpcDeleteSecurityContext PROC
		push ebp
		mov ebp, esp
		push 03772D223h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03772D223h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_3772D223:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3772D223
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3772D223
		call do_sysenter_interrupt_3772D223
		lea esp, [esp+4]
	ret_address_epilog_3772D223:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3772D223:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcDeleteSecurityContext ENDP

Sw3NtAlpcDisconnectPort PROC
		push ebp
		mov ebp, esp
		push 063317C9Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 063317C9Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_63317C9A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_63317C9A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_63317C9A
		call do_sysenter_interrupt_63317C9A
		lea esp, [esp+4]
	ret_address_epilog_63317C9A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_63317C9A:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcDisconnectPort ENDP

Sw3NtAlpcImpersonateClientContainerOfPort PROC
		push ebp
		mov ebp, esp
		push 078F2797Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 078F2797Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_78F2797C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_78F2797C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_78F2797C
		call do_sysenter_interrupt_78F2797C
		lea esp, [esp+4]
	ret_address_epilog_78F2797C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_78F2797C:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcImpersonateClientContainerOfPort ENDP

Sw3NtAlpcImpersonateClientOfPort PROC
		push ebp
		mov ebp, esp
		push 0E57FC4D1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E57FC4D1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_E57FC4D1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E57FC4D1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E57FC4D1
		call do_sysenter_interrupt_E57FC4D1
		lea esp, [esp+4]
	ret_address_epilog_E57FC4D1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E57FC4D1:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcImpersonateClientOfPort ENDP

Sw3NtAlpcOpenSenderProcess PROC
		push ebp
		mov ebp, esp
		push 076B70D3Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 076B70D3Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_76B70D3B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_76B70D3B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_76B70D3B
		call do_sysenter_interrupt_76B70D3B
		lea esp, [esp+4]
	ret_address_epilog_76B70D3B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_76B70D3B:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcOpenSenderProcess ENDP

Sw3NtAlpcOpenSenderThread PROC
		push ebp
		mov ebp, esp
		push 0FD59BDFDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FD59BDFDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_FD59BDFD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FD59BDFD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FD59BDFD
		call do_sysenter_interrupt_FD59BDFD
		lea esp, [esp+4]
	ret_address_epilog_FD59BDFD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FD59BDFD:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcOpenSenderThread ENDP

Sw3NtAlpcQueryInformation PROC
		push ebp
		mov ebp, esp
		push 00F92EAC0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00F92EAC0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0F92EAC0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0F92EAC0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0F92EAC0
		call do_sysenter_interrupt_0F92EAC0
		lea esp, [esp+4]
	ret_address_epilog_0F92EAC0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0F92EAC0:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcQueryInformation ENDP

Sw3NtAlpcQueryInformationMessage PROC
		push ebp
		mov ebp, esp
		push 06FCB5E10h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06FCB5E10h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_6FCB5E10:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6FCB5E10
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6FCB5E10
		call do_sysenter_interrupt_6FCB5E10
		lea esp, [esp+4]
	ret_address_epilog_6FCB5E10:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6FCB5E10:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcQueryInformationMessage ENDP

Sw3NtAlpcRevokeSecurityContext PROC
		push ebp
		mov ebp, esp
		push 0568A4902h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0568A4902h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_568A4902:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_568A4902
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_568A4902
		call do_sysenter_interrupt_568A4902
		lea esp, [esp+4]
	ret_address_epilog_568A4902:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_568A4902:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcRevokeSecurityContext ENDP

Sw3NtAlpcSendWaitReceivePort PROC
		push ebp
		mov ebp, esp
		push 03CB1C5BCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03CB1C5BCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_3CB1C5BC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3CB1C5BC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3CB1C5BC
		call do_sysenter_interrupt_3CB1C5BC
		lea esp, [esp+4]
	ret_address_epilog_3CB1C5BC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3CB1C5BC:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcSendWaitReceivePort ENDP

Sw3NtAlpcSetInformation PROC
		push ebp
		mov ebp, esp
		push 0029B2007h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0029B2007h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_029B2007:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_029B2007
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_029B2007
		call do_sysenter_interrupt_029B2007
		lea esp, [esp+4]
	ret_address_epilog_029B2007:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_029B2007:
		mov edx, esp
		jmp edi
		ret
Sw3NtAlpcSetInformation ENDP

Sw3NtAreMappedFilesTheSame PROC
		push ebp
		mov ebp, esp
		push 0DE223565h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DE223565h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_DE223565:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DE223565
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DE223565
		call do_sysenter_interrupt_DE223565
		lea esp, [esp+4]
	ret_address_epilog_DE223565:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DE223565:
		mov edx, esp
		jmp edi
		ret
Sw3NtAreMappedFilesTheSame ENDP

Sw3NtAssignProcessToJobObject PROC
		push ebp
		mov ebp, esp
		push 0E834EAA9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E834EAA9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_E834EAA9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E834EAA9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E834EAA9
		call do_sysenter_interrupt_E834EAA9
		lea esp, [esp+4]
	ret_address_epilog_E834EAA9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E834EAA9:
		mov edx, esp
		jmp edi
		ret
Sw3NtAssignProcessToJobObject ENDP

Sw3NtAssociateWaitCompletionPacket PROC
		push ebp
		mov ebp, esp
		push 0179D26D0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0179D26D0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_179D26D0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_179D26D0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_179D26D0
		call do_sysenter_interrupt_179D26D0
		lea esp, [esp+4]
	ret_address_epilog_179D26D0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_179D26D0:
		mov edx, esp
		jmp edi
		ret
Sw3NtAssociateWaitCompletionPacket ENDP

Sw3NtCallEnclave PROC
		push ebp
		mov ebp, esp
		push 012B03800h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 012B03800h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_12B03800:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_12B03800
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_12B03800
		call do_sysenter_interrupt_12B03800
		lea esp, [esp+4]
	ret_address_epilog_12B03800:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_12B03800:
		mov edx, esp
		jmp edi
		ret
Sw3NtCallEnclave ENDP

Sw3NtCancelIoFileEx PROC
		push ebp
		mov ebp, esp
		push 08E9450C3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08E9450C3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_8E9450C3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8E9450C3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8E9450C3
		call do_sysenter_interrupt_8E9450C3
		lea esp, [esp+4]
	ret_address_epilog_8E9450C3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8E9450C3:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelIoFileEx ENDP

Sw3NtCancelSynchronousIoFile PROC
		push ebp
		mov ebp, esp
		push 03F9CF1BAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03F9CF1BAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_3F9CF1BA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3F9CF1BA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3F9CF1BA
		call do_sysenter_interrupt_3F9CF1BA
		lea esp, [esp+4]
	ret_address_epilog_3F9CF1BA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3F9CF1BA:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelSynchronousIoFile ENDP

Sw3NtCancelTimer2 PROC
		push ebp
		mov ebp, esp
		push 099B3866Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 099B3866Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_99B3866D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_99B3866D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_99B3866D
		call do_sysenter_interrupt_99B3866D
		lea esp, [esp+4]
	ret_address_epilog_99B3866D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_99B3866D:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelTimer2 ENDP

Sw3NtCancelWaitCompletionPacket PROC
		push ebp
		mov ebp, esp
		push 0359B0130h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0359B0130h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_359B0130:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_359B0130
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_359B0130
		call do_sysenter_interrupt_359B0130
		lea esp, [esp+4]
	ret_address_epilog_359B0130:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_359B0130:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelWaitCompletionPacket ENDP

Sw3NtCommitComplete PROC
		push ebp
		mov ebp, esp
		push 0CE029ABCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CE029ABCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_CE029ABC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CE029ABC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CE029ABC
		call do_sysenter_interrupt_CE029ABC
		lea esp, [esp+4]
	ret_address_epilog_CE029ABC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CE029ABC:
		mov edx, esp
		jmp edi
		ret
Sw3NtCommitComplete ENDP

Sw3NtCommitEnlistment PROC
		push ebp
		mov ebp, esp
		push 06B264A7Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06B264A7Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_6B264A7B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6B264A7B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6B264A7B
		call do_sysenter_interrupt_6B264A7B
		lea esp, [esp+4]
	ret_address_epilog_6B264A7B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6B264A7B:
		mov edx, esp
		jmp edi
		ret
Sw3NtCommitEnlistment ENDP

Sw3NtCommitRegistryTransaction PROC
		push ebp
		mov ebp, esp
		push 0414A45DDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0414A45DDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_414A45DD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_414A45DD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_414A45DD
		call do_sysenter_interrupt_414A45DD
		lea esp, [esp+4]
	ret_address_epilog_414A45DD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_414A45DD:
		mov edx, esp
		jmp edi
		ret
Sw3NtCommitRegistryTransaction ENDP

Sw3NtCommitTransaction PROC
		push ebp
		mov ebp, esp
		push 0C348FFEAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C348FFEAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_C348FFEA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C348FFEA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C348FFEA
		call do_sysenter_interrupt_C348FFEA
		lea esp, [esp+4]
	ret_address_epilog_C348FFEA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C348FFEA:
		mov edx, esp
		jmp edi
		ret
Sw3NtCommitTransaction ENDP

Sw3NtCompactKeys PROC
		push ebp
		mov ebp, esp
		push 0B2D2BB65h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B2D2BB65h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_B2D2BB65:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B2D2BB65
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B2D2BB65
		call do_sysenter_interrupt_B2D2BB65
		lea esp, [esp+4]
	ret_address_epilog_B2D2BB65:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B2D2BB65:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompactKeys ENDP

Sw3NtCompareObjects PROC
		push ebp
		mov ebp, esp
		push 023A83701h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 023A83701h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_23A83701:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_23A83701
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_23A83701
		call do_sysenter_interrupt_23A83701
		lea esp, [esp+4]
	ret_address_epilog_23A83701:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_23A83701:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompareObjects ENDP

Sw3NtCompareSigningLevels PROC
		push ebp
		mov ebp, esp
		push 060DC2008h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 060DC2008h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_60DC2008:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_60DC2008
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_60DC2008
		call do_sysenter_interrupt_60DC2008
		lea esp, [esp+4]
	ret_address_epilog_60DC2008:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_60DC2008:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompareSigningLevels ENDP

Sw3NtCompareTokens PROC
		push ebp
		mov ebp, esp
		push 06CB7085Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06CB7085Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_6CB7085E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6CB7085E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6CB7085E
		call do_sysenter_interrupt_6CB7085E
		lea esp, [esp+4]
	ret_address_epilog_6CB7085E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6CB7085E:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompareTokens ENDP

Sw3NtCompleteConnectPort PROC
		push ebp
		mov ebp, esp
		push 06531805Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06531805Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_6531805B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6531805B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6531805B
		call do_sysenter_interrupt_6531805B
		lea esp, [esp+4]
	ret_address_epilog_6531805B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6531805B:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompleteConnectPort ENDP

Sw3NtCompressKey PROC
		push ebp
		mov ebp, esp
		push 0F84DE3DDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F84DE3DDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_F84DE3DD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F84DE3DD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F84DE3DD
		call do_sysenter_interrupt_F84DE3DD
		lea esp, [esp+4]
	ret_address_epilog_F84DE3DD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F84DE3DD:
		mov edx, esp
		jmp edi
		ret
Sw3NtCompressKey ENDP

Sw3NtConnectPort PROC
		push ebp
		mov ebp, esp
		push 020BF1F7Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 020BF1F7Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_20BF1F7C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_20BF1F7C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_20BF1F7C
		call do_sysenter_interrupt_20BF1F7C
		lea esp, [esp+4]
	ret_address_epilog_20BF1F7C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_20BF1F7C:
		mov edx, esp
		jmp edi
		ret
Sw3NtConnectPort ENDP

Sw3NtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
		push ebp
		mov ebp, esp
		push 00D85D5CFh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00D85D5CFh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0D85D5CF:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0D85D5CF
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0D85D5CF
		call do_sysenter_interrupt_0D85D5CF
		lea esp, [esp+4]
	ret_address_epilog_0D85D5CF:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0D85D5CF:
		mov edx, esp
		jmp edi
		ret
Sw3NtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP

Sw3NtCreateDebugObject PROC
		push ebp
		mov ebp, esp
		push 0AF08BD96h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AF08BD96h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_AF08BD96:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AF08BD96
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AF08BD96
		call do_sysenter_interrupt_AF08BD96
		lea esp, [esp+4]
	ret_address_epilog_AF08BD96:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AF08BD96:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateDebugObject ENDP

Sw3NtCreateDirectoryObject PROC
		push ebp
		mov ebp, esp
		push 0DAEB26EBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DAEB26EBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_DAEB26EB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DAEB26EB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DAEB26EB
		call do_sysenter_interrupt_DAEB26EB
		lea esp, [esp+4]
	ret_address_epilog_DAEB26EB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DAEB26EB:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateDirectoryObject ENDP

Sw3NtCreateDirectoryObjectEx PROC
		push ebp
		mov ebp, esp
		push 0FC01B530h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FC01B530h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_FC01B530:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FC01B530
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FC01B530
		call do_sysenter_interrupt_FC01B530
		lea esp, [esp+4]
	ret_address_epilog_FC01B530:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FC01B530:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateDirectoryObjectEx ENDP

Sw3NtCreateEnclave PROC
		push ebp
		mov ebp, esp
		push 05E902C58h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05E902C58h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_5E902C58:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5E902C58
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5E902C58
		call do_sysenter_interrupt_5E902C58
		lea esp, [esp+4]
	ret_address_epilog_5E902C58:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5E902C58:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateEnclave ENDP

Sw3NtCreateEnlistment PROC
		push ebp
		mov ebp, esp
		push 051D7141Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 051D7141Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_51D7141D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_51D7141D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_51D7141D
		call do_sysenter_interrupt_51D7141D
		lea esp, [esp+4]
	ret_address_epilog_51D7141D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_51D7141D:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateEnlistment ENDP

Sw3NtCreateEventPair PROC
		push ebp
		mov ebp, esp
		push 03790A697h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03790A697h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_3790A697:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3790A697
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3790A697
		call do_sysenter_interrupt_3790A697
		lea esp, [esp+4]
	ret_address_epilog_3790A697:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3790A697:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateEventPair ENDP

Sw3NtCreateIRTimer PROC
		push ebp
		mov ebp, esp
		push 0CD962FC6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CD962FC6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_CD962FC6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CD962FC6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CD962FC6
		call do_sysenter_interrupt_CD962FC6
		lea esp, [esp+4]
	ret_address_epilog_CD962FC6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CD962FC6:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateIRTimer ENDP

Sw3NtCreateIoCompletion PROC
		push ebp
		mov ebp, esp
		push 040297E85h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 040297E85h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_40297E85:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_40297E85
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_40297E85
		call do_sysenter_interrupt_40297E85
		lea esp, [esp+4]
	ret_address_epilog_40297E85:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_40297E85:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateIoCompletion ENDP

Sw3NtCreateJobObject PROC
		push ebp
		mov ebp, esp
		push 034A14C55h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 034A14C55h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_34A14C55:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_34A14C55
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_34A14C55
		call do_sysenter_interrupt_34A14C55
		lea esp, [esp+4]
	ret_address_epilog_34A14C55:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_34A14C55:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateJobObject ENDP

Sw3NtCreateJobSet PROC
		push ebp
		mov ebp, esp
		push 0F35FD9E2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F35FD9E2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_F35FD9E2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F35FD9E2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F35FD9E2
		call do_sysenter_interrupt_F35FD9E2
		lea esp, [esp+4]
	ret_address_epilog_F35FD9E2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F35FD9E2:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateJobSet ENDP

Sw3NtCreateKeyTransacted PROC
		push ebp
		mov ebp, esp
		push 0BC9F24A2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BC9F24A2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_BC9F24A2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BC9F24A2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BC9F24A2
		call do_sysenter_interrupt_BC9F24A2
		lea esp, [esp+4]
	ret_address_epilog_BC9F24A2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BC9F24A2:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateKeyTransacted ENDP

Sw3NtCreateKeyedEvent PROC
		push ebp
		mov ebp, esp
		push 004AC2CF8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 004AC2CF8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_04AC2CF8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_04AC2CF8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_04AC2CF8
		call do_sysenter_interrupt_04AC2CF8
		lea esp, [esp+4]
	ret_address_epilog_04AC2CF8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_04AC2CF8:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateKeyedEvent ENDP

Sw3NtCreateLowBoxToken PROC
		push ebp
		mov ebp, esp
		push 0AC4DF4E7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AC4DF4E7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_AC4DF4E7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AC4DF4E7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AC4DF4E7
		call do_sysenter_interrupt_AC4DF4E7
		lea esp, [esp+4]
	ret_address_epilog_AC4DF4E7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AC4DF4E7:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateLowBoxToken ENDP

Sw3NtCreateMailslotFile PROC
		push ebp
		mov ebp, esp
		push 0DEC9A4DEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DEC9A4DEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_DEC9A4DE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DEC9A4DE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DEC9A4DE
		call do_sysenter_interrupt_DEC9A4DE
		lea esp, [esp+4]
	ret_address_epilog_DEC9A4DE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DEC9A4DE:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateMailslotFile ENDP

Sw3NtCreateMutant PROC
		push ebp
		mov ebp, esp
		push 034965906h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 034965906h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_34965906:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_34965906
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_34965906
		call do_sysenter_interrupt_34965906
		lea esp, [esp+4]
	ret_address_epilog_34965906:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_34965906:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateMutant ENDP

Sw3NtCreateNamedPipeFile PROC
		push ebp
		mov ebp, esp
		push 01E99E88Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01E99E88Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0eh
	push_argument_1E99E88A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1E99E88A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1E99E88A
		call do_sysenter_interrupt_1E99E88A
		lea esp, [esp+4]
	ret_address_epilog_1E99E88A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1E99E88A:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateNamedPipeFile ENDP

Sw3NtCreatePagingFile PROC
		push ebp
		mov ebp, esp
		push 029B32153h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 029B32153h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_29B32153:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_29B32153
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_29B32153
		call do_sysenter_interrupt_29B32153
		lea esp, [esp+4]
	ret_address_epilog_29B32153:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_29B32153:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreatePagingFile ENDP

Sw3NtCreatePartition PROC
		push ebp
		mov ebp, esp
		push 0062DC67Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0062DC67Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_062DC67F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_062DC67F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_062DC67F
		call do_sysenter_interrupt_062DC67F
		lea esp, [esp+4]
	ret_address_epilog_062DC67F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_062DC67F:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreatePartition ENDP

Sw3NtCreatePort PROC
		push ebp
		mov ebp, esp
		push 06AF75534h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06AF75534h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_6AF75534:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6AF75534
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6AF75534
		call do_sysenter_interrupt_6AF75534
		lea esp, [esp+4]
	ret_address_epilog_6AF75534:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6AF75534:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreatePort ENDP

Sw3NtCreatePrivateNamespace PROC
		push ebp
		mov ebp, esp
		push 0316914B1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0316914B1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_316914B1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_316914B1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_316914B1
		call do_sysenter_interrupt_316914B1
		lea esp, [esp+4]
	ret_address_epilog_316914B1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_316914B1:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreatePrivateNamespace ENDP

Sw3NtCreateProcess PROC
		push ebp
		mov ebp, esp
		push 0E697E71Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E697E71Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_E697E71B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E697E71B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E697E71B
		call do_sysenter_interrupt_E697E71B
		lea esp, [esp+4]
	ret_address_epilog_E697E71B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E697E71B:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateProcess ENDP

Sw3NtCreateProfile PROC
		push ebp
		mov ebp, esp
		push 0E9AEC72Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E9AEC72Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_E9AEC72B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E9AEC72B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E9AEC72B
		call do_sysenter_interrupt_E9AEC72B
		lea esp, [esp+4]
	ret_address_epilog_E9AEC72B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E9AEC72B:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateProfile ENDP

Sw3NtCreateProfileEx PROC
		push ebp
		mov ebp, esp
		push 02686E9C0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02686E9C0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_2686E9C0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2686E9C0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2686E9C0
		call do_sysenter_interrupt_2686E9C0
		lea esp, [esp+4]
	ret_address_epilog_2686E9C0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2686E9C0:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateProfileEx ENDP

Sw3NtCreateRegistryTransaction PROC
		push ebp
		mov ebp, esp
		push 0148E361Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0148E361Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_148E361F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_148E361F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_148E361F
		call do_sysenter_interrupt_148E361F
		lea esp, [esp+4]
	ret_address_epilog_148E361F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_148E361F:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateRegistryTransaction ENDP

Sw3NtCreateResourceManager PROC
		push ebp
		mov ebp, esp
		push 002299D24h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 002299D24h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_02299D24:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_02299D24
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_02299D24
		call do_sysenter_interrupt_02299D24
		lea esp, [esp+4]
	ret_address_epilog_02299D24:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_02299D24:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateResourceManager ENDP

Sw3NtCreateSemaphore PROC
		push ebp
		mov ebp, esp
		push 0DA883009h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DA883009h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_DA883009:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DA883009
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DA883009
		call do_sysenter_interrupt_DA883009
		lea esp, [esp+4]
	ret_address_epilog_DA883009:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DA883009:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateSemaphore ENDP

Sw3NtCreateSymbolicLinkObject PROC
		push ebp
		mov ebp, esp
		push 0284900D5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0284900D5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_284900D5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_284900D5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_284900D5
		call do_sysenter_interrupt_284900D5
		lea esp, [esp+4]
	ret_address_epilog_284900D5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_284900D5:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateSymbolicLinkObject ENDP

Sw3NtCreateThreadEx PROC
		push ebp
		mov ebp, esp
		push 0D62F28A9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D62F28A9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_D62F28A9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D62F28A9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D62F28A9
		call do_sysenter_interrupt_D62F28A9
		lea esp, [esp+4]
	ret_address_epilog_D62F28A9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D62F28A9:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateThreadEx ENDP

Sw3NtCreateTimer PROC
		push ebp
		mov ebp, esp
		push 03D970936h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03D970936h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_3D970936:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3D970936
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3D970936
		call do_sysenter_interrupt_3D970936
		lea esp, [esp+4]
	ret_address_epilog_3D970936:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3D970936:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateTimer ENDP

Sw3NtCreateTimer2 PROC
		push ebp
		mov ebp, esp
		push 00BAB4C3Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00BAB4C3Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0BAB4C3B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0BAB4C3B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0BAB4C3B
		call do_sysenter_interrupt_0BAB4C3B
		lea esp, [esp+4]
	ret_address_epilog_0BAB4C3B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0BAB4C3B:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateTimer2 ENDP

Sw3NtCreateToken PROC
		push ebp
		mov ebp, esp
		push 03D990D30h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03D990D30h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0dh
	push_argument_3D990D30:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3D990D30
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3D990D30
		call do_sysenter_interrupt_3D990D30
		lea esp, [esp+4]
	ret_address_epilog_3D990D30:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3D990D30:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateToken ENDP

Sw3NtCreateTokenEx PROC
		push ebp
		mov ebp, esp
		push 038AB767Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 038AB767Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 011h
	push_argument_38AB767C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_38AB767C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_38AB767C
		call do_sysenter_interrupt_38AB767C
		lea esp, [esp+4]
	ret_address_epilog_38AB767C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_38AB767C:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateTokenEx ENDP

Sw3NtCreateTransaction PROC
		push ebp
		mov ebp, esp
		push 0484468D7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0484468D7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_484468D7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_484468D7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_484468D7
		call do_sysenter_interrupt_484468D7
		lea esp, [esp+4]
	ret_address_epilog_484468D7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_484468D7:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateTransaction ENDP

Sw3NtCreateTransactionManager PROC
		push ebp
		mov ebp, esp
		push 0883D9097h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0883D9097h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_883D9097:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_883D9097
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_883D9097
		call do_sysenter_interrupt_883D9097
		lea esp, [esp+4]
	ret_address_epilog_883D9097:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_883D9097:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateTransactionManager ENDP

Sw3NtCreateUserProcess PROC
		push ebp
		mov ebp, esp
		push 082027D6Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 082027D6Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0bh
	push_argument_82027D6F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_82027D6F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_82027D6F
		call do_sysenter_interrupt_82027D6F
		lea esp, [esp+4]
	ret_address_epilog_82027D6F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_82027D6F:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateUserProcess ENDP

Sw3NtCreateWaitCompletionPacket PROC
		push ebp
		mov ebp, esp
		push 0753375A4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0753375A4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_753375A4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_753375A4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_753375A4
		call do_sysenter_interrupt_753375A4
		lea esp, [esp+4]
	ret_address_epilog_753375A4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_753375A4:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateWaitCompletionPacket ENDP

Sw3NtCreateWaitablePort PROC
		push ebp
		mov ebp, esp
		push 0FD74F4E9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FD74F4E9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_FD74F4E9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FD74F4E9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FD74F4E9
		call do_sysenter_interrupt_FD74F4E9
		lea esp, [esp+4]
	ret_address_epilog_FD74F4E9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FD74F4E9:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateWaitablePort ENDP

Sw3NtCreateWnfStateName PROC
		push ebp
		mov ebp, esp
		push 0CF1DA8C4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CF1DA8C4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_CF1DA8C4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CF1DA8C4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CF1DA8C4
		call do_sysenter_interrupt_CF1DA8C4
		lea esp, [esp+4]
	ret_address_epilog_CF1DA8C4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CF1DA8C4:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateWnfStateName ENDP

Sw3NtCreateWorkerFactory PROC
		push ebp
		mov ebp, esp
		push 046924E04h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 046924E04h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_46924E04:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_46924E04
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_46924E04
		call do_sysenter_interrupt_46924E04
		lea esp, [esp+4]
	ret_address_epilog_46924E04:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_46924E04:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateWorkerFactory ENDP

Sw3NtDebugActiveProcess PROC
		push ebp
		mov ebp, esp
		push 0A23BA9A7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A23BA9A7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_A23BA9A7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A23BA9A7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A23BA9A7
		call do_sysenter_interrupt_A23BA9A7
		lea esp, [esp+4]
	ret_address_epilog_A23BA9A7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A23BA9A7:
		mov edx, esp
		jmp edi
		ret
Sw3NtDebugActiveProcess ENDP

Sw3NtDebugContinue PROC
		push ebp
		mov ebp, esp
		push 0CA4EDDC2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CA4EDDC2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_CA4EDDC2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CA4EDDC2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CA4EDDC2
		call do_sysenter_interrupt_CA4EDDC2
		lea esp, [esp+4]
	ret_address_epilog_CA4EDDC2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CA4EDDC2:
		mov edx, esp
		jmp edi
		ret
Sw3NtDebugContinue ENDP

Sw3NtDeleteAtom PROC
		push ebp
		mov ebp, esp
		push 058D4A7BEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 058D4A7BEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_58D4A7BE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_58D4A7BE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_58D4A7BE
		call do_sysenter_interrupt_58D4A7BE
		lea esp, [esp+4]
	ret_address_epilog_58D4A7BE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_58D4A7BE:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteAtom ENDP

Sw3NtDeleteBootEntry PROC
		push ebp
		mov ebp, esp
		push 001953DD0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 001953DD0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_01953DD0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_01953DD0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_01953DD0
		call do_sysenter_interrupt_01953DD0
		lea esp, [esp+4]
	ret_address_epilog_01953DD0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_01953DD0:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteBootEntry ENDP

Sw3NtDeleteDriverEntry PROC
		push ebp
		mov ebp, esp
		push 029B8332Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 029B8332Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_29B8332A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_29B8332A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_29B8332A
		call do_sysenter_interrupt_29B8332A
		lea esp, [esp+4]
	ret_address_epilog_29B8332A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_29B8332A:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteDriverEntry ENDP

Sw3NtDeleteFile PROC
		push ebp
		mov ebp, esp
		push 058F3AA66h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 058F3AA66h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_58F3AA66:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_58F3AA66
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_58F3AA66
		call do_sysenter_interrupt_58F3AA66
		lea esp, [esp+4]
	ret_address_epilog_58F3AA66:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_58F3AA66:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteFile ENDP

Sw3NtDeleteKey PROC
		push ebp
		mov ebp, esp
		push 075CF1C2Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 075CF1C2Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_75CF1C2C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_75CF1C2C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_75CF1C2C
		call do_sysenter_interrupt_75CF1C2C
		lea esp, [esp+4]
	ret_address_epilog_75CF1C2C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_75CF1C2C:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteKey ENDP

Sw3NtDeleteObjectAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 018B7FEE6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 018B7FEE6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_18B7FEE6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_18B7FEE6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_18B7FEE6
		call do_sysenter_interrupt_18B7FEE6
		lea esp, [esp+4]
	ret_address_epilog_18B7FEE6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_18B7FEE6:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteObjectAuditAlarm ENDP

Sw3NtDeletePrivateNamespace PROC
		push ebp
		mov ebp, esp
		push 062B27703h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 062B27703h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_62B27703:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_62B27703
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_62B27703
		call do_sysenter_interrupt_62B27703
		lea esp, [esp+4]
	ret_address_epilog_62B27703:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_62B27703:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeletePrivateNamespace ENDP

Sw3NtDeleteValueKey PROC
		push ebp
		mov ebp, esp
		push 0FD3DD8A6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FD3DD8A6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_FD3DD8A6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FD3DD8A6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FD3DD8A6
		call do_sysenter_interrupt_FD3DD8A6
		lea esp, [esp+4]
	ret_address_epilog_FD3DD8A6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FD3DD8A6:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteValueKey ENDP

Sw3NtDeleteWnfStateData PROC
		push ebp
		mov ebp, esp
		push 0A705B1B3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A705B1B3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_A705B1B3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A705B1B3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A705B1B3
		call do_sysenter_interrupt_A705B1B3
		lea esp, [esp+4]
	ret_address_epilog_A705B1B3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A705B1B3:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteWnfStateData ENDP

Sw3NtDeleteWnfStateName PROC
		push ebp
		mov ebp, esp
		push 09EBC4E86h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09EBC4E86h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_9EBC4E86:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9EBC4E86
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9EBC4E86
		call do_sysenter_interrupt_9EBC4E86
		lea esp, [esp+4]
	ret_address_epilog_9EBC4E86:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9EBC4E86:
		mov edx, esp
		jmp edi
		ret
Sw3NtDeleteWnfStateName ENDP

Sw3NtDisableLastKnownGood PROC
		push ebp
		mov ebp, esp
		push 0A1325B24h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A1325B24h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_A1325B24:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A1325B24
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A1325B24
		call do_sysenter_interrupt_A1325B24
		lea esp, [esp+4]
	ret_address_epilog_A1325B24:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A1325B24:
		mov edx, esp
		jmp edi
		ret
Sw3NtDisableLastKnownGood ENDP

Sw3NtDisplayString PROC
		push ebp
		mov ebp, esp
		push 042C25672h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 042C25672h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_42C25672:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_42C25672
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_42C25672
		call do_sysenter_interrupt_42C25672
		lea esp, [esp+4]
	ret_address_epilog_42C25672:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_42C25672:
		mov edx, esp
		jmp edi
		ret
Sw3NtDisplayString ENDP

Sw3NtDrawText PROC
		push ebp
		mov ebp, esp
		push 090D59545h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 090D59545h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_90D59545:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_90D59545
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_90D59545
		call do_sysenter_interrupt_90D59545
		lea esp, [esp+4]
	ret_address_epilog_90D59545:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_90D59545:
		mov edx, esp
		jmp edi
		ret
Sw3NtDrawText ENDP

Sw3NtEnableLastKnownGood PROC
		push ebp
		mov ebp, esp
		push 05B75CE7Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05B75CE7Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_5B75CE7C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5B75CE7C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5B75CE7C
		call do_sysenter_interrupt_5B75CE7C
		lea esp, [esp+4]
	ret_address_epilog_5B75CE7C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5B75CE7C:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnableLastKnownGood ENDP

Sw3NtEnumerateBootEntries PROC
		push ebp
		mov ebp, esp
		push 0F6A602CAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F6A602CAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_F6A602CA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F6A602CA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F6A602CA
		call do_sysenter_interrupt_F6A602CA
		lea esp, [esp+4]
	ret_address_epilog_F6A602CA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F6A602CA:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateBootEntries ENDP

Sw3NtEnumerateDriverEntries PROC
		push ebp
		mov ebp, esp
		push 038AF4143h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 038AF4143h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_38AF4143:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_38AF4143
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_38AF4143
		call do_sysenter_interrupt_38AF4143
		lea esp, [esp+4]
	ret_address_epilog_38AF4143:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_38AF4143:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateDriverEntries ENDP

Sw3NtEnumerateSystemEnvironmentValuesEx PROC
		push ebp
		mov ebp, esp
		push 0737E2DABh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0737E2DABh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_737E2DAB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_737E2DAB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_737E2DAB
		call do_sysenter_interrupt_737E2DAB
		lea esp, [esp+4]
	ret_address_epilog_737E2DAB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_737E2DAB:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateSystemEnvironmentValuesEx ENDP

Sw3NtEnumerateTransactionObject PROC
		push ebp
		mov ebp, esp
		push 00DC91B6Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00DC91B6Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0DC91B6A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0DC91B6A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0DC91B6A
		call do_sysenter_interrupt_0DC91B6A
		lea esp, [esp+4]
	ret_address_epilog_0DC91B6A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0DC91B6A:
		mov edx, esp
		jmp edi
		ret
Sw3NtEnumerateTransactionObject ENDP

Sw3NtExtendSection PROC
		push ebp
		mov ebp, esp
		push 056827417h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 056827417h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_56827417:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_56827417
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_56827417
		call do_sysenter_interrupt_56827417
		lea esp, [esp+4]
	ret_address_epilog_56827417:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_56827417:
		mov edx, esp
		jmp edi
		ret
Sw3NtExtendSection ENDP

Sw3NtFilterBootOption PROC
		push ebp
		mov ebp, esp
		push 00C98080Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C98080Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_0C98080D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C98080D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C98080D
		call do_sysenter_interrupt_0C98080D
		lea esp, [esp+4]
	ret_address_epilog_0C98080D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C98080D:
		mov edx, esp
		jmp edi
		ret
Sw3NtFilterBootOption ENDP

Sw3NtFilterToken PROC
		push ebp
		mov ebp, esp
		push 0259A1F12h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0259A1F12h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_259A1F12:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_259A1F12
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_259A1F12
		call do_sysenter_interrupt_259A1F12
		lea esp, [esp+4]
	ret_address_epilog_259A1F12:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_259A1F12:
		mov edx, esp
		jmp edi
		ret
Sw3NtFilterToken ENDP

Sw3NtFilterTokenEx PROC
		push ebp
		mov ebp, esp
		push 0C28B0DDDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C28B0DDDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0eh
	push_argument_C28B0DDD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C28B0DDD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C28B0DDD
		call do_sysenter_interrupt_C28B0DDD
		lea esp, [esp+4]
	ret_address_epilog_C28B0DDD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C28B0DDD:
		mov edx, esp
		jmp edi
		ret
Sw3NtFilterTokenEx ENDP

Sw3NtFlushBuffersFileEx PROC
		push ebp
		mov ebp, esp
		push 0208BF3D0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0208BF3D0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_208BF3D0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_208BF3D0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_208BF3D0
		call do_sysenter_interrupt_208BF3D0
		lea esp, [esp+4]
	ret_address_epilog_208BF3D0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_208BF3D0:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushBuffersFileEx ENDP

Sw3NtFlushInstallUILanguage PROC
		push ebp
		mov ebp, esp
		push 02B89682Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02B89682Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_2B89682C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2B89682C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2B89682C
		call do_sysenter_interrupt_2B89682C
		lea esp, [esp+4]
	ret_address_epilog_2B89682C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2B89682C:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushInstallUILanguage ENDP

Sw3NtFlushInstructionCache PROC
		push ebp
		mov ebp, esp
		push 080205217h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 080205217h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_80205217:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_80205217
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_80205217
		call do_sysenter_interrupt_80205217
		lea esp, [esp+4]
	ret_address_epilog_80205217:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_80205217:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushInstructionCache ENDP

Sw3NtFlushKey PROC
		push ebp
		mov ebp, esp
		push 0E0C012B4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E0C012B4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_E0C012B4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E0C012B4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E0C012B4
		call do_sysenter_interrupt_E0C012B4
		lea esp, [esp+4]
	ret_address_epilog_E0C012B4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E0C012B4:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushKey ENDP

Sw3NtFlushProcessWriteBuffers PROC
		push ebp
		mov ebp, esp
		push 090BBB6EEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 090BBB6EEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_90BBB6EE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_90BBB6EE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_90BBB6EE
		call do_sysenter_interrupt_90BBB6EE
		lea esp, [esp+4]
	ret_address_epilog_90BBB6EE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_90BBB6EE:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushProcessWriteBuffers ENDP

Sw3NtFlushVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 0B52ED9BBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B52ED9BBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_B52ED9BB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B52ED9BB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B52ED9BB
		call do_sysenter_interrupt_B52ED9BB
		lea esp, [esp+4]
	ret_address_epilog_B52ED9BB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B52ED9BB:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushVirtualMemory ENDP

Sw3NtFlushWriteBuffer PROC
		push ebp
		mov ebp, esp
		push 0F85B0859h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F85B0859h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_F85B0859:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F85B0859
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F85B0859
		call do_sysenter_interrupt_F85B0859
		lea esp, [esp+4]
	ret_address_epilog_F85B0859:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F85B0859:
		mov edx, esp
		jmp edi
		ret
Sw3NtFlushWriteBuffer ENDP

Sw3NtFreeUserPhysicalPages PROC
		push ebp
		mov ebp, esp
		push 079DE88B0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 079DE88B0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_79DE88B0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_79DE88B0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_79DE88B0
		call do_sysenter_interrupt_79DE88B0
		lea esp, [esp+4]
	ret_address_epilog_79DE88B0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_79DE88B0:
		mov edx, esp
		jmp edi
		ret
Sw3NtFreeUserPhysicalPages ENDP

Sw3NtFreezeRegistry PROC
		push ebp
		mov ebp, esp
		push 0028C1C15h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0028C1C15h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_028C1C15:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_028C1C15
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_028C1C15
		call do_sysenter_interrupt_028C1C15
		lea esp, [esp+4]
	ret_address_epilog_028C1C15:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_028C1C15:
		mov edx, esp
		jmp edi
		ret
Sw3NtFreezeRegistry ENDP

Sw3NtFreezeTransactions PROC
		push ebp
		mov ebp, esp
		push 0D515F597h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D515F597h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_D515F597:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D515F597
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D515F597
		call do_sysenter_interrupt_D515F597
		lea esp, [esp+4]
	ret_address_epilog_D515F597:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D515F597:
		mov edx, esp
		jmp edi
		ret
Sw3NtFreezeTransactions ENDP

Sw3NtGetCachedSigningLevel PROC
		push ebp
		mov ebp, esp
		push 02C9713DCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02C9713DCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_2C9713DC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2C9713DC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2C9713DC
		call do_sysenter_interrupt_2C9713DC
		lea esp, [esp+4]
	ret_address_epilog_2C9713DC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2C9713DC:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetCachedSigningLevel ENDP

Sw3NtGetCompleteWnfStateSubscription PROC
		push ebp
		mov ebp, esp
		push 0FAB21EE3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FAB21EE3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_FAB21EE3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FAB21EE3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FAB21EE3
		call do_sysenter_interrupt_FAB21EE3
		lea esp, [esp+4]
	ret_address_epilog_FAB21EE3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FAB21EE3:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetCompleteWnfStateSubscription ENDP

Sw3NtGetContextThread PROC
		push ebp
		mov ebp, esp
		push 064BC5463h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 064BC5463h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_64BC5463:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_64BC5463
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_64BC5463
		call do_sysenter_interrupt_64BC5463
		lea esp, [esp+4]
	ret_address_epilog_64BC5463:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_64BC5463:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetContextThread ENDP

Sw3NtGetCurrentProcessorNumber PROC
		push ebp
		mov ebp, esp
		push 06C2B04F0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06C2B04F0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_6C2B04F0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6C2B04F0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6C2B04F0
		call do_sysenter_interrupt_6C2B04F0
		lea esp, [esp+4]
	ret_address_epilog_6C2B04F0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6C2B04F0:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetCurrentProcessorNumber ENDP

Sw3NtGetCurrentProcessorNumberEx PROC
		push ebp
		mov ebp, esp
		push 04CD40E6Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 04CD40E6Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_4CD40E6E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_4CD40E6E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_4CD40E6E
		call do_sysenter_interrupt_4CD40E6E
		lea esp, [esp+4]
	ret_address_epilog_4CD40E6E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_4CD40E6E:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetCurrentProcessorNumberEx ENDP

Sw3NtGetDevicePowerState PROC
		push ebp
		mov ebp, esp
		push 000AEFF2Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 000AEFF2Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_00AEFF2C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_00AEFF2C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_00AEFF2C
		call do_sysenter_interrupt_00AEFF2C
		lea esp, [esp+4]
	ret_address_epilog_00AEFF2C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_00AEFF2C:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetDevicePowerState ENDP

Sw3NtGetMUIRegistryInfo PROC
		push ebp
		mov ebp, esp
		push 08221BC8Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08221BC8Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_8221BC8F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8221BC8F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8221BC8F
		call do_sysenter_interrupt_8221BC8F
		lea esp, [esp+4]
	ret_address_epilog_8221BC8F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8221BC8F:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetMUIRegistryInfo ENDP

Sw3NtGetNextProcess PROC
		push ebp
		mov ebp, esp
		push 0CF31DCBEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CF31DCBEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_CF31DCBE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CF31DCBE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CF31DCBE
		call do_sysenter_interrupt_CF31DCBE
		lea esp, [esp+4]
	ret_address_epilog_CF31DCBE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CF31DCBE:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetNextProcess ENDP

Sw3NtGetNextThread PROC
		push ebp
		mov ebp, esp
		push 08C69CEC7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08C69CEC7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_8C69CEC7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8C69CEC7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8C69CEC7
		call do_sysenter_interrupt_8C69CEC7
		lea esp, [esp+4]
	ret_address_epilog_8C69CEC7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8C69CEC7:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetNextThread ENDP

Sw3NtGetNlsSectionPtr PROC
		push ebp
		mov ebp, esp
		push 02B6DEF5Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02B6DEF5Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_2B6DEF5B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2B6DEF5B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2B6DEF5B
		call do_sysenter_interrupt_2B6DEF5B
		lea esp, [esp+4]
	ret_address_epilog_2B6DEF5B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2B6DEF5B:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetNlsSectionPtr ENDP

Sw3NtGetNotificationResourceManager PROC
		push ebp
		mov ebp, esp
		push 0DF87F15Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DF87F15Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_DF87F15B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DF87F15B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DF87F15B
		call do_sysenter_interrupt_DF87F15B
		lea esp, [esp+4]
	ret_address_epilog_DF87F15B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DF87F15B:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetNotificationResourceManager ENDP

Sw3NtGetWriteWatch PROC
		push ebp
		mov ebp, esp
		push 076CB8B5Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 076CB8B5Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_76CB8B5E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_76CB8B5E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_76CB8B5E
		call do_sysenter_interrupt_76CB8B5E
		lea esp, [esp+4]
	ret_address_epilog_76CB8B5E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_76CB8B5E:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetWriteWatch ENDP

Sw3NtImpersonateAnonymousToken PROC
		push ebp
		mov ebp, esp
		push 02395B49Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02395B49Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_2395B49C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2395B49C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2395B49C
		call do_sysenter_interrupt_2395B49C
		lea esp, [esp+4]
	ret_address_epilog_2395B49C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2395B49C:
		mov edx, esp
		jmp edi
		ret
Sw3NtImpersonateAnonymousToken ENDP

Sw3NtImpersonateThread PROC
		push ebp
		mov ebp, esp
		push 08CA0558Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08CA0558Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_8CA0558A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8CA0558A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8CA0558A
		call do_sysenter_interrupt_8CA0558A
		lea esp, [esp+4]
	ret_address_epilog_8CA0558A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8CA0558A:
		mov edx, esp
		jmp edi
		ret
Sw3NtImpersonateThread ENDP

Sw3NtInitializeEnclave PROC
		push ebp
		mov ebp, esp
		push 058998824h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 058998824h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_58998824:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_58998824
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_58998824
		call do_sysenter_interrupt_58998824
		lea esp, [esp+4]
	ret_address_epilog_58998824:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_58998824:
		mov edx, esp
		jmp edi
		ret
Sw3NtInitializeEnclave ENDP

Sw3NtInitializeNlsFiles PROC
		push ebp
		mov ebp, esp
		push 0ED581D3Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0ED581D3Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_ED581D3B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_ED581D3B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_ED581D3B
		call do_sysenter_interrupt_ED581D3B
		lea esp, [esp+4]
	ret_address_epilog_ED581D3B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_ED581D3B:
		mov edx, esp
		jmp edi
		ret
Sw3NtInitializeNlsFiles ENDP

Sw3NtInitializeRegistry PROC
		push ebp
		mov ebp, esp
		push 03C90083Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03C90083Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_3C90083D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3C90083D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3C90083D
		call do_sysenter_interrupt_3C90083D
		lea esp, [esp+4]
	ret_address_epilog_3C90083D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3C90083D:
		mov edx, esp
		jmp edi
		ret
Sw3NtInitializeRegistry ENDP

Sw3NtInitiatePowerAction PROC
		push ebp
		mov ebp, esp
		push 01AB2FCE7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01AB2FCE7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_1AB2FCE7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1AB2FCE7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1AB2FCE7
		call do_sysenter_interrupt_1AB2FCE7
		lea esp, [esp+4]
	ret_address_epilog_1AB2FCE7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1AB2FCE7:
		mov edx, esp
		jmp edi
		ret
Sw3NtInitiatePowerAction ENDP

Sw3NtIsSystemResumeAutomatic PROC
		push ebp
		mov ebp, esp
		push 00AF887D6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00AF887D6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_0AF887D6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0AF887D6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0AF887D6
		call do_sysenter_interrupt_0AF887D6
		lea esp, [esp+4]
	ret_address_epilog_0AF887D6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0AF887D6:
		mov edx, esp
		jmp edi
		ret
Sw3NtIsSystemResumeAutomatic ENDP

Sw3NtIsUILanguageComitted PROC
		push ebp
		mov ebp, esp
		push 0E3ADFB11h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E3ADFB11h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_E3ADFB11:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E3ADFB11
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E3ADFB11
		call do_sysenter_interrupt_E3ADFB11
		lea esp, [esp+4]
	ret_address_epilog_E3ADFB11:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E3ADFB11:
		mov edx, esp
		jmp edi
		ret
Sw3NtIsUILanguageComitted ENDP

Sw3NtListenPort PROC
		push ebp
		mov ebp, esp
		push 0DCB639E4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DCB639E4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_DCB639E4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DCB639E4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DCB639E4
		call do_sysenter_interrupt_DCB639E4
		lea esp, [esp+4]
	ret_address_epilog_DCB639E4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DCB639E4:
		mov edx, esp
		jmp edi
		ret
Sw3NtListenPort ENDP

Sw3NtLoadDriver PROC
		push ebp
		mov ebp, esp
		push 0775D0DB2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0775D0DB2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_775D0DB2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_775D0DB2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_775D0DB2
		call do_sysenter_interrupt_775D0DB2
		lea esp, [esp+4]
	ret_address_epilog_775D0DB2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_775D0DB2:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadDriver ENDP

Sw3NtLoadEnclaveData PROC
		push ebp
		mov ebp, esp
		push 0E74FB47Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E74FB47Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_E74FB47D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E74FB47D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E74FB47D
		call do_sysenter_interrupt_E74FB47D
		lea esp, [esp+4]
	ret_address_epilog_E74FB47D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E74FB47D:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadEnclaveData ENDP

Sw3NtLoadHotPatch PROC
		push ebp
		mov ebp, esp
		push 0ECB8C834h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0ECB8C834h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_ECB8C834:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_ECB8C834
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_ECB8C834
		call do_sysenter_interrupt_ECB8C834
		lea esp, [esp+4]
	ret_address_epilog_ECB8C834:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_ECB8C834:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadHotPatch ENDP

Sw3NtLoadKey PROC
		push ebp
		mov ebp, esp
		push 0051D30AFh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0051D30AFh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_051D30AF:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_051D30AF
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_051D30AF
		call do_sysenter_interrupt_051D30AF
		lea esp, [esp+4]
	ret_address_epilog_051D30AF:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_051D30AF:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadKey ENDP

Sw3NtLoadKey2 PROC
		push ebp
		mov ebp, esp
		push 0AA18631Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AA18631Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_AA18631F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AA18631F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AA18631F
		call do_sysenter_interrupt_AA18631F
		lea esp, [esp+4]
	ret_address_epilog_AA18631F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AA18631F:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadKey2 ENDP

Sw3NtLoadKeyEx PROC
		push ebp
		mov ebp, esp
		push 0D5B206E9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D5B206E9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_D5B206E9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D5B206E9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D5B206E9
		call do_sysenter_interrupt_D5B206E9
		lea esp, [esp+4]
	ret_address_epilog_D5B206E9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D5B206E9:
		mov edx, esp
		jmp edi
		ret
Sw3NtLoadKeyEx ENDP

Sw3NtLockFile PROC
		push ebp
		mov ebp, esp
		push 064A47610h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 064A47610h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_64A47610:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_64A47610
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_64A47610
		call do_sysenter_interrupt_64A47610
		lea esp, [esp+4]
	ret_address_epilog_64A47610:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_64A47610:
		mov edx, esp
		jmp edi
		ret
Sw3NtLockFile ENDP

Sw3NtLockProductActivationKeys PROC
		push ebp
		mov ebp, esp
		push 03B244EC2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03B244EC2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3B244EC2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3B244EC2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3B244EC2
		call do_sysenter_interrupt_3B244EC2
		lea esp, [esp+4]
	ret_address_epilog_3B244EC2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3B244EC2:
		mov edx, esp
		jmp edi
		ret
Sw3NtLockProductActivationKeys ENDP

Sw3NtLockRegistryKey PROC
		push ebp
		mov ebp, esp
		push 01210378Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01210378Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_1210378D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1210378D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1210378D
		call do_sysenter_interrupt_1210378D
		lea esp, [esp+4]
	ret_address_epilog_1210378D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1210378D:
		mov edx, esp
		jmp edi
		ret
Sw3NtLockRegistryKey ENDP

Sw3NtLockVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 023B12923h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 023B12923h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_23B12923:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_23B12923
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_23B12923
		call do_sysenter_interrupt_23B12923
		lea esp, [esp+4]
	ret_address_epilog_23B12923:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_23B12923:
		mov edx, esp
		jmp edi
		ret
Sw3NtLockVirtualMemory ENDP

Sw3NtMakePermanentObject PROC
		push ebp
		mov ebp, esp
		push 0A9B7DB49h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A9B7DB49h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_A9B7DB49:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A9B7DB49
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A9B7DB49
		call do_sysenter_interrupt_A9B7DB49
		lea esp, [esp+4]
	ret_address_epilog_A9B7DB49:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A9B7DB49:
		mov edx, esp
		jmp edi
		ret
Sw3NtMakePermanentObject ENDP

Sw3NtMakeTemporaryObject PROC
		push ebp
		mov ebp, esp
		push 0069A6E07h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0069A6E07h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_069A6E07:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_069A6E07
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_069A6E07
		call do_sysenter_interrupt_069A6E07
		lea esp, [esp+4]
	ret_address_epilog_069A6E07:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_069A6E07:
		mov edx, esp
		jmp edi
		ret
Sw3NtMakeTemporaryObject ENDP

Sw3NtManagePartition PROC
		push ebp
		mov ebp, esp
		push 07AE296A1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07AE296A1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_7AE296A1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7AE296A1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7AE296A1
		call do_sysenter_interrupt_7AE296A1
		lea esp, [esp+4]
	ret_address_epilog_7AE296A1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7AE296A1:
		mov edx, esp
		jmp edi
		ret
Sw3NtManagePartition ENDP

Sw3NtMapCMFModule PROC
		push ebp
		mov ebp, esp
		push 0108281B4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0108281B4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_108281B4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_108281B4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_108281B4
		call do_sysenter_interrupt_108281B4
		lea esp, [esp+4]
	ret_address_epilog_108281B4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_108281B4:
		mov edx, esp
		jmp edi
		ret
Sw3NtMapCMFModule ENDP

Sw3NtMapUserPhysicalPages PROC
		push ebp
		mov ebp, esp
		push 099BC46FCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 099BC46FCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_99BC46FC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_99BC46FC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_99BC46FC
		call do_sysenter_interrupt_99BC46FC
		lea esp, [esp+4]
	ret_address_epilog_99BC46FC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_99BC46FC:
		mov edx, esp
		jmp edi
		ret
Sw3NtMapUserPhysicalPages ENDP

Sw3NtMapViewOfSectionEx PROC
		push ebp
		mov ebp, esp
		push 0F8130765h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F8130765h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_F8130765:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F8130765
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F8130765
		call do_sysenter_interrupt_F8130765
		lea esp, [esp+4]
	ret_address_epilog_F8130765:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F8130765:
		mov edx, esp
		jmp edi
		ret
Sw3NtMapViewOfSectionEx ENDP

Sw3NtModifyBootEntry PROC
		push ebp
		mov ebp, esp
		push 049A4C2A6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 049A4C2A6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_49A4C2A6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_49A4C2A6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_49A4C2A6
		call do_sysenter_interrupt_49A4C2A6
		lea esp, [esp+4]
	ret_address_epilog_49A4C2A6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_49A4C2A6:
		mov edx, esp
		jmp edi
		ret
Sw3NtModifyBootEntry ENDP

Sw3NtModifyDriverEntry PROC
		push ebp
		mov ebp, esp
		push 019A73D78h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 019A73D78h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_19A73D78:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_19A73D78
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_19A73D78
		call do_sysenter_interrupt_19A73D78
		lea esp, [esp+4]
	ret_address_epilog_19A73D78:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_19A73D78:
		mov edx, esp
		jmp edi
		ret
Sw3NtModifyDriverEntry ENDP

Sw3NtNotifyChangeDirectoryFile PROC
		push ebp
		mov ebp, esp
		push 070DA6E62h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 070DA6E62h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_70DA6E62:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_70DA6E62
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_70DA6E62
		call do_sysenter_interrupt_70DA6E62
		lea esp, [esp+4]
	ret_address_epilog_70DA6E62:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_70DA6E62:
		mov edx, esp
		jmp edi
		ret
Sw3NtNotifyChangeDirectoryFile ENDP

Sw3NtNotifyChangeDirectoryFileEx PROC
		push ebp
		mov ebp, esp
		push 00AB9CCC7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00AB9CCC7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_0AB9CCC7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0AB9CCC7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0AB9CCC7
		call do_sysenter_interrupt_0AB9CCC7
		lea esp, [esp+4]
	ret_address_epilog_0AB9CCC7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0AB9CCC7:
		mov edx, esp
		jmp edi
		ret
Sw3NtNotifyChangeDirectoryFileEx ENDP

Sw3NtNotifyChangeKey PROC
		push ebp
		mov ebp, esp
		push 09F1A7F02h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09F1A7F02h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_9F1A7F02:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9F1A7F02
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9F1A7F02
		call do_sysenter_interrupt_9F1A7F02
		lea esp, [esp+4]
	ret_address_epilog_9F1A7F02:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9F1A7F02:
		mov edx, esp
		jmp edi
		ret
Sw3NtNotifyChangeKey ENDP

Sw3NtNotifyChangeMultipleKeys PROC
		push ebp
		mov ebp, esp
		push 0403BB97Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0403BB97Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ch
	push_argument_403BB97C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_403BB97C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_403BB97C
		call do_sysenter_interrupt_403BB97C
		lea esp, [esp+4]
	ret_address_epilog_403BB97C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_403BB97C:
		mov edx, esp
		jmp edi
		ret
Sw3NtNotifyChangeMultipleKeys ENDP

Sw3NtNotifyChangeSession PROC
		push ebp
		mov ebp, esp
		push 031A77D74h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 031A77D74h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 08h
	push_argument_31A77D74:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_31A77D74
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_31A77D74
		call do_sysenter_interrupt_31A77D74
		lea esp, [esp+4]
	ret_address_epilog_31A77D74:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_31A77D74:
		mov edx, esp
		jmp edi
		ret
Sw3NtNotifyChangeSession ENDP

Sw3NtOpenEnlistment PROC
		push ebp
		mov ebp, esp
		push 071EB041Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 071EB041Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_71EB041D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_71EB041D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_71EB041D
		call do_sysenter_interrupt_71EB041D
		lea esp, [esp+4]
	ret_address_epilog_71EB041D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_71EB041D:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenEnlistment ENDP

Sw3NtOpenEventPair PROC
		push ebp
		mov ebp, esp
		push 000D50853h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 000D50853h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_00D50853:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_00D50853
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_00D50853
		call do_sysenter_interrupt_00D50853
		lea esp, [esp+4]
	ret_address_epilog_00D50853:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_00D50853:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenEventPair ENDP

Sw3NtOpenIoCompletion PROC
		push ebp
		mov ebp, esp
		push 00AA52831h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00AA52831h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_0AA52831:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0AA52831
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0AA52831
		call do_sysenter_interrupt_0AA52831
		lea esp, [esp+4]
	ret_address_epilog_0AA52831:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0AA52831:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenIoCompletion ENDP

Sw3NtOpenJobObject PROC
		push ebp
		mov ebp, esp
		push 012B8FCE5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 012B8FCE5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_12B8FCE5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_12B8FCE5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_12B8FCE5
		call do_sysenter_interrupt_12B8FCE5
		lea esp, [esp+4]
	ret_address_epilog_12B8FCE5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_12B8FCE5:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenJobObject ENDP

Sw3NtOpenKeyEx PROC
		push ebp
		mov ebp, esp
		push 02B9C7F40h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02B9C7F40h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_2B9C7F40:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2B9C7F40
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2B9C7F40
		call do_sysenter_interrupt_2B9C7F40
		lea esp, [esp+4]
	ret_address_epilog_2B9C7F40:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2B9C7F40:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenKeyEx ENDP

Sw3NtOpenKeyTransacted PROC
		push ebp
		mov ebp, esp
		push 0AC80CA59h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AC80CA59h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_AC80CA59:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AC80CA59
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AC80CA59
		call do_sysenter_interrupt_AC80CA59
		lea esp, [esp+4]
	ret_address_epilog_AC80CA59:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AC80CA59:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenKeyTransacted ENDP

Sw3NtOpenKeyTransactedEx PROC
		push ebp
		mov ebp, esp
		push 060D95362h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 060D95362h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_60D95362:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_60D95362
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_60D95362
		call do_sysenter_interrupt_60D95362
		lea esp, [esp+4]
	ret_address_epilog_60D95362:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_60D95362:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenKeyTransactedEx ENDP

Sw3NtOpenKeyedEvent PROC
		push ebp
		mov ebp, esp
		push 01E9E2134h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01E9E2134h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1E9E2134:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1E9E2134
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1E9E2134
		call do_sysenter_interrupt_1E9E2134
		lea esp, [esp+4]
	ret_address_epilog_1E9E2134:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1E9E2134:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenKeyedEvent ENDP

Sw3NtOpenMutant PROC
		push ebp
		mov ebp, esp
		push 08CCEAB1Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08CCEAB1Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_8CCEAB1D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8CCEAB1D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8CCEAB1D
		call do_sysenter_interrupt_8CCEAB1D
		lea esp, [esp+4]
	ret_address_epilog_8CCEAB1D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8CCEAB1D:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenMutant ENDP

Sw3NtOpenObjectAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 0C2A3E27Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C2A3E27Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ch
	push_argument_C2A3E27D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C2A3E27D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C2A3E27D
		call do_sysenter_interrupt_C2A3E27D
		lea esp, [esp+4]
	ret_address_epilog_C2A3E27D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C2A3E27D:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenObjectAuditAlarm ENDP

Sw3NtOpenPartition PROC
		push ebp
		mov ebp, esp
		push 0F26B96B1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F26B96B1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_F26B96B1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F26B96B1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F26B96B1
		call do_sysenter_interrupt_F26B96B1
		lea esp, [esp+4]
	ret_address_epilog_F26B96B1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F26B96B1:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenPartition ENDP

Sw3NtOpenPrivateNamespace PROC
		push ebp
		mov ebp, esp
		push 008B2D00Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 008B2D00Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_08B2D00F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_08B2D00F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_08B2D00F
		call do_sysenter_interrupt_08B2D00F
		lea esp, [esp+4]
	ret_address_epilog_08B2D00F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_08B2D00F:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenPrivateNamespace ENDP

Sw3NtOpenProcessToken PROC
		push ebp
		mov ebp, esp
		push 0C64333D8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C64333D8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_C64333D8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C64333D8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C64333D8
		call do_sysenter_interrupt_C64333D8
		lea esp, [esp+4]
	ret_address_epilog_C64333D8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C64333D8:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenProcessToken ENDP

Sw3NtOpenRegistryTransaction PROC
		push ebp
		mov ebp, esp
		push 084CE4396h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 084CE4396h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_84CE4396:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_84CE4396
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_84CE4396
		call do_sysenter_interrupt_84CE4396
		lea esp, [esp+4]
	ret_address_epilog_84CE4396:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_84CE4396:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenRegistryTransaction ENDP

Sw3NtOpenResourceManager PROC
		push ebp
		mov ebp, esp
		push 0E25ED6E4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E25ED6E4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_E25ED6E4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E25ED6E4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E25ED6E4
		call do_sysenter_interrupt_E25ED6E4
		lea esp, [esp+4]
	ret_address_epilog_E25ED6E4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E25ED6E4:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenResourceManager ENDP

Sw3NtOpenSemaphore PROC
		push ebp
		mov ebp, esp
		push 046D3127Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 046D3127Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_46D3127C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_46D3127C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_46D3127C
		call do_sysenter_interrupt_46D3127C
		lea esp, [esp+4]
	ret_address_epilog_46D3127C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_46D3127C:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenSemaphore ENDP

Sw3NtOpenSession PROC
		push ebp
		mov ebp, esp
		push 0742D52FCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0742D52FCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_742D52FC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_742D52FC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_742D52FC
		call do_sysenter_interrupt_742D52FC
		lea esp, [esp+4]
	ret_address_epilog_742D52FC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_742D52FC:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenSession ENDP

Sw3NtOpenSymbolicLinkObject PROC
		push ebp
		mov ebp, esp
		push 0A837B89Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A837B89Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_A837B89B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A837B89B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A837B89B
		call do_sysenter_interrupt_A837B89B
		lea esp, [esp+4]
	ret_address_epilog_A837B89B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A837B89B:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenSymbolicLinkObject ENDP

Sw3NtOpenThread PROC
		push ebp
		mov ebp, esp
		push 0B490B820h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B490B820h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_B490B820:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B490B820
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B490B820
		call do_sysenter_interrupt_B490B820
		lea esp, [esp+4]
	ret_address_epilog_B490B820:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B490B820:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenThread ENDP

Sw3NtOpenTimer PROC
		push ebp
		mov ebp, esp
		push 07F9898CAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07F9898CAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_7F9898CA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7F9898CA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7F9898CA
		call do_sysenter_interrupt_7F9898CA
		lea esp, [esp+4]
	ret_address_epilog_7F9898CA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7F9898CA:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenTimer ENDP

Sw3NtOpenTransaction PROC
		push ebp
		mov ebp, esp
		push 000C91C7Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 000C91C7Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_00C91C7B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_00C91C7B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_00C91C7B
		call do_sysenter_interrupt_00C91C7B
		lea esp, [esp+4]
	ret_address_epilog_00C91C7B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_00C91C7B:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenTransaction ENDP

Sw3NtOpenTransactionManager PROC
		push ebp
		mov ebp, esp
		push 00937C06Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00937C06Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_0937C06C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0937C06C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0937C06C
		call do_sysenter_interrupt_0937C06C
		lea esp, [esp+4]
	ret_address_epilog_0937C06C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0937C06C:
		mov edx, esp
		jmp edi
		ret
Sw3NtOpenTransactionManager ENDP

Sw3NtPlugPlayControl PROC
		push ebp
		mov ebp, esp
		push 00751C00Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00751C00Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_0751C00A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0751C00A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0751C00A
		call do_sysenter_interrupt_0751C00A
		lea esp, [esp+4]
	ret_address_epilog_0751C00A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0751C00A:
		mov edx, esp
		jmp edi
		ret
Sw3NtPlugPlayControl ENDP

Sw3NtPrePrepareComplete PROC
		push ebp
		mov ebp, esp
		push 03AB3687Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03AB3687Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3AB3687C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3AB3687C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3AB3687C
		call do_sysenter_interrupt_3AB3687C
		lea esp, [esp+4]
	ret_address_epilog_3AB3687C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3AB3687C:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrePrepareComplete ENDP

Sw3NtPrePrepareEnlistment PROC
		push ebp
		mov ebp, esp
		push 00FC0084Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00FC0084Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0FC0084B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0FC0084B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0FC0084B
		call do_sysenter_interrupt_0FC0084B
		lea esp, [esp+4]
	ret_address_epilog_0FC0084B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0FC0084B:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrePrepareEnlistment ENDP

Sw3NtPrepareComplete PROC
		push ebp
		mov ebp, esp
		push 03A933430h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03A933430h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3A933430:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3A933430
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3A933430
		call do_sysenter_interrupt_3A933430
		lea esp, [esp+4]
	ret_address_epilog_3A933430:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3A933430:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrepareComplete ENDP

Sw3NtPrepareEnlistment PROC
		push ebp
		mov ebp, esp
		push 0D255EDFEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D255EDFEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_D255EDFE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D255EDFE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D255EDFE
		call do_sysenter_interrupt_D255EDFE
		lea esp, [esp+4]
	ret_address_epilog_D255EDFE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D255EDFE:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrepareEnlistment ENDP

Sw3NtPrivilegeCheck PROC
		push ebp
		mov ebp, esp
		push 0009F0901h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0009F0901h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_009F0901:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_009F0901
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_009F0901
		call do_sysenter_interrupt_009F0901
		lea esp, [esp+4]
	ret_address_epilog_009F0901:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_009F0901:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrivilegeCheck ENDP

Sw3NtPrivilegeObjectAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 026983E16h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 026983E16h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_26983E16:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_26983E16
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_26983E16
		call do_sysenter_interrupt_26983E16
		lea esp, [esp+4]
	ret_address_epilog_26983E16:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_26983E16:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrivilegeObjectAuditAlarm ENDP

Sw3NtPrivilegedServiceAuditAlarm PROC
		push ebp
		mov ebp, esp
		push 0AEA1A03Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AEA1A03Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_AEA1A03C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AEA1A03C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AEA1A03C
		call do_sysenter_interrupt_AEA1A03C
		lea esp, [esp+4]
	ret_address_epilog_AEA1A03C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AEA1A03C:
		mov edx, esp
		jmp edi
		ret
Sw3NtPrivilegedServiceAuditAlarm ENDP

Sw3NtPropagationComplete PROC
		push ebp
		mov ebp, esp
		push 02E97489Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02E97489Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_2E97489C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2E97489C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2E97489C
		call do_sysenter_interrupt_2E97489C
		lea esp, [esp+4]
	ret_address_epilog_2E97489C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2E97489C:
		mov edx, esp
		jmp edi
		ret
Sw3NtPropagationComplete ENDP

Sw3NtPropagationFailed PROC
		push ebp
		mov ebp, esp
		push 0FA22CAFEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FA22CAFEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_FA22CAFE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FA22CAFE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FA22CAFE
		call do_sysenter_interrupt_FA22CAFE
		lea esp, [esp+4]
	ret_address_epilog_FA22CAFE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FA22CAFE:
		mov edx, esp
		jmp edi
		ret
Sw3NtPropagationFailed ENDP

Sw3NtPulseEvent PROC
		push ebp
		mov ebp, esp
		push 058C14742h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 058C14742h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_58C14742:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_58C14742
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_58C14742
		call do_sysenter_interrupt_58C14742
		lea esp, [esp+4]
	ret_address_epilog_58C14742:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_58C14742:
		mov edx, esp
		jmp edi
		ret
Sw3NtPulseEvent ENDP

Sw3NtQueryAuxiliaryCounterFrequency PROC
		push ebp
		mov ebp, esp
		push 03685CFFBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03685CFFBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_3685CFFB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3685CFFB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3685CFFB
		call do_sysenter_interrupt_3685CFFB
		lea esp, [esp+4]
	ret_address_epilog_3685CFFB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3685CFFB:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryAuxiliaryCounterFrequency ENDP

Sw3NtQueryBootEntryOrder PROC
		push ebp
		mov ebp, esp
		push 0070A019Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0070A019Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_070A019F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_070A019F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_070A019F
		call do_sysenter_interrupt_070A019F
		lea esp, [esp+4]
	ret_address_epilog_070A019F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_070A019F:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryBootEntryOrder ENDP

Sw3NtQueryBootOptions PROC
		push ebp
		mov ebp, esp
		push 0541B528Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0541B528Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_541B528D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_541B528D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_541B528D
		call do_sysenter_interrupt_541B528D
		lea esp, [esp+4]
	ret_address_epilog_541B528D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_541B528D:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryBootOptions ENDP

Sw3NtQueryDebugFilterState PROC
		push ebp
		mov ebp, esp
		push 0CE94F858h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CE94F858h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_CE94F858:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CE94F858
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CE94F858
		call do_sysenter_interrupt_CE94F858
		lea esp, [esp+4]
	ret_address_epilog_CE94F858:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CE94F858:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDebugFilterState ENDP

Sw3NtQueryDirectoryFileEx PROC
		push ebp
		mov ebp, esp
		push 01A3942F8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01A3942F8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 0ah
	push_argument_1A3942F8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1A3942F8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1A3942F8
		call do_sysenter_interrupt_1A3942F8
		lea esp, [esp+4]
	ret_address_epilog_1A3942F8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1A3942F8:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDirectoryFileEx ENDP

Sw3NtQueryDirectoryObject PROC
		push ebp
		mov ebp, esp
		push 01880121Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01880121Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_1880121D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1880121D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1880121D
		call do_sysenter_interrupt_1880121D
		lea esp, [esp+4]
	ret_address_epilog_1880121D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1880121D:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDirectoryObject ENDP

Sw3NtQueryDriverEntryOrder PROC
		push ebp
		mov ebp, esp
		push 01FBC6939h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01FBC6939h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_1FBC6939:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1FBC6939
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1FBC6939
		call do_sysenter_interrupt_1FBC6939
		lea esp, [esp+4]
	ret_address_epilog_1FBC6939:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1FBC6939:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryDriverEntryOrder ENDP

Sw3NtQueryEaFile PROC
		push ebp
		mov ebp, esp
		push 02EB84A62h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02EB84A62h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_2EB84A62:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2EB84A62
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2EB84A62
		call do_sysenter_interrupt_2EB84A62
		lea esp, [esp+4]
	ret_address_epilog_2EB84A62:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2EB84A62:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryEaFile ENDP

Sw3NtQueryFullAttributesFile PROC
		push ebp
		mov ebp, esp
		push 0F279F8EEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F279F8EEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_F279F8EE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F279F8EE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F279F8EE
		call do_sysenter_interrupt_F279F8EE
		lea esp, [esp+4]
	ret_address_epilog_F279F8EE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F279F8EE:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryFullAttributesFile ENDP

Sw3NtQueryInformationAtom PROC
		push ebp
		mov ebp, esp
		push 0F16ADEFFh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F16ADEFFh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_F16ADEFF:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F16ADEFF
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F16ADEFF
		call do_sysenter_interrupt_F16ADEFF
		lea esp, [esp+4]
	ret_address_epilog_F16ADEFF:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F16ADEFF:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationAtom ENDP

Sw3NtQueryInformationByName PROC
		push ebp
		mov ebp, esp
		push 029963C1Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 029963C1Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_29963C1C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_29963C1C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_29963C1C
		call do_sysenter_interrupt_29963C1C
		lea esp, [esp+4]
	ret_address_epilog_29963C1C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_29963C1C:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationByName ENDP

Sw3NtQueryInformationEnlistment PROC
		push ebp
		mov ebp, esp
		push 0019F1019h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0019F1019h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_019F1019:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_019F1019
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_019F1019
		call do_sysenter_interrupt_019F1019
		lea esp, [esp+4]
	ret_address_epilog_019F1019:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_019F1019:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationEnlistment ENDP

Sw3NtQueryInformationJobObject PROC
		push ebp
		mov ebp, esp
		push 03A941419h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03A941419h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_3A941419:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3A941419
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3A941419
		call do_sysenter_interrupt_3A941419
		lea esp, [esp+4]
	ret_address_epilog_3A941419:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3A941419:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationJobObject ENDP

Sw3NtQueryInformationPort PROC
		push ebp
		mov ebp, esp
		push 020B02922h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 020B02922h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_20B02922:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_20B02922
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_20B02922
		call do_sysenter_interrupt_20B02922
		lea esp, [esp+4]
	ret_address_epilog_20B02922:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_20B02922:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationPort ENDP

Sw3NtQueryInformationResourceManager PROC
		push ebp
		mov ebp, esp
		push 0BFA0DD70h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BFA0DD70h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_BFA0DD70:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BFA0DD70
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BFA0DD70
		call do_sysenter_interrupt_BFA0DD70
		lea esp, [esp+4]
	ret_address_epilog_BFA0DD70:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BFA0DD70:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationResourceManager ENDP

Sw3NtQueryInformationTransaction PROC
		push ebp
		mov ebp, esp
		push 0D68AF41Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D68AF41Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_D68AF41F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D68AF41F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D68AF41F
		call do_sysenter_interrupt_D68AF41F
		lea esp, [esp+4]
	ret_address_epilog_D68AF41F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D68AF41F:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationTransaction ENDP

Sw3NtQueryInformationTransactionManager PROC
		push ebp
		mov ebp, esp
		push 0BDE063ACh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BDE063ACh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_BDE063AC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BDE063AC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BDE063AC
		call do_sysenter_interrupt_BDE063AC
		lea esp, [esp+4]
	ret_address_epilog_BDE063AC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BDE063AC:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationTransactionManager ENDP

Sw3NtQueryInformationWorkerFactory PROC
		push ebp
		mov ebp, esp
		push 0C89DF852h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C89DF852h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_C89DF852:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C89DF852
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C89DF852
		call do_sysenter_interrupt_C89DF852
		lea esp, [esp+4]
	ret_address_epilog_C89DF852:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C89DF852:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInformationWorkerFactory ENDP

Sw3NtQueryInstallUILanguage PROC
		push ebp
		mov ebp, esp
		push 0FD4F220Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FD4F220Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_FD4F220E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FD4F220E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FD4F220E
		call do_sysenter_interrupt_FD4F220E
		lea esp, [esp+4]
	ret_address_epilog_FD4F220E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FD4F220E:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryInstallUILanguage ENDP

Sw3NtQueryIntervalProfile PROC
		push ebp
		mov ebp, esp
		push 01EB9363Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01EB9363Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_1EB9363A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1EB9363A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1EB9363A
		call do_sysenter_interrupt_1EB9363A
		lea esp, [esp+4]
	ret_address_epilog_1EB9363A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1EB9363A:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryIntervalProfile ENDP

Sw3NtQueryIoCompletion PROC
		push ebp
		mov ebp, esp
		push 09D0AA580h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09D0AA580h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_9D0AA580:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9D0AA580
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9D0AA580
		call do_sysenter_interrupt_9D0AA580
		lea esp, [esp+4]
	ret_address_epilog_9D0AA580:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9D0AA580:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryIoCompletion ENDP

Sw3NtQueryLicenseValue PROC
		push ebp
		mov ebp, esp
		push 01A8E1B24h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01A8E1B24h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_1A8E1B24:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1A8E1B24
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1A8E1B24
		call do_sysenter_interrupt_1A8E1B24
		lea esp, [esp+4]
	ret_address_epilog_1A8E1B24:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1A8E1B24:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryLicenseValue ENDP

Sw3NtQueryMultipleValueKey PROC
		push ebp
		mov ebp, esp
		push 0CEBBD729h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CEBBD729h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_CEBBD729:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CEBBD729
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CEBBD729
		call do_sysenter_interrupt_CEBBD729
		lea esp, [esp+4]
	ret_address_epilog_CEBBD729:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CEBBD729:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryMultipleValueKey ENDP

Sw3NtQueryMutant PROC
		push ebp
		mov ebp, esp
		push 0E45DD79Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E45DD79Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_E45DD79A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E45DD79A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E45DD79A
		call do_sysenter_interrupt_E45DD79A
		lea esp, [esp+4]
	ret_address_epilog_E45DD79A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E45DD79A:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryMutant ENDP

Sw3NtQueryOpenSubKeys PROC
		push ebp
		mov ebp, esp
		push 03AA60F01h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03AA60F01h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3AA60F01:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3AA60F01
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3AA60F01
		call do_sysenter_interrupt_3AA60F01
		lea esp, [esp+4]
	ret_address_epilog_3AA60F01:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3AA60F01:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryOpenSubKeys ENDP

Sw3NtQueryOpenSubKeysEx PROC
		push ebp
		mov ebp, esp
		push 0C3A736DBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C3A736DBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_C3A736DB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C3A736DB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C3A736DB
		call do_sysenter_interrupt_C3A736DB
		lea esp, [esp+4]
	ret_address_epilog_C3A736DB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C3A736DB:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryOpenSubKeysEx ENDP

Sw3NtQueryPortInformationProcess PROC
		push ebp
		mov ebp, esp
		push 08A188595h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08A188595h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_8A188595:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8A188595
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8A188595
		call do_sysenter_interrupt_8A188595
		lea esp, [esp+4]
	ret_address_epilog_8A188595:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8A188595:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryPortInformationProcess ENDP

Sw3NtQueryQuotaInformationFile PROC
		push ebp
		mov ebp, esp
		push 028BC4C3Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 028BC4C3Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_28BC4C3E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_28BC4C3E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_28BC4C3E
		call do_sysenter_interrupt_28BC4C3E
		lea esp, [esp+4]
	ret_address_epilog_28BC4C3E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_28BC4C3E:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryQuotaInformationFile ENDP

Sw3NtQuerySecurityAttributesToken PROC
		push ebp
		mov ebp, esp
		push 0B124E186h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0B124E186h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_B124E186:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_B124E186
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_B124E186
		call do_sysenter_interrupt_B124E186
		lea esp, [esp+4]
	ret_address_epilog_B124E186:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_B124E186:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySecurityAttributesToken ENDP

Sw3NtQuerySecurityObject PROC
		push ebp
		mov ebp, esp
		push 0EAB4F82Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0EAB4F82Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_EAB4F82A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_EAB4F82A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_EAB4F82A
		call do_sysenter_interrupt_EAB4F82A
		lea esp, [esp+4]
	ret_address_epilog_EAB4F82A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_EAB4F82A:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySecurityObject ENDP

Sw3NtQuerySecurityPolicy PROC
		push ebp
		mov ebp, esp
		push 0849EFD60h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0849EFD60h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_849EFD60:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_849EFD60
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_849EFD60
		call do_sysenter_interrupt_849EFD60
		lea esp, [esp+4]
	ret_address_epilog_849EFD60:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_849EFD60:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySecurityPolicy ENDP

Sw3NtQuerySemaphore PROC
		push ebp
		mov ebp, esp
		push 008D86214h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 008D86214h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_08D86214:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_08D86214
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_08D86214
		call do_sysenter_interrupt_08D86214
		lea esp, [esp+4]
	ret_address_epilog_08D86214:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_08D86214:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySemaphore ENDP

Sw3NtQuerySymbolicLinkObject PROC
		push ebp
		mov ebp, esp
		push 060BD48E1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 060BD48E1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_60BD48E1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_60BD48E1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_60BD48E1
		call do_sysenter_interrupt_60BD48E1
		lea esp, [esp+4]
	ret_address_epilog_60BD48E1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_60BD48E1:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySymbolicLinkObject ENDP

Sw3NtQuerySystemEnvironmentValue PROC
		push ebp
		mov ebp, esp
		push 00E8C2F00h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00E8C2F00h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0E8C2F00:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0E8C2F00
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0E8C2F00
		call do_sysenter_interrupt_0E8C2F00
		lea esp, [esp+4]
	ret_address_epilog_0E8C2F00:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0E8C2F00:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySystemEnvironmentValue ENDP

Sw3NtQuerySystemEnvironmentValueEx PROC
		push ebp
		mov ebp, esp
		push 0238D6948h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0238D6948h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_238D6948:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_238D6948
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_238D6948
		call do_sysenter_interrupt_238D6948
		lea esp, [esp+4]
	ret_address_epilog_238D6948:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_238D6948:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySystemEnvironmentValueEx ENDP

Sw3NtQuerySystemInformationEx PROC
		push ebp
		mov ebp, esp
		push 0FA9135D7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FA9135D7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_FA9135D7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FA9135D7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FA9135D7
		call do_sysenter_interrupt_FA9135D7
		lea esp, [esp+4]
	ret_address_epilog_FA9135D7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FA9135D7:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySystemInformationEx ENDP

Sw3NtQueryTimerResolution PROC
		push ebp
		mov ebp, esp
		push 00C96F2D7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C96F2D7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_0C96F2D7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C96F2D7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C96F2D7
		call do_sysenter_interrupt_0C96F2D7
		lea esp, [esp+4]
	ret_address_epilog_0C96F2D7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C96F2D7:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryTimerResolution ENDP

Sw3NtQueryWnfStateData PROC
		push ebp
		mov ebp, esp
		push 0A239CE36h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A239CE36h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_A239CE36:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A239CE36
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A239CE36
		call do_sysenter_interrupt_A239CE36
		lea esp, [esp+4]
	ret_address_epilog_A239CE36:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A239CE36:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryWnfStateData ENDP

Sw3NtQueryWnfStateNameInformation PROC
		push ebp
		mov ebp, esp
		push 094946FD0h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 094946FD0h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_94946FD0:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_94946FD0
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_94946FD0
		call do_sysenter_interrupt_94946FD0
		lea esp, [esp+4]
	ret_address_epilog_94946FD0:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_94946FD0:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueryWnfStateNameInformation ENDP

Sw3NtQueueApcThreadEx PROC
		push ebp
		mov ebp, esp
		push 0948E24B5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0948E24B5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_948E24B5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_948E24B5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_948E24B5
		call do_sysenter_interrupt_948E24B5
		lea esp, [esp+4]
	ret_address_epilog_948E24B5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_948E24B5:
		mov edx, esp
		jmp edi
		ret
Sw3NtQueueApcThreadEx ENDP

Sw3NtRaiseException PROC
		push ebp
		mov ebp, esp
		push 004E3E673h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 004E3E673h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_04E3E673:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_04E3E673
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_04E3E673
		call do_sysenter_interrupt_04E3E673
		lea esp, [esp+4]
	ret_address_epilog_04E3E673:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_04E3E673:
		mov edx, esp
		jmp edi
		ret
Sw3NtRaiseException ENDP

Sw3NtRaiseHardError PROC
		push ebp
		mov ebp, esp
		push 005936185h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 005936185h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_05936185:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_05936185
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_05936185
		call do_sysenter_interrupt_05936185
		lea esp, [esp+4]
	ret_address_epilog_05936185:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_05936185:
		mov edx, esp
		jmp edi
		ret
Sw3NtRaiseHardError ENDP

Sw3NtReadOnlyEnlistment PROC
		push ebp
		mov ebp, esp
		push 097BA54EDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 097BA54EDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_97BA54ED:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_97BA54ED
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_97BA54ED
		call do_sysenter_interrupt_97BA54ED
		lea esp, [esp+4]
	ret_address_epilog_97BA54ED:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_97BA54ED:
		mov edx, esp
		jmp edi
		ret
Sw3NtReadOnlyEnlistment ENDP

Sw3NtRecoverEnlistment PROC
		push ebp
		mov ebp, esp
		push 00BAC083Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00BAC083Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0BAC083B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0BAC083B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0BAC083B
		call do_sysenter_interrupt_0BAC083B
		lea esp, [esp+4]
	ret_address_epilog_0BAC083B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0BAC083B:
		mov edx, esp
		jmp edi
		ret
Sw3NtRecoverEnlistment ENDP

Sw3NtRecoverResourceManager PROC
		push ebp
		mov ebp, esp
		push 087B39311h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 087B39311h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_87B39311:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_87B39311
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_87B39311
		call do_sysenter_interrupt_87B39311
		lea esp, [esp+4]
	ret_address_epilog_87B39311:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_87B39311:
		mov edx, esp
		jmp edi
		ret
Sw3NtRecoverResourceManager ENDP

Sw3NtRecoverTransactionManager PROC
		push ebp
		mov ebp, esp
		push 009B15B6Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 009B15B6Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_09B15B6A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_09B15B6A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_09B15B6A
		call do_sysenter_interrupt_09B15B6A
		lea esp, [esp+4]
	ret_address_epilog_09B15B6A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_09B15B6A:
		mov edx, esp
		jmp edi
		ret
Sw3NtRecoverTransactionManager ENDP

Sw3NtRegisterProtocolAddressInformation PROC
		push ebp
		mov ebp, esp
		push 0DC37DCA5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DC37DCA5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_DC37DCA5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DC37DCA5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DC37DCA5
		call do_sysenter_interrupt_DC37DCA5
		lea esp, [esp+4]
	ret_address_epilog_DC37DCA5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DC37DCA5:
		mov edx, esp
		jmp edi
		ret
Sw3NtRegisterProtocolAddressInformation ENDP

Sw3NtRegisterThreadTerminatePort PROC
		push ebp
		mov ebp, esp
		push 052F2411Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 052F2411Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_52F2411C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_52F2411C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_52F2411C
		call do_sysenter_interrupt_52F2411C
		lea esp, [esp+4]
	ret_address_epilog_52F2411C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_52F2411C:
		mov edx, esp
		jmp edi
		ret
Sw3NtRegisterThreadTerminatePort ENDP

Sw3NtReleaseKeyedEvent PROC
		push ebp
		mov ebp, esp
		push 04ECB6756h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 04ECB6756h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_4ECB6756:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_4ECB6756
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_4ECB6756
		call do_sysenter_interrupt_4ECB6756
		lea esp, [esp+4]
	ret_address_epilog_4ECB6756:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_4ECB6756:
		mov edx, esp
		jmp edi
		ret
Sw3NtReleaseKeyedEvent ENDP

Sw3NtReleaseWorkerFactoryWorker PROC
		push ebp
		mov ebp, esp
		push 0529A6659h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0529A6659h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_529A6659:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_529A6659
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_529A6659
		call do_sysenter_interrupt_529A6659
		lea esp, [esp+4]
	ret_address_epilog_529A6659:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_529A6659:
		mov edx, esp
		jmp edi
		ret
Sw3NtReleaseWorkerFactoryWorker ENDP

Sw3NtRemoveIoCompletionEx PROC
		push ebp
		mov ebp, esp
		push 0809322A8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0809322A8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_809322A8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_809322A8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_809322A8
		call do_sysenter_interrupt_809322A8
		lea esp, [esp+4]
	ret_address_epilog_809322A8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_809322A8:
		mov edx, esp
		jmp edi
		ret
Sw3NtRemoveIoCompletionEx ENDP

Sw3NtRemoveProcessDebug PROC
		push ebp
		mov ebp, esp
		push 09A2EA964h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09A2EA964h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_9A2EA964:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9A2EA964
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9A2EA964
		call do_sysenter_interrupt_9A2EA964
		lea esp, [esp+4]
	ret_address_epilog_9A2EA964:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9A2EA964:
		mov edx, esp
		jmp edi
		ret
Sw3NtRemoveProcessDebug ENDP

Sw3NtRenameKey PROC
		push ebp
		mov ebp, esp
		push 0FB331A68h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FB331A68h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_FB331A68:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FB331A68
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FB331A68
		call do_sysenter_interrupt_FB331A68
		lea esp, [esp+4]
	ret_address_epilog_FB331A68:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FB331A68:
		mov edx, esp
		jmp edi
		ret
Sw3NtRenameKey ENDP

Sw3NtRenameTransactionManager PROC
		push ebp
		mov ebp, esp
		push 00FB6919Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00FB6919Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0FB6919E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0FB6919E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0FB6919E
		call do_sysenter_interrupt_0FB6919E
		lea esp, [esp+4]
	ret_address_epilog_0FB6919E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0FB6919E:
		mov edx, esp
		jmp edi
		ret
Sw3NtRenameTransactionManager ENDP

Sw3NtReplaceKey PROC
		push ebp
		mov ebp, esp
		push 09D136573h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09D136573h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_9D136573:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9D136573
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9D136573
		call do_sysenter_interrupt_9D136573
		lea esp, [esp+4]
	ret_address_epilog_9D136573:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9D136573:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplaceKey ENDP

Sw3NtReplacePartitionUnit PROC
		push ebp
		mov ebp, esp
		push 006AC1806h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 006AC1806h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_06AC1806:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_06AC1806
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_06AC1806
		call do_sysenter_interrupt_06AC1806
		lea esp, [esp+4]
	ret_address_epilog_06AC1806:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_06AC1806:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplacePartitionUnit ENDP

Sw3NtReplyWaitReplyPort PROC
		push ebp
		mov ebp, esp
		push 024A92F36h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 024A92F36h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_24A92F36:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_24A92F36
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_24A92F36
		call do_sysenter_interrupt_24A92F36
		lea esp, [esp+4]
	ret_address_epilog_24A92F36:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_24A92F36:
		mov edx, esp
		jmp edi
		ret
Sw3NtReplyWaitReplyPort ENDP

Sw3NtRequestPort PROC
		push ebp
		mov ebp, esp
		push 0A0B0DEBAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A0B0DEBAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_A0B0DEBA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A0B0DEBA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A0B0DEBA
		call do_sysenter_interrupt_A0B0DEBA
		lea esp, [esp+4]
	ret_address_epilog_A0B0DEBA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A0B0DEBA:
		mov edx, esp
		jmp edi
		ret
Sw3NtRequestPort ENDP

Sw3NtResetEvent PROC
		push ebp
		mov ebp, esp
		push 0A2B8AB3Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A2B8AB3Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_A2B8AB3C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A2B8AB3C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A2B8AB3C
		call do_sysenter_interrupt_A2B8AB3C
		lea esp, [esp+4]
	ret_address_epilog_A2B8AB3C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A2B8AB3C:
		mov edx, esp
		jmp edi
		ret
Sw3NtResetEvent ENDP

Sw3NtResetWriteWatch PROC
		push ebp
		mov ebp, esp
		push 02EEF663Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02EEF663Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_2EEF663E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2EEF663E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2EEF663E
		call do_sysenter_interrupt_2EEF663E
		lea esp, [esp+4]
	ret_address_epilog_2EEF663E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2EEF663E:
		mov edx, esp
		jmp edi
		ret
Sw3NtResetWriteWatch ENDP

Sw3NtRestoreKey PROC
		push ebp
		mov ebp, esp
		push 0CD3EF69Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CD3EF69Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_CD3EF69C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CD3EF69C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CD3EF69C
		call do_sysenter_interrupt_CD3EF69C
		lea esp, [esp+4]
	ret_address_epilog_CD3EF69C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CD3EF69C:
		mov edx, esp
		jmp edi
		ret
Sw3NtRestoreKey ENDP

Sw3NtResumeProcess PROC
		push ebp
		mov ebp, esp
		push 0772B9E36h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0772B9E36h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_772B9E36:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_772B9E36
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_772B9E36
		call do_sysenter_interrupt_772B9E36
		lea esp, [esp+4]
	ret_address_epilog_772B9E36:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_772B9E36:
		mov edx, esp
		jmp edi
		ret
Sw3NtResumeProcess ENDP

Sw3NtRevertContainerImpersonation PROC
		push ebp
		mov ebp, esp
		push 0D48BF415h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D48BF415h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_D48BF415:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D48BF415
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D48BF415
		call do_sysenter_interrupt_D48BF415
		lea esp, [esp+4]
	ret_address_epilog_D48BF415:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D48BF415:
		mov edx, esp
		jmp edi
		ret
Sw3NtRevertContainerImpersonation ENDP

Sw3NtRollbackComplete PROC
		push ebp
		mov ebp, esp
		push 05921B370h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05921B370h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_5921B370:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5921B370
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5921B370
		call do_sysenter_interrupt_5921B370
		lea esp, [esp+4]
	ret_address_epilog_5921B370:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5921B370:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollbackComplete ENDP

Sw3NtRollbackEnlistment PROC
		push ebp
		mov ebp, esp
		push 013B20825h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 013B20825h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_13B20825:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_13B20825
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_13B20825
		call do_sysenter_interrupt_13B20825
		lea esp, [esp+4]
	ret_address_epilog_13B20825:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_13B20825:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollbackEnlistment ENDP

Sw3NtRollbackRegistryTransaction PROC
		push ebp
		mov ebp, esp
		push 092CC5697h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 092CC5697h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_92CC5697:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_92CC5697
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_92CC5697
		call do_sysenter_interrupt_92CC5697
		lea esp, [esp+4]
	ret_address_epilog_92CC5697:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_92CC5697:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollbackRegistryTransaction ENDP

Sw3NtRollbackTransaction PROC
		push ebp
		mov ebp, esp
		push 000AB263Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 000AB263Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_00AB263B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_00AB263B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_00AB263B
		call do_sysenter_interrupt_00AB263B
		lea esp, [esp+4]
	ret_address_epilog_00AB263B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_00AB263B:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollbackTransaction ENDP

Sw3NtRollforwardTransactionManager PROC
		push ebp
		mov ebp, esp
		push 0CE12DA8Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CE12DA8Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_CE12DA8F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CE12DA8F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CE12DA8F
		call do_sysenter_interrupt_CE12DA8F
		lea esp, [esp+4]
	ret_address_epilog_CE12DA8F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CE12DA8F:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollforwardTransactionManager ENDP

Sw3NtSaveKey PROC
		push ebp
		mov ebp, esp
		push 0FFBCDC16h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FFBCDC16h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_FFBCDC16:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FFBCDC16
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FFBCDC16
		call do_sysenter_interrupt_FFBCDC16
		lea esp, [esp+4]
	ret_address_epilog_FFBCDC16:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FFBCDC16:
		mov edx, esp
		jmp edi
		ret
Sw3NtSaveKey ENDP

Sw3NtSaveKeyEx PROC
		push ebp
		mov ebp, esp
		push 0285418DDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0285418DDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_285418DD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_285418DD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_285418DD
		call do_sysenter_interrupt_285418DD
		lea esp, [esp+4]
	ret_address_epilog_285418DD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_285418DD:
		mov edx, esp
		jmp edi
		ret
Sw3NtSaveKeyEx ENDP

Sw3NtSaveMergedKeys PROC
		push ebp
		mov ebp, esp
		push 03DE2527Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03DE2527Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_3DE2527A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3DE2527A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3DE2527A
		call do_sysenter_interrupt_3DE2527A
		lea esp, [esp+4]
	ret_address_epilog_3DE2527A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3DE2527A:
		mov edx, esp
		jmp edi
		ret
Sw3NtSaveMergedKeys ENDP

Sw3NtSecureConnectPort PROC
		push ebp
		mov ebp, esp
		push 06EF76D78h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 06EF76D78h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_6EF76D78:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_6EF76D78
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_6EF76D78
		call do_sysenter_interrupt_6EF76D78
		lea esp, [esp+4]
	ret_address_epilog_6EF76D78:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_6EF76D78:
		mov edx, esp
		jmp edi
		ret
Sw3NtSecureConnectPort ENDP

Sw3NtSerializeBoot PROC
		push ebp
		mov ebp, esp
		push 08C5DE045h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08C5DE045h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_8C5DE045:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8C5DE045
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8C5DE045
		call do_sysenter_interrupt_8C5DE045
		lea esp, [esp+4]
	ret_address_epilog_8C5DE045:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8C5DE045:
		mov edx, esp
		jmp edi
		ret
Sw3NtSerializeBoot ENDP

Sw3NtSetBootEntryOrder PROC
		push ebp
		mov ebp, esp
		push 0D3EC04B4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D3EC04B4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_D3EC04B4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D3EC04B4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D3EC04B4
		call do_sysenter_interrupt_D3EC04B4
		lea esp, [esp+4]
	ret_address_epilog_D3EC04B4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D3EC04B4:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetBootEntryOrder ENDP

Sw3NtSetBootOptions PROC
		push ebp
		mov ebp, esp
		push 01B89F899h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01B89F899h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_1B89F899:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1B89F899
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1B89F899
		call do_sysenter_interrupt_1B89F899
		lea esp, [esp+4]
	ret_address_epilog_1B89F899:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1B89F899:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetBootOptions ENDP

Sw3NtSetCachedSigningLevel PROC
		push ebp
		mov ebp, esp
		push 09CA506A8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09CA506A8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_9CA506A8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9CA506A8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9CA506A8
		call do_sysenter_interrupt_9CA506A8
		lea esp, [esp+4]
	ret_address_epilog_9CA506A8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9CA506A8:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetCachedSigningLevel ENDP

Sw3NtSetCachedSigningLevel2 PROC
		push ebp
		mov ebp, esp
		push 03439F52Ah                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03439F52Ah        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_3439F52A:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3439F52A
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3439F52A
		call do_sysenter_interrupt_3439F52A
		lea esp, [esp+4]
	ret_address_epilog_3439F52A:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3439F52A:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetCachedSigningLevel2 ENDP

Sw3NtSetContextThread PROC
		push ebp
		mov ebp, esp
		push 0F45EBCF3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F45EBCF3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_F45EBCF3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F45EBCF3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F45EBCF3
		call do_sysenter_interrupt_F45EBCF3
		lea esp, [esp+4]
	ret_address_epilog_F45EBCF3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F45EBCF3:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetContextThread ENDP

Sw3NtSetDebugFilterState PROC
		push ebp
		mov ebp, esp
		push 01C42FD0Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01C42FD0Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1C42FD0C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1C42FD0C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1C42FD0C
		call do_sysenter_interrupt_1C42FD0C
		lea esp, [esp+4]
	ret_address_epilog_1C42FD0C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1C42FD0C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetDebugFilterState ENDP

Sw3NtSetDefaultHardErrorPort PROC
		push ebp
		mov ebp, esp
		push 0E072EDE8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E072EDE8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_E072EDE8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E072EDE8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E072EDE8
		call do_sysenter_interrupt_E072EDE8
		lea esp, [esp+4]
	ret_address_epilog_E072EDE8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E072EDE8:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetDefaultHardErrorPort ENDP

Sw3NtSetDefaultLocale PROC
		push ebp
		mov ebp, esp
		push 011A28799h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 011A28799h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_11A28799:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_11A28799
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_11A28799
		call do_sysenter_interrupt_11A28799
		lea esp, [esp+4]
	ret_address_epilog_11A28799:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_11A28799:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetDefaultLocale ENDP

Sw3NtSetDefaultUILanguage PROC
		push ebp
		mov ebp, esp
		push 02FB1146Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 02FB1146Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_2FB1146C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_2FB1146C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_2FB1146C
		call do_sysenter_interrupt_2FB1146C
		lea esp, [esp+4]
	ret_address_epilog_2FB1146C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_2FB1146C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetDefaultUILanguage ENDP

Sw3NtSetDriverEntryOrder PROC
		push ebp
		mov ebp, esp
		push 0D58E8157h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D58E8157h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_D58E8157:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D58E8157
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D58E8157
		call do_sysenter_interrupt_D58E8157
		lea esp, [esp+4]
	ret_address_epilog_D58E8157:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D58E8157:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetDriverEntryOrder ENDP

Sw3NtSetEaFile PROC
		push ebp
		mov ebp, esp
		push 0793BD18Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0793BD18Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_793BD18C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_793BD18C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_793BD18C
		call do_sysenter_interrupt_793BD18C
		lea esp, [esp+4]
	ret_address_epilog_793BD18C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_793BD18C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetEaFile ENDP

Sw3NtSetHighEventPair PROC
		push ebp
		mov ebp, esp
		push 09D2EA180h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09D2EA180h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_9D2EA180:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9D2EA180
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9D2EA180
		call do_sysenter_interrupt_9D2EA180
		lea esp, [esp+4]
	ret_address_epilog_9D2EA180:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9D2EA180:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetHighEventPair ENDP

Sw3NtSetHighWaitLowEventPair PROC
		push ebp
		mov ebp, esp
		push 00C9C381Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C9C381Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_0C9C381D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C9C381D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C9C381D
		call do_sysenter_interrupt_0C9C381D
		lea esp, [esp+4]
	ret_address_epilog_0C9C381D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C9C381D:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetHighWaitLowEventPair ENDP

Sw3NtSetIRTimer PROC
		push ebp
		mov ebp, esp
		push 0279609CEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0279609CEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_279609CE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_279609CE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_279609CE
		call do_sysenter_interrupt_279609CE
		lea esp, [esp+4]
	ret_address_epilog_279609CE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_279609CE:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetIRTimer ENDP

Sw3NtSetInformationDebugObject PROC
		push ebp
		mov ebp, esp
		push 0041F9433h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0041F9433h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_041F9433:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_041F9433
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_041F9433
		call do_sysenter_interrupt_041F9433
		lea esp, [esp+4]
	ret_address_epilog_041F9433:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_041F9433:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationDebugObject ENDP

Sw3NtSetInformationEnlistment PROC
		push ebp
		mov ebp, esp
		push 01842C315h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01842C315h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_1842C315:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1842C315
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1842C315
		call do_sysenter_interrupt_1842C315
		lea esp, [esp+4]
	ret_address_epilog_1842C315:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1842C315:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationEnlistment ENDP

Sw3NtSetInformationJobObject PROC
		push ebp
		mov ebp, esp
		push 007B8E3D7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 007B8E3D7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_07B8E3D7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_07B8E3D7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_07B8E3D7
		call do_sysenter_interrupt_07B8E3D7
		lea esp, [esp+4]
	ret_address_epilog_07B8E3D7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_07B8E3D7:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationJobObject ENDP

Sw3NtSetInformationKey PROC
		push ebp
		mov ebp, esp
		push 08081AD25h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08081AD25h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_8081AD25:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8081AD25
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8081AD25
		call do_sysenter_interrupt_8081AD25
		lea esp, [esp+4]
	ret_address_epilog_8081AD25:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8081AD25:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationKey ENDP

Sw3NtSetInformationResourceManager PROC
		push ebp
		mov ebp, esp
		push 0863F0824h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0863F0824h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_863F0824:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_863F0824
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_863F0824
		call do_sysenter_interrupt_863F0824
		lea esp, [esp+4]
	ret_address_epilog_863F0824:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_863F0824:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationResourceManager ENDP

Sw3NtSetInformationSymbolicLink PROC
		push ebp
		mov ebp, esp
		push 0E2B5E62Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E2B5E62Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_E2B5E62C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E2B5E62C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E2B5E62C
		call do_sysenter_interrupt_E2B5E62C
		lea esp, [esp+4]
	ret_address_epilog_E2B5E62C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E2B5E62C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationSymbolicLink ENDP

Sw3NtSetInformationToken PROC
		push ebp
		mov ebp, esp
		push 00D2F7BACh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00D2F7BACh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0D2F7BAC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0D2F7BAC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0D2F7BAC
		call do_sysenter_interrupt_0D2F7BAC
		lea esp, [esp+4]
	ret_address_epilog_0D2F7BAC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0D2F7BAC:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationToken ENDP

Sw3NtSetInformationTransaction PROC
		push ebp
		mov ebp, esp
		push 000C8261Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 000C8261Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_00C8261D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_00C8261D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_00C8261D
		call do_sysenter_interrupt_00C8261D
		lea esp, [esp+4]
	ret_address_epilog_00C8261D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_00C8261D:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationTransaction ENDP

Sw3NtSetInformationTransactionManager PROC
		push ebp
		mov ebp, esp
		push 03C26A42Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03C26A42Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_3C26A42C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3C26A42C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3C26A42C
		call do_sysenter_interrupt_3C26A42C
		lea esp, [esp+4]
	ret_address_epilog_3C26A42C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3C26A42C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationTransactionManager ENDP

Sw3NtSetInformationVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 001A4654Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 001A4654Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_01A4654B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_01A4654B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_01A4654B
		call do_sysenter_interrupt_01A4654B
		lea esp, [esp+4]
	ret_address_epilog_01A4654B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_01A4654B:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationVirtualMemory ENDP

Sw3NtSetInformationWorkerFactory PROC
		push ebp
		mov ebp, esp
		push 08A9EFA67h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08A9EFA67h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_8A9EFA67:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8A9EFA67
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8A9EFA67
		call do_sysenter_interrupt_8A9EFA67
		lea esp, [esp+4]
	ret_address_epilog_8A9EFA67:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8A9EFA67:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationWorkerFactory ENDP

Sw3NtSetIntervalProfile PROC
		push ebp
		mov ebp, esp
		push 00CDE85C8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00CDE85C8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0CDE85C8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0CDE85C8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0CDE85C8
		call do_sysenter_interrupt_0CDE85C8
		lea esp, [esp+4]
	ret_address_epilog_0CDE85C8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0CDE85C8:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetIntervalProfile ENDP

Sw3NtSetIoCompletion PROC
		push ebp
		mov ebp, esp
		push 048922841h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 048922841h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_48922841:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_48922841
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_48922841
		call do_sysenter_interrupt_48922841
		lea esp, [esp+4]
	ret_address_epilog_48922841:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_48922841:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetIoCompletion ENDP

Sw3NtSetIoCompletionEx PROC
		push ebp
		mov ebp, esp
		push 0E0D2B208h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E0D2B208h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_E0D2B208:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E0D2B208
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E0D2B208
		call do_sysenter_interrupt_E0D2B208
		lea esp, [esp+4]
	ret_address_epilog_E0D2B208:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E0D2B208:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetIoCompletionEx ENDP

Sw3NtSetLdtEntries PROC
		push ebp
		mov ebp, esp
		push 0FEA20ADEh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FEA20ADEh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_FEA20ADE:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FEA20ADE
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FEA20ADE
		call do_sysenter_interrupt_FEA20ADE
		lea esp, [esp+4]
	ret_address_epilog_FEA20ADE:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FEA20ADE:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetLdtEntries ENDP

Sw3NtSetLowEventPair PROC
		push ebp
		mov ebp, esp
		push 0875B8DCCh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0875B8DCCh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_875B8DCC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_875B8DCC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_875B8DCC
		call do_sysenter_interrupt_875B8DCC
		lea esp, [esp+4]
	ret_address_epilog_875B8DCC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_875B8DCC:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetLowEventPair ENDP

Sw3NtSetLowWaitHighEventPair PROC
		push ebp
		mov ebp, esp
		push 0075601C6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0075601C6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_075601C6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_075601C6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_075601C6
		call do_sysenter_interrupt_075601C6
		lea esp, [esp+4]
	ret_address_epilog_075601C6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_075601C6:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetLowWaitHighEventPair ENDP

Sw3NtSetQuotaInformationFile PROC
		push ebp
		mov ebp, esp
		push 0C25B10ECh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C25B10ECh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_C25B10EC:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C25B10EC
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C25B10EC
		call do_sysenter_interrupt_C25B10EC
		lea esp, [esp+4]
	ret_address_epilog_C25B10EC:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C25B10EC:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetQuotaInformationFile ENDP

Sw3NtSetSecurityObject PROC
		push ebp
		mov ebp, esp
		push 00AB9FBD5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00AB9FBD5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_0AB9FBD5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0AB9FBD5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0AB9FBD5
		call do_sysenter_interrupt_0AB9FBD5
		lea esp, [esp+4]
	ret_address_epilog_0AB9FBD5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0AB9FBD5:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSecurityObject ENDP

Sw3NtSetSystemEnvironmentValue PROC
		push ebp
		mov ebp, esp
		push 0BC3BEB80h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BC3BEB80h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_BC3BEB80:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BC3BEB80
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BC3BEB80
		call do_sysenter_interrupt_BC3BEB80
		lea esp, [esp+4]
	ret_address_epilog_BC3BEB80:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BC3BEB80:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSystemEnvironmentValue ENDP

Sw3NtSetSystemEnvironmentValueEx PROC
		push ebp
		mov ebp, esp
		push 047BB8206h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 047BB8206h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_47BB8206:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_47BB8206
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_47BB8206
		call do_sysenter_interrupt_47BB8206
		lea esp, [esp+4]
	ret_address_epilog_47BB8206:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_47BB8206:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSystemEnvironmentValueEx ENDP

Sw3NtSetSystemInformation PROC
		push ebp
		mov ebp, esp
		push 01D831B10h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01D831B10h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1D831B10:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1D831B10
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1D831B10
		call do_sysenter_interrupt_1D831B10
		lea esp, [esp+4]
	ret_address_epilog_1D831B10:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1D831B10:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSystemInformation ENDP

Sw3NtSetSystemPowerState PROC
		push ebp
		mov ebp, esp
		push 0EF17C7DBh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0EF17C7DBh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_EF17C7DB:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_EF17C7DB
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_EF17C7DB
		call do_sysenter_interrupt_EF17C7DB
		lea esp, [esp+4]
	ret_address_epilog_EF17C7DB:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_EF17C7DB:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSystemPowerState ENDP

Sw3NtSetSystemTime PROC
		push ebp
		mov ebp, esp
		push 0222E2F84h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0222E2F84h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_222E2F84:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_222E2F84
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_222E2F84
		call do_sysenter_interrupt_222E2F84
		lea esp, [esp+4]
	ret_address_epilog_222E2F84:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_222E2F84:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetSystemTime ENDP

Sw3NtSetThreadExecutionState PROC
		push ebp
		mov ebp, esp
		push 033AD7309h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 033AD7309h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_33AD7309:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_33AD7309
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_33AD7309
		call do_sysenter_interrupt_33AD7309
		lea esp, [esp+4]
	ret_address_epilog_33AD7309:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_33AD7309:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetThreadExecutionState ENDP

Sw3NtSetTimer2 PROC
		push ebp
		mov ebp, esp
		push 0191199C7h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0191199C7h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_191199C7:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_191199C7
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_191199C7
		call do_sysenter_interrupt_191199C7
		lea esp, [esp+4]
	ret_address_epilog_191199C7:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_191199C7:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetTimer2 ENDP

Sw3NtSetTimerEx PROC
		push ebp
		mov ebp, esp
		push 0E208C4B5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E208C4B5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_E208C4B5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E208C4B5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E208C4B5
		call do_sysenter_interrupt_E208C4B5
		lea esp, [esp+4]
	ret_address_epilog_E208C4B5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E208C4B5:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetTimerEx ENDP

Sw3NtSetTimerResolution PROC
		push ebp
		mov ebp, esp
		push 00C93EC81h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C93EC81h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_0C93EC81:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C93EC81
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C93EC81
		call do_sysenter_interrupt_0C93EC81
		lea esp, [esp+4]
	ret_address_epilog_0C93EC81:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C93EC81:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetTimerResolution ENDP

Sw3NtSetUuidSeed PROC
		push ebp
		mov ebp, esp
		push 09DBF1F82h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09DBF1F82h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_9DBF1F82:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9DBF1F82
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9DBF1F82
		call do_sysenter_interrupt_9DBF1F82
		lea esp, [esp+4]
	ret_address_epilog_9DBF1F82:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9DBF1F82:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetUuidSeed ENDP

Sw3NtSetVolumeInformationFile PROC
		push ebp
		mov ebp, esp
		push 0BE16D092h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0BE16D092h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_BE16D092:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_BE16D092
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_BE16D092
		call do_sysenter_interrupt_BE16D092
		lea esp, [esp+4]
	ret_address_epilog_BE16D092:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_BE16D092:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetVolumeInformationFile ENDP

Sw3NtSetWnfProcessNotificationEvent PROC
		push ebp
		mov ebp, esp
		push 00AA10532h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00AA10532h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_0AA10532:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0AA10532
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0AA10532
		call do_sysenter_interrupt_0AA10532
		lea esp, [esp+4]
	ret_address_epilog_0AA10532:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0AA10532:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetWnfProcessNotificationEvent ENDP

Sw3NtShutdownSystem PROC
		push ebp
		mov ebp, esp
		push 01892E09Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01892E09Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_1892E09D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1892E09D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1892E09D
		call do_sysenter_interrupt_1892E09D
		lea esp, [esp+4]
	ret_address_epilog_1892E09D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1892E09D:
		mov edx, esp
		jmp edi
		ret
Sw3NtShutdownSystem ENDP

Sw3NtShutdownWorkerFactory PROC
		push ebp
		mov ebp, esp
		push 08C9EF67Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 08C9EF67Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_8C9EF67F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_8C9EF67F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_8C9EF67F
		call do_sysenter_interrupt_8C9EF67F
		lea esp, [esp+4]
	ret_address_epilog_8C9EF67F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_8C9EF67F:
		mov edx, esp
		jmp edi
		ret
Sw3NtShutdownWorkerFactory ENDP

Sw3NtSignalAndWaitForSingleObject PROC
		push ebp
		mov ebp, esp
		push 094A8BC34h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 094A8BC34h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_94A8BC34:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_94A8BC34
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_94A8BC34
		call do_sysenter_interrupt_94A8BC34
		lea esp, [esp+4]
	ret_address_epilog_94A8BC34:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_94A8BC34:
		mov edx, esp
		jmp edi
		ret
Sw3NtSignalAndWaitForSingleObject ENDP

Sw3NtSinglePhaseReject PROC
		push ebp
		mov ebp, esp
		push 00C216CBDh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00C216CBDh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0C216CBD:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0C216CBD
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0C216CBD
		call do_sysenter_interrupt_0C216CBD
		lea esp, [esp+4]
	ret_address_epilog_0C216CBD:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0C216CBD:
		mov edx, esp
		jmp edi
		ret
Sw3NtSinglePhaseReject ENDP

Sw3NtStartProfile PROC
		push ebp
		mov ebp, esp
		push 0CD53BE47h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CD53BE47h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_CD53BE47:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CD53BE47
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CD53BE47
		call do_sysenter_interrupt_CD53BE47
		lea esp, [esp+4]
	ret_address_epilog_CD53BE47:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CD53BE47:
		mov edx, esp
		jmp edi
		ret
Sw3NtStartProfile ENDP

Sw3NtStopProfile PROC
		push ebp
		mov ebp, esp
		push 0189DD2AAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0189DD2AAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_189DD2AA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_189DD2AA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_189DD2AA
		call do_sysenter_interrupt_189DD2AA
		lea esp, [esp+4]
	ret_address_epilog_189DD2AA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_189DD2AA:
		mov edx, esp
		jmp edi
		ret
Sw3NtStopProfile ENDP

Sw3NtSubscribeWnfStateChange PROC
		push ebp
		mov ebp, esp
		push 0DE4ED9D2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0DE4ED9D2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_DE4ED9D2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_DE4ED9D2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_DE4ED9D2
		call do_sysenter_interrupt_DE4ED9D2
		lea esp, [esp+4]
	ret_address_epilog_DE4ED9D2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_DE4ED9D2:
		mov edx, esp
		jmp edi
		ret
Sw3NtSubscribeWnfStateChange ENDP

Sw3NtSuspendProcess PROC
		push ebp
		mov ebp, esp
		push 0C428CFB5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0C428CFB5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_C428CFB5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_C428CFB5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_C428CFB5
		call do_sysenter_interrupt_C428CFB5
		lea esp, [esp+4]
	ret_address_epilog_C428CFB5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_C428CFB5:
		mov edx, esp
		jmp edi
		ret
Sw3NtSuspendProcess ENDP

Sw3NtSuspendThread PROC
		push ebp
		mov ebp, esp
		push 07CD66469h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07CD66469h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_7CD66469:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7CD66469
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7CD66469
		call do_sysenter_interrupt_7CD66469
		lea esp, [esp+4]
	ret_address_epilog_7CD66469:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7CD66469:
		mov edx, esp
		jmp edi
		ret
Sw3NtSuspendThread ENDP

Sw3NtSystemDebugControl PROC
		push ebp
		mov ebp, esp
		push 047972B4Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 047972B4Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_47972B4F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_47972B4F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_47972B4F
		call do_sysenter_interrupt_47972B4F
		lea esp, [esp+4]
	ret_address_epilog_47972B4F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_47972B4F:
		mov edx, esp
		jmp edi
		ret
Sw3NtSystemDebugControl ENDP

Sw3NtTerminateEnclave PROC
		push ebp
		mov ebp, esp
		push 072B4427Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 072B4427Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_72B4427E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_72B4427E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_72B4427E
		call do_sysenter_interrupt_72B4427E
		lea esp, [esp+4]
	ret_address_epilog_72B4427E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_72B4427E:
		mov edx, esp
		jmp edi
		ret
Sw3NtTerminateEnclave ENDP

Sw3NtTerminateJobObject PROC
		push ebp
		mov ebp, esp
		push 0AAB9C3A4h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AAB9C3A4h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_AAB9C3A4:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AAB9C3A4
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AAB9C3A4
		call do_sysenter_interrupt_AAB9C3A4
		lea esp, [esp+4]
	ret_address_epilog_AAB9C3A4:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AAB9C3A4:
		mov edx, esp
		jmp edi
		ret
Sw3NtTerminateJobObject ENDP

Sw3NtTestAlert PROC
		push ebp
		mov ebp, esp
		push 00E946B44h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00E946B44h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_0E946B44:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0E946B44
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0E946B44
		call do_sysenter_interrupt_0E946B44
		lea esp, [esp+4]
	ret_address_epilog_0E946B44:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0E946B44:
		mov edx, esp
		jmp edi
		ret
Sw3NtTestAlert ENDP

Sw3NtThawRegistry PROC
		push ebp
		mov ebp, esp
		push 0CC96E237h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0CC96E237h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_CC96E237:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_CC96E237
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_CC96E237
		call do_sysenter_interrupt_CC96E237
		lea esp, [esp+4]
	ret_address_epilog_CC96E237:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_CC96E237:
		mov edx, esp
		jmp edi
		ret
Sw3NtThawRegistry ENDP

Sw3NtThawTransactions PROC
		push ebp
		mov ebp, esp
		push 0FFA520F6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0FFA520F6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_FFA520F6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_FFA520F6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_FFA520F6
		call do_sysenter_interrupt_FFA520F6
		lea esp, [esp+4]
	ret_address_epilog_FFA520F6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_FFA520F6:
		mov edx, esp
		jmp edi
		ret
Sw3NtThawTransactions ENDP

Sw3NtTraceControl PROC
		push ebp
		mov ebp, esp
		push 0F7DD0CCAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F7DD0CCAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 06h
	push_argument_F7DD0CCA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F7DD0CCA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F7DD0CCA
		call do_sysenter_interrupt_F7DD0CCA
		lea esp, [esp+4]
	ret_address_epilog_F7DD0CCA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F7DD0CCA:
		mov edx, esp
		jmp edi
		ret
Sw3NtTraceControl ENDP

Sw3NtTranslateFilePath PROC
		push ebp
		mov ebp, esp
		push 036A94146h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 036A94146h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_36A94146:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_36A94146
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_36A94146
		call do_sysenter_interrupt_36A94146
		lea esp, [esp+4]
	ret_address_epilog_36A94146:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_36A94146:
		mov edx, esp
		jmp edi
		ret
Sw3NtTranslateFilePath ENDP

Sw3NtUmsThreadYield PROC
		push ebp
		mov ebp, esp
		push 03BD00443h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03BD00443h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_3BD00443:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3BD00443
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3BD00443
		call do_sysenter_interrupt_3BD00443
		lea esp, [esp+4]
	ret_address_epilog_3BD00443:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3BD00443:
		mov edx, esp
		jmp edi
		ret
Sw3NtUmsThreadYield ENDP

Sw3NtUnloadDriver PROC
		push ebp
		mov ebp, esp
		push 0329E1220h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0329E1220h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_329E1220:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_329E1220
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_329E1220
		call do_sysenter_interrupt_329E1220
		lea esp, [esp+4]
	ret_address_epilog_329E1220:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_329E1220:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnloadDriver ENDP

Sw3NtUnloadKey PROC
		push ebp
		mov ebp, esp
		push 0AB339694h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0AB339694h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_AB339694:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_AB339694
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_AB339694
		call do_sysenter_interrupt_AB339694
		lea esp, [esp+4]
	ret_address_epilog_AB339694:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_AB339694:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnloadKey ENDP

Sw3NtUnloadKey2 PROC
		push ebp
		mov ebp, esp
		push 03F98D486h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 03F98D486h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_3F98D486:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_3F98D486
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_3F98D486
		call do_sysenter_interrupt_3F98D486
		lea esp, [esp+4]
	ret_address_epilog_3F98D486:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_3F98D486:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnloadKey2 ENDP

Sw3NtUnloadKeyEx PROC
		push ebp
		mov ebp, esp
		push 089A7E95Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 089A7E95Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_89A7E95F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_89A7E95F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_89A7E95F
		call do_sysenter_interrupt_89A7E95F
		lea esp, [esp+4]
	ret_address_epilog_89A7E95F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_89A7E95F:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnloadKeyEx ENDP

Sw3NtUnlockFile PROC
		push ebp
		mov ebp, esp
		push 004851632h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 004851632h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 05h
	push_argument_04851632:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_04851632
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_04851632
		call do_sysenter_interrupt_04851632
		lea esp, [esp+4]
	ret_address_epilog_04851632:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_04851632:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnlockFile ENDP

Sw3NtUnlockVirtualMemory PROC
		push ebp
		mov ebp, esp
		push 00391150Fh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00391150Fh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_0391150F:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0391150F
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0391150F
		call do_sysenter_interrupt_0391150F
		lea esp, [esp+4]
	ret_address_epilog_0391150F:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0391150F:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnlockVirtualMemory ENDP

Sw3NtUnmapViewOfSectionEx PROC
		push ebp
		mov ebp, esp
		push 01E9D5E24h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01E9D5E24h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_1E9D5E24:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1E9D5E24
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1E9D5E24
		call do_sysenter_interrupt_1E9D5E24
		lea esp, [esp+4]
	ret_address_epilog_1E9D5E24:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1E9D5E24:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnmapViewOfSectionEx ENDP

Sw3NtUnsubscribeWnfStateChange PROC
		push ebp
		mov ebp, esp
		push 07C9FF982h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07C9FF982h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_7C9FF982:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7C9FF982
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7C9FF982
		call do_sysenter_interrupt_7C9FF982
		lea esp, [esp+4]
	ret_address_epilog_7C9FF982:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7C9FF982:
		mov edx, esp
		jmp edi
		ret
Sw3NtUnsubscribeWnfStateChange ENDP

Sw3NtUpdateWnfStateData PROC
		push ebp
		mov ebp, esp
		push 042BA31A6h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 042BA31A6h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 07h
	push_argument_42BA31A6:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_42BA31A6
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_42BA31A6
		call do_sysenter_interrupt_42BA31A6
		lea esp, [esp+4]
	ret_address_epilog_42BA31A6:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_42BA31A6:
		mov edx, esp
		jmp edi
		ret
Sw3NtUpdateWnfStateData ENDP

Sw3NtVdmControl PROC
		push ebp
		mov ebp, esp
		push 00FE00B7Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00FE00B7Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_0FE00B7B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0FE00B7B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0FE00B7B
		call do_sysenter_interrupt_0FE00B7B
		lea esp, [esp+4]
	ret_address_epilog_0FE00B7B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0FE00B7B:
		mov edx, esp
		jmp edi
		ret
Sw3NtVdmControl ENDP

Sw3NtWaitForAlertByThreadId PROC
		push ebp
		mov ebp, esp
		push 077A3EA93h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 077A3EA93h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_77A3EA93:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_77A3EA93
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_77A3EA93
		call do_sysenter_interrupt_77A3EA93
		lea esp, [esp+4]
	ret_address_epilog_77A3EA93:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_77A3EA93:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForAlertByThreadId ENDP

Sw3NtWaitForDebugEvent PROC
		push ebp
		mov ebp, esp
		push 07272E76Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 07272E76Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_7272E76B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_7272E76B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_7272E76B
		call do_sysenter_interrupt_7272E76B
		lea esp, [esp+4]
	ret_address_epilog_7272E76B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_7272E76B:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForDebugEvent ENDP

Sw3NtWaitForKeyedEvent PROC
		push ebp
		mov ebp, esp
		push 042894F18h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 042894F18h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_42894F18:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_42894F18
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_42894F18
		call do_sysenter_interrupt_42894F18
		lea esp, [esp+4]
	ret_address_epilog_42894F18:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_42894F18:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForKeyedEvent ENDP

Sw3NtWaitForWorkViaWorkerFactory PROC
		push ebp
		mov ebp, esp
		push 0988C6CF2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0988C6CF2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_988C6CF2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_988C6CF2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_988C6CF2
		call do_sysenter_interrupt_988C6CF2
		lea esp, [esp+4]
	ret_address_epilog_988C6CF2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_988C6CF2:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForWorkViaWorkerFactory ENDP

Sw3NtWaitHighEventPair PROC
		push ebp
		mov ebp, esp
		push 0D9B63FE1h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0D9B63FE1h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_D9B63FE1:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_D9B63FE1
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_D9B63FE1
		call do_sysenter_interrupt_D9B63FE1
		lea esp, [esp+4]
	ret_address_epilog_D9B63FE1:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_D9B63FE1:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitHighEventPair ENDP

Sw3NtWaitLowEventPair PROC
		push ebp
		mov ebp, esp
		push 0F0B21525h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0F0B21525h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_F0B21525:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_F0B21525
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_F0B21525
		call do_sysenter_interrupt_F0B21525
		lea esp, [esp+4]
	ret_address_epilog_F0B21525:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_F0B21525:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitLowEventPair ENDP

Sw3NtAcquireCMFViewOwnership PROC
		push ebp
		mov ebp, esp
		push 0684C0CD9h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0684C0CD9h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_684C0CD9:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_684C0CD9
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_684C0CD9
		call do_sysenter_interrupt_684C0CD9
		lea esp, [esp+4]
	ret_address_epilog_684C0CD9:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_684C0CD9:
		mov edx, esp
		jmp edi
		ret
Sw3NtAcquireCMFViewOwnership ENDP

Sw3NtCancelDeviceWakeupRequest PROC
		push ebp
		mov ebp, esp
		push 013991D02h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 013991D02h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_13991D02:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_13991D02
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_13991D02
		call do_sysenter_interrupt_13991D02
		lea esp, [esp+4]
	ret_address_epilog_13991D02:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_13991D02:
		mov edx, esp
		jmp edi
		ret
Sw3NtCancelDeviceWakeupRequest ENDP

Sw3NtClearAllSavepointsTransaction PROC
		push ebp
		mov ebp, esp
		push 09C17DCC5h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09C17DCC5h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_9C17DCC5:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9C17DCC5
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9C17DCC5
		call do_sysenter_interrupt_9C17DCC5
		lea esp, [esp+4]
	ret_address_epilog_9C17DCC5:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9C17DCC5:
		mov edx, esp
		jmp edi
		ret
Sw3NtClearAllSavepointsTransaction ENDP

Sw3NtClearSavepointTransaction PROC
		push ebp
		mov ebp, esp
		push 04689005Dh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 04689005Dh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_4689005D:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_4689005D
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_4689005D
		call do_sysenter_interrupt_4689005D
		lea esp, [esp+4]
	ret_address_epilog_4689005D:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_4689005D:
		mov edx, esp
		jmp edi
		ret
Sw3NtClearSavepointTransaction ENDP

Sw3NtRollbackSavepointTransaction PROC
		push ebp
		mov ebp, esp
		push 01289321Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01289321Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_1289321B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1289321B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1289321B
		call do_sysenter_interrupt_1289321B
		lea esp, [esp+4]
	ret_address_epilog_1289321B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1289321B:
		mov edx, esp
		jmp edi
		ret
Sw3NtRollbackSavepointTransaction ENDP

Sw3NtSavepointTransaction PROC
		push ebp
		mov ebp, esp
		push 0654DBB65h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0654DBB65h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 03h
	push_argument_654DBB65:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_654DBB65
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_654DBB65
		call do_sysenter_interrupt_654DBB65
		lea esp, [esp+4]
	ret_address_epilog_654DBB65:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_654DBB65:
		mov edx, esp
		jmp edi
		ret
Sw3NtSavepointTransaction ENDP

Sw3NtSavepointComplete PROC
		push ebp
		mov ebp, esp
		push 054B4B7FAh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 054B4B7FAh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_54B4B7FA:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_54B4B7FA
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_54B4B7FA
		call do_sysenter_interrupt_54B4B7FA
		lea esp, [esp+4]
	ret_address_epilog_54B4B7FA:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_54B4B7FA:
		mov edx, esp
		jmp edi
		ret
Sw3NtSavepointComplete ENDP

Sw3NtCreateSectionEx PROC
		push ebp
		mov ebp, esp
		push 0389EDDE3h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0389EDDE3h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 09h
	push_argument_389EDDE3:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_389EDDE3
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_389EDDE3
		call do_sysenter_interrupt_389EDDE3
		lea esp, [esp+4]
	ret_address_epilog_389EDDE3:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_389EDDE3:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateSectionEx ENDP

Sw3NtCreateCrossVmEvent PROC
		push ebp
		mov ebp, esp
		push 0025513F8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0025513F8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_025513F8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_025513F8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_025513F8
		call do_sysenter_interrupt_025513F8
		lea esp, [esp+4]
	ret_address_epilog_025513F8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_025513F8:
		mov edx, esp
		jmp edi
		ret
Sw3NtCreateCrossVmEvent ENDP

Sw3NtGetPlugPlayEvent PROC
		push ebp
		mov ebp, esp
		push 0201D158Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0201D158Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_201D158B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_201D158B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_201D158B
		call do_sysenter_interrupt_201D158B
		lea esp, [esp+4]
	ret_address_epilog_201D158B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_201D158B:
		mov edx, esp
		jmp edi
		ret
Sw3NtGetPlugPlayEvent ENDP

Sw3NtListTransactions PROC
		push ebp
		mov ebp, esp
		push 05F90510Bh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 05F90510Bh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_5F90510B:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_5F90510B
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_5F90510B
		call do_sysenter_interrupt_5F90510B
		lea esp, [esp+4]
	ret_address_epilog_5F90510B:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_5F90510B:
		mov edx, esp
		jmp edi
		ret
Sw3NtListTransactions ENDP

Sw3NtMarshallTransaction PROC
		push ebp
		mov ebp, esp
		push 01258C0F8h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 01258C0F8h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_1258C0F8:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_1258C0F8
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_1258C0F8
		call do_sysenter_interrupt_1258C0F8
		lea esp, [esp+4]
	ret_address_epilog_1258C0F8:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_1258C0F8:
		mov edx, esp
		jmp edi
		ret
Sw3NtMarshallTransaction ENDP

Sw3NtPullTransaction PROC
		push ebp
		mov ebp, esp
		push 0148C3259h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0148C3259h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_148C3259:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_148C3259
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_148C3259
		call do_sysenter_interrupt_148C3259
		lea esp, [esp+4]
	ret_address_epilog_148C3259:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_148C3259:
		mov edx, esp
		jmp edi
		ret
Sw3NtPullTransaction ENDP

Sw3NtReleaseCMFViewOwnership PROC
		push ebp
		mov ebp, esp
		push 0A234A4A2h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0A234A4A2h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_A234A4A2:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_A234A4A2
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_A234A4A2
		call do_sysenter_interrupt_A234A4A2
		lea esp, [esp+4]
	ret_address_epilog_A234A4A2:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_A234A4A2:
		mov edx, esp
		jmp edi
		ret
Sw3NtReleaseCMFViewOwnership ENDP

Sw3NtWaitForWnfNotifications PROC
		push ebp
		mov ebp, esp
		push 0099B2D09h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0099B2D09h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_099B2D09:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_099B2D09
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_099B2D09
		call do_sysenter_interrupt_099B2D09
		lea esp, [esp+4]
	ret_address_epilog_099B2D09:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_099B2D09:
		mov edx, esp
		jmp edi
		ret
Sw3NtWaitForWnfNotifications ENDP

Sw3NtStartTm PROC
		push ebp
		mov ebp, esp
		push 0E589D504h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E589D504h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 00h
	push_argument_E589D504:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E589D504
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E589D504
		call do_sysenter_interrupt_E589D504
		lea esp, [esp+4]
	ret_address_epilog_E589D504:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E589D504:
		mov edx, esp
		jmp edi
		ret
Sw3NtStartTm ENDP

Sw3NtSetInformationProcess PROC
		push ebp
		mov ebp, esp
		push 09D31855Ch                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 09D31855Ch        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_9D31855C:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_9D31855C
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_9D31855C
		call do_sysenter_interrupt_9D31855C
		lea esp, [esp+4]
	ret_address_epilog_9D31855C:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_9D31855C:
		mov edx, esp
		jmp edi
		ret
Sw3NtSetInformationProcess ENDP

Sw3NtRequestDeviceWakeup PROC
		push ebp
		mov ebp, esp
		push 0318B2922h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0318B2922h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_318B2922:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_318B2922
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_318B2922
		call do_sysenter_interrupt_318B2922
		lea esp, [esp+4]
	ret_address_epilog_318B2922:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_318B2922:
		mov edx, esp
		jmp edi
		ret
Sw3NtRequestDeviceWakeup ENDP

Sw3NtRequestWakeupLatency PROC
		push ebp
		mov ebp, esp
		push 00E8D1310h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 00E8D1310h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_0E8D1310:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_0E8D1310
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_0E8D1310
		call do_sysenter_interrupt_0E8D1310
		lea esp, [esp+4]
	ret_address_epilog_0E8D1310:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_0E8D1310:
		mov edx, esp
		jmp edi
		ret
Sw3NtRequestWakeupLatency ENDP

Sw3NtQuerySystemTime PROC
		push ebp
		mov ebp, esp
		push 0E3A7F600h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E3A7F600h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 01h
	push_argument_E3A7F600:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E3A7F600
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E3A7F600
		call do_sysenter_interrupt_E3A7F600
		lea esp, [esp+4]
	ret_address_epilog_E3A7F600:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E3A7F600:
		mov edx, esp
		jmp edi
		ret
Sw3NtQuerySystemTime ENDP

Sw3NtManageHotPatch PROC
		push ebp
		mov ebp, esp
		push 0E8A72700h                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E8A72700h        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 04h
	push_argument_E8A72700:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E8A72700
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E8A72700
		call do_sysenter_interrupt_E8A72700
		lea esp, [esp+4]
	ret_address_epilog_E8A72700:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E8A72700:
		mov edx, esp
		jmp edi
		ret
Sw3NtManageHotPatch ENDP

Sw3NtContinueEx PROC
		push ebp
		mov ebp, esp
		push 0E9CB972Eh                  ; Load function hash into ECX.
		call SW3_GetSyscallAddress              ; Resolve function hash into syscall offset.
		mov edi, eax                           ; Save the address of the syscall
		push 0E9CB972Eh        ; Re-Load function hash into ECX (optional).
		call SW3_GetSyscallNumber
		lea esp, [esp+4]
		mov ecx, 02h
	push_argument_E9CB972E:
		dec ecx
		push [ebp + 8 + ecx * 4]
		jnz push_argument_E9CB972E
		mov ecx, eax
		mov eax, ecx
		push ret_address_epilog_E9CB972E
		call do_sysenter_interrupt_E9CB972E
		lea esp, [esp+4]
	ret_address_epilog_E9CB972E:
		mov esp, ebp
		pop ebp
		ret
	do_sysenter_interrupt_E9CB972E:
		mov edx, esp
		jmp edi
		ret
Sw3NtContinueEx ENDP

end