#include "Syscalls.h"
#include <stdio.h>

//#define DEBUG

#define JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

#if defined(_MSC_VER)

__declspec(naked) BOOL local_is_wow64(void)
{
    __asm {
        mov eax, fs:[0xc0]
        test eax, eax
        jne wow64
        mov eax, 0
        ret
        wow64:
        mov eax, 1
        ret
    }
}


#elif defined(__GNUC__)

__declspec(naked) BOOL local_is_wow64(void)
{
    asm(
        "mov eax, fs:[0xc0] \n"
        "test eax, eax \n"
        "jne wow64 \n"
        "mov eax, 0 \n"
        "ret \n"
        "wow64: \n"
        "mov eax, 1 \n"
        "ret \n"
    );
}

#endif

#endif

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

SW3_SYSCALL_LIST SW3_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD SW3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + SW3_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;

   #ifdef _WIN64
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
   #else
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
    ULONG distance_to_syscall = 0x0f;
   #endif

  #ifdef _M_IX86
    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    if (local_is_wow64())
    {
    #ifdef DEBUG
        printf("[+] Running 32-bit app on x64 (WOW64)\n");
    #endif
        return NULL;
    }
  #endif

    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = SW3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
        return SyscallAddress;
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = SW3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
        #if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
        #endif
            return SyscallAddress;
        }
    }

#ifdef DEBUG
    printf("Syscall Opcodes not found!\n");
#endif

    return NULL;
}
#endif


BOOL SW3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (SW3_SyscallList.Count) return TRUE;

    #ifdef _WIN64
    PSW3_PEB Peb = (PSW3_PEB)__readgsqword(0x60);
    #else
    PSW3_PEB Peb = (PSW3_PEB)__readfsdword(0x30);
    #endif
    PSW3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PSW3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = SW3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate SW3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PSW3_SYSCALL_ENTRY Entries = SW3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = SW3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(SW3_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == SW3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    SW3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < SW3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < SW3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                SW3_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD SW3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID SW3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < SW3_SyscallList.Count; i++)
    {
        if (FunctionHash == SW3_SyscallList.Entries[i].Hash)
        {
            return SW3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID SW3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure SW3_SyscallList is populated.
    if (!SW3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD) rand()) % SW3_SyscallList.Count;

    while (FunctionHash == SW3_SyscallList.Entries[index].Hash){
        // Spoofing the syscall return address
        index = ((DWORD) rand()) % SW3_SyscallList.Count;
    }
    return SW3_SyscallList.Entries[index].SyscallAddress;
}
#if defined(__GNUC__)

__declspec(naked) NTSTATUS Sw3NtAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x84194C45 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x84194C45 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x84194C45 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x84194C45 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_84194C45: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_84194C45 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_84194C45] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_84194C45 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_84194C45: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_84194C45: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x17AB350D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x17AB350D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x17AB350D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x17AB350D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_17AB350D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_17AB350D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_17AB350D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_17AB350D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_17AB350D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_17AB350D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26B13D1E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26B13D1E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26B13D1E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26B13D1E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_26B13D1E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26B13D1E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26B13D1E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26B13D1E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26B13D1E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26B13D1E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x39A00711 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x39A00711 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x39A00711 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x39A00711 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_39A00711: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_39A00711 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_39A00711] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_39A00711 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_39A00711: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_39A00711: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1AB45459 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AB45459 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AB45459 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AB45459 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1AB45459: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AB45459 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AB45459] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AB45459 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AB45459: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AB45459: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3AA018F4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AA018F4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AA018F4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AA018F4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3AA018F4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AA018F4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AA018F4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AA018F4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AA018F4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AA018F4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2285D3DF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2285D3DF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2285D3DF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2285D3DF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_2285D3DF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2285D3DF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2285D3DF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2285D3DF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2285D3DF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2285D3DF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3CE62662 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3CE62662 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3CE62662 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3CE62662 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_3CE62662: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3CE62662 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3CE62662] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3CE62662 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3CE62662: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3CE62662: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x203BBE0A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x203BBE0A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x203BBE0A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x203BBE0A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_203BBE0A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_203BBE0A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_203BBE0A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_203BBE0A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_203BBE0A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_203BBE0A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x14823411 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14823411 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14823411 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14823411 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_14823411: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14823411 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14823411] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14823411 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14823411: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14823411: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD847F48E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD847F48E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD847F48E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD847F48E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_D847F48E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D847F48E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D847F48E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D847F48E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D847F48E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D847F48E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA4F022E3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA4F022E3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA4F022E3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA4F022E3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_A4F022E3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A4F022E3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A4F022E3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A4F022E3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A4F022E3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A4F022E3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5C38A756 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5C38A756 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5C38A756 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5C38A756 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_5C38A756: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5C38A756 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5C38A756] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5C38A756 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5C38A756: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5C38A756: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3E06FB3F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3E06FB3F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3E06FB3F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3E06FB3F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3E06FB3F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3E06FB3F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3E06FB3F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3E06FB3F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3E06FB3F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3E06FB3F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6F534EE6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6F534EE6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6F534EE6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6F534EE6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6F534EE6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6F534EE6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6F534EE6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6F534EE6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6F534EE6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6F534EE6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClose(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD495D53C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD495D53C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD495D53C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD495D53C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D495D53C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D495D53C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D495D53C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D495D53C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D495D53C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D495D53C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x12248724 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12248724 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12248724 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12248724 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_12248724: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12248724 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12248724] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12248724 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12248724: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12248724: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE55C2FE9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE55C2FE9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE55C2FE9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE55C2FE9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E55C2FE9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E55C2FE9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E55C2FE9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E55C2FE9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E55C2FE9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E55C2FE9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x01142289 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01142289 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01142289 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01142289 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_01142289: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01142289 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01142289] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01142289 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01142289: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01142289: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5DAD5A30 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5DAD5A30 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5DAD5A30 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5DAD5A30 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_5DAD5A30: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5DAD5A30 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5DAD5A30] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5DAD5A30 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5DAD5A30: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5DAD5A30: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD4B954A7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD4B954A7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD4B954A7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD4B954A7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_D4B954A7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D4B954A7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D4B954A7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D4B954A7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D4B954A7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D4B954A7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x013E9405 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x013E9405 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x013E9405 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x013E9405 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_013E9405: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_013E9405 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_013E9405] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_013E9405 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_013E9405: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_013E9405: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x36EFCA98 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36EFCA98 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36EFCA98 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36EFCA98 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_36EFCA98: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36EFCA98 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36EFCA98] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36EFCA98 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36EFCA98: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36EFCA98: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD51FE8A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD51FE8A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD51FE8A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD51FE8A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_D51FE8A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D51FE8A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D51FE8A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D51FE8A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D51FE8A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D51FE8A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1F890917 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F890917 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F890917 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F890917 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1F890917: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F890917 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F890917] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F890917 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F890917: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F890917: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D108090 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D108090 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D108090 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D108090 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9D108090: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D108090 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D108090] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D108090 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D108090: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D108090: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB29C100C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB29C100C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB29C100C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB29C100C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_B29C100C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B29C100C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B29C100C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B29C100C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B29C100C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B29C100C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x57C02D4D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x57C02D4D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x57C02D4D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x57C02D4D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_57C02D4D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_57C02D4D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_57C02D4D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_57C02D4D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_57C02D4D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_57C02D4D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE912D2A0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE912D2A0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE912D2A0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE912D2A0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_E912D2A0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E912D2A0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E912D2A0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E912D2A0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E912D2A0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E912D2A0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x01AC0D2B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01AC0D2B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01AC0D2B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01AC0D2B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_01AC0D2B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01AC0D2B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01AC0D2B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01AC0D2B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01AC0D2B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01AC0D2B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2CB71778 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CB71778 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CB71778 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CB71778 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2CB71778: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CB71778 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CB71778] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CB71778 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CB71778: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CB71778: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB731515B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB731515B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB731515B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB731515B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B731515B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B731515B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B731515B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B731515B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B731515B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B731515B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D9EFF9A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D9EFF9A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D9EFF9A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D9EFF9A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0D9EFF9A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D9EFF9A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D9EFF9A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D9EFF9A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D9EFF9A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D9EFF9A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x24B30B20 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24B30B20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24B30B20 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24B30B20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_24B30B20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24B30B20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24B30B20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24B30B20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24B30B20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24B30B20: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFDAF09D3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFDAF09D3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFDAF09D3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFDAF09D3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FDAF09D3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FDAF09D3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FDAF09D3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FDAF09D3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FDAF09D3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FDAF09D3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FD77554 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FD77554 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FD77554 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FD77554 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0FD77554: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FD77554 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FD77554] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FD77554 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FD77554: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FD77554: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x904C6265 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x904C6265 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x904C6265 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x904C6265 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_904C6265: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_904C6265 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_904C6265] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_904C6265 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_904C6265: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_904C6265: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC636C5A7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC636C5A7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC636C5A7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC636C5A7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C636C5A7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C636C5A7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C636C5A7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C636C5A7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C636C5A7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C636C5A7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3A3CCE2A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A3CCE2A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A3CCE2A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A3CCE2A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_3A3CCE2A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A3CCE2A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A3CCE2A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A3CCE2A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A3CCE2A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A3CCE2A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0EA56AB7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0EA56AB7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0EA56AB7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0EA56AB7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_0EA56AB7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0EA56AB7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0EA56AB7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0EA56AB7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0EA56AB7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0EA56AB7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x18B7FBF8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18B7FBF8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18B7FBF8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18B7FBF8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_18B7FBF8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18B7FBF8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18B7FBF8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18B7FBF8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18B7FBF8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18B7FBF8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x34AB3E37 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x34AB3E37 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x34AB3E37 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x34AB3E37 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_34AB3E37: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_34AB3E37 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_34AB3E37] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_34AB3E37 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_34AB3E37: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_34AB3E37: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E1258CC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E1258CC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E1258CC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E1258CC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0E1258CC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E1258CC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E1258CC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E1258CC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E1258CC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E1258CC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x49A54828 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x49A54828 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x49A54828 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x49A54828 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_49A54828: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_49A54828 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_49A54828] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_49A54828 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_49A54828: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_49A54828: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEventBoostPriority(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C9A0418 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C9A0418 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C9A0418 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C9A0418 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0C9A0418: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C9A0418 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C9A0418] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C9A0418 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C9A0418: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C9A0418: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x018C0B15 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x018C0B15 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x018C0B15 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x018C0B15 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_018C0B15: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_018C0B15 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_018C0B15] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_018C0B15 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_018C0B15: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_018C0B15: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x029D41A6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x029D41A6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x029D41A6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x029D41A6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_029D41A6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_029D41A6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_029D41A6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_029D41A6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_029D41A6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_029D41A6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7B9B455E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7B9B455E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7B9B455E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7B9B455E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_7B9B455E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7B9B455E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7B9B455E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7B9B455E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7B9B455E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7B9B455E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6FDA3D1B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6FDA3D1B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6FDA3D1B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6FDA3D1B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6FDA3D1B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6FDA3D1B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6FDA3D1B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6FDA3D1B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6FDA3D1B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6FDA3D1B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE53FFC9C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE53FFC9C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE53FFC9C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE53FFC9C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_E53FFC9C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E53FFC9C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E53FFC9C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E53FFC9C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E53FFC9C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E53FFC9C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAAA4399F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAAA4399F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAAA4399F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAAA4399F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_AAA4399F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AAA4399F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AAA4399F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AAA4399F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AAA4399F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AAA4399F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x42CC0415 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x42CC0415 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x42CC0415 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x42CC0415 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_42CC0415: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_42CC0415 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_42CC0415] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_42CC0415 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_42CC0415: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_42CC0415: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x24B3B68B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24B3B68B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24B3B68B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24B3B68B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_24B3B68B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24B3B68B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24B3B68B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24B3B68B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24B3B68B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24B3B68B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04CC065D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04CC065D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04CC065D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04CC065D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_04CC065D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04CC065D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04CC065D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04CC065D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04CC065D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04CC065D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x356F31FD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x356F31FD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x356F31FD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x356F31FD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_356F31FD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_356F31FD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_356F31FD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_356F31FD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_356F31FD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_356F31FD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x086400F9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x086400F9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x086400F9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x086400F9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_086400F9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_086400F9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_086400F9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_086400F9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_086400F9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_086400F9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5FB9D499 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5FB9D499 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5FB9D499 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5FB9D499 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_5FB9D499: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5FB9D499 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5FB9D499] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5FB9D499 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5FB9D499: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5FB9D499: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x198D3F13 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x198D3F13 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x198D3F13 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x198D3F13 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_198D3F13: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_198D3F13 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_198D3F13] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_198D3F13 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_198D3F13: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_198D3F13: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02A43E2A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02A43E2A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02A43E2A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02A43E2A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_02A43E2A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02A43E2A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02A43E2A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02A43E2A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02A43E2A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02A43E2A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2B18FD3B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B18FD3B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B18FD3B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B18FD3B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_2B18FD3B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B18FD3B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B18FD3B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B18FD3B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B18FD3B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B18FD3B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3AF8163E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AF8163E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AF8163E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AF8163E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3AF8163E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AF8163E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AF8163E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AF8163E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AF8163E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AF8163E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearEvent(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xEE8CF305 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEE8CF305 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEE8CF305 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEE8CF305 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_EE8CF305: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EE8CF305 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EE8CF305] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EE8CF305 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EE8CF305: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EE8CF305: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D961905 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D961905 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D961905 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D961905 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0D961905: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D961905 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D961905] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D961905 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D961905: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D961905: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x390A189E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x390A189E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x390A189E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x390A189E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_390A189E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_390A189E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_390A189E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_390A189E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_390A189E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_390A189E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE7BFE923 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE7BFE923 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE7BFE923 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE7BFE923 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_E7BFE923: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E7BFE923 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E7BFE923] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E7BFE923 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E7BFE923: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E7BFE923: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x40592E9A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x40592E9A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x40592E9A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x40592E9A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_40592E9A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_40592E9A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_40592E9A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_40592E9A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_40592E9A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_40592E9A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE6A6876C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE6A6876C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE6A6876C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE6A6876C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E6A6876C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E6A6876C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E6A6876C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E6A6876C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E6A6876C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E6A6876C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2DCF286C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2DCF286C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2DCF286C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2DCF286C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2DCF286C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2DCF286C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2DCF286C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2DCF286C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2DCF286C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2DCF286C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38812A0F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38812A0F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38812A0F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38812A0F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_38812A0F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38812A0F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38812A0F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38812A0F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38812A0F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38812A0F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtYieldExecution()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC417E2C3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC417E2C3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC417E2C3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC417E2C3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C417E2C3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C417E2C3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C417E2C3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C417E2C3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C417E2C3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C417E2C3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x44D1690C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x44D1690C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x44D1690C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x44D1690C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_44D1690C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_44D1690C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_44D1690C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_44D1690C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_44D1690C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_44D1690C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8E0BB54C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8E0BB54C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8E0BB54C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8E0BB54C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8E0BB54C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8E0BB54C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8E0BB54C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8E0BB54C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8E0BB54C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8E0BB54C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE87E2058 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE87E2058 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE87E2058 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE87E2058 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E87E2058: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E87E2058 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E87E2058] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E87E2058 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E87E2058: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E87E2058: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDB10DB8E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB10DB8E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB10DB8E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB10DB8E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_DB10DB8E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB10DB8E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB10DB8E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB10DB8E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB10DB8E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB10DB8E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFC77D2FC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFC77D2FC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFC77D2FC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFC77D2FC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FC77D2FC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FC77D2FC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FC77D2FC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FC77D2FC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FC77D2FC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FC77D2FC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0A590EC1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0A590EC1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0A590EC1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0A590EC1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0A590EC1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0A590EC1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0A590EC1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0A590EC1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0A590EC1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0A590EC1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x018DDCD9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x018DDCD9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x018DDCD9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x018DDCD9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_018DDCD9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_018DDCD9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_018DDCD9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_018DDCD9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_018DDCD9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_018DDCD9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x08A4C28A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08A4C28A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08A4C28A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08A4C28A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_08A4C28A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08A4C28A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08A4C28A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08A4C28A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08A4C28A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08A4C28A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDDA7BDA1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDDA7BDA1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDDA7BDA1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDDA7BDA1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DDA7BDA1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DDA7BDA1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DDA7BDA1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DDA7BDA1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DDA7BDA1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DDA7BDA1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06932E3C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06932E3C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06932E3C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06932E3C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_06932E3C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06932E3C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06932E3C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06932E3C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06932E3C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06932E3C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02E9027B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02E9027B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02E9027B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02E9027B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_02E9027B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02E9027B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02E9027B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02E9027B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02E9027B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02E9027B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6C4EBE7F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6C4EBE7F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6C4EBE7F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6C4EBE7F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6C4EBE7F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6C4EBE7F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6C4EBE7F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6C4EBE7F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6C4EBE7F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6C4EBE7F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x56E22C5B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x56E22C5B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x56E22C5B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x56E22C5B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_56E22C5B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_56E22C5B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_56E22C5B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_56E22C5B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_56E22C5B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_56E22C5B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x934B7F07 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x934B7F07 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x934B7F07 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x934B7F07 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_934B7F07: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_934B7F07 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_934B7F07] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_934B7F07 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_934B7F07: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_934B7F07: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5EB57672 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5EB57672 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5EB57672 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5EB57672 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_5EB57672: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5EB57672 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5EB57672] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5EB57672 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5EB57672: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5EB57672: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE0DA953A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE0DA953A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE0DA953A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE0DA953A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E0DA953A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E0DA953A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E0DA953A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E0DA953A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E0DA953A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E0DA953A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA301D18F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA301D18F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA301D18F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA301D18F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A301D18F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A301D18F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A301D18F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A301D18F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A301D18F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A301D18F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9BB1A90F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9BB1A90F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9BB1A90F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9BB1A90F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_9BB1A90F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9BB1A90F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9BB1A90F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9BB1A90F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9BB1A90F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9BB1A90F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x96919038 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x96919038 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x96919038 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x96919038 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_96919038: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_96919038 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_96919038] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_96919038 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_96919038: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_96919038: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAF3399AF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAF3399AF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAF3399AF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAF3399AF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_AF3399AF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AF3399AF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AF3399AF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AF3399AF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AF3399AF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AF3399AF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E2176AD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E2176AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E2176AD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E2176AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0E2176AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E2176AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E2176AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E2176AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E2176AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E2176AD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD870D6E4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD870D6E4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD870D6E4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD870D6E4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D870D6E4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D870D6E4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D870D6E4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D870D6E4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D870D6E4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D870D6E4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF84A1E11 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF84A1E11 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF84A1E11 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF84A1E11 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F84A1E11: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F84A1E11 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F84A1E11] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F84A1E11 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F84A1E11: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F84A1E11: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1BB1633C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1BB1633C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1BB1633C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1BB1633C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1BB1633C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1BB1633C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1BB1633C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1BB1633C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1BB1633C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1BB1633C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2E1A51E1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2E1A51E1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2E1A51E1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2E1A51E1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2E1A51E1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2E1A51E1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2E1A51E1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2E1A51E1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2E1A51E1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2E1A51E1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFC4FA465 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFC4FA465 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFC4FA465 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFC4FA465 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FC4FA465: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FC4FA465 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FC4FA465] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FC4FA465 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FC4FA465: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FC4FA465: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9382698A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9382698A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9382698A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9382698A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_9382698A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9382698A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9382698A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9382698A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9382698A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9382698A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5CDB22C2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5CDB22C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5CDB22C2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5CDB22C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_5CDB22C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5CDB22C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5CDB22C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5CDB22C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5CDB22C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5CDB22C2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2D72CA61 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2D72CA61 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2D72CA61 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2D72CA61 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_2D72CA61: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2D72CA61 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2D72CA61] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2D72CA61 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2D72CA61: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2D72CA61: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x76BAA514 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76BAA514 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x76BAA514 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x76BAA514 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_76BAA514: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_76BAA514 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_76BAA514] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_76BAA514 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_76BAA514: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_76BAA514: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x49D47F46 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x49D47F46 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x49D47F46 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x49D47F46 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_49D47F46: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_49D47F46 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_49D47F46] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_49D47F46 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_49D47F46: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_49D47F46: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcquireProcessActivityReference()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF54CF3D1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF54CF3D1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF54CF3D1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF54CF3D1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_F54CF3D1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F54CF3D1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F54CF3D1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F54CF3D1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F54CF3D1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F54CF3D1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2DDCF980 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2DDCF980 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2DDCF980 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2DDCF980 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_2DDCF980: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2DDCF980 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2DDCF980] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2DDCF980 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2DDCF980: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2DDCF980: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE468ECE7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE468ECE7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE468ECE7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE468ECE7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E468ECE7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E468ECE7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E468ECE7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E468ECE7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E468ECE7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E468ECE7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4791712E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4791712E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4791712E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4791712E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4791712E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4791712E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4791712E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4791712E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4791712E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4791712E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x53965D76 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x53965D76 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x53965D76 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x53965D76 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_53965D76: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_53965D76 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_53965D76] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_53965D76 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_53965D76: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_53965D76: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1B873517 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1B873517 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1B873517 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1B873517 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_1B873517: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1B873517 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1B873517] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1B873517 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1B873517: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1B873517: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB417FEB9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB417FEB9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB417FEB9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB417FEB9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B417FEB9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B417FEB9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B417FEB9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B417FEB9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B417FEB9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B417FEB9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertThread(
	IN HANDLE ThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C56C6F8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C56C6F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C56C6F8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C56C6F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0C56C6F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C56C6F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C56C6F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C56C6F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C56C6F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C56C6F8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlertThreadByThreadId(
	IN ULONG ThreadId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x093325B3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x093325B3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x093325B3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x093325B3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_093325B3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_093325B3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_093325B3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_093325B3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_093325B3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_093325B3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateLocallyUniqueId(
	OUT PLUID Luid)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9C491F77 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9C491F77 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9C491F77 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9C491F77 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9C491F77: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9C491F77 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9C491F77] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9C491F77 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9C491F77: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9C491F77: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x785718CB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x785718CB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x785718CB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x785718CB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_785718CB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_785718CB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_785718CB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_785718CB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_785718CB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_785718CB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x09902E20 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x09902E20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x09902E20 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x09902E20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_09902E20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_09902E20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_09902E20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_09902E20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_09902E20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_09902E20: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7514A448 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7514A448 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7514A448 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7514A448 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_7514A448: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7514A448 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7514A448] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7514A448 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7514A448: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7514A448: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x189E7A75 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x189E7A75 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x189E7A75 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x189E7A75 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_189E7A75: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_189E7A75 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_189E7A75] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_189E7A75 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_189E7A75: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_189E7A75: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6EF57F78 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6EF57F78 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6EF57F78 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6EF57F78 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_6EF57F78: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6EF57F78 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6EF57F78] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6EF57F78 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6EF57F78: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6EF57F78: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x138E2016 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x138E2016 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x138E2016 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x138E2016 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_138E2016: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_138E2016 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_138E2016] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_138E2016 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_138E2016: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_138E2016: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x66F15D5E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66F15D5E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66F15D5E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66F15D5E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_66F15D5E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66F15D5E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66F15D5E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66F15D5E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66F15D5E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66F15D5E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x23AEFFFA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x23AEFFFA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x23AEFFFA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x23AEFFFA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_23AEFFFA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_23AEFFFA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_23AEFFFA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_23AEFFFA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_23AEFFFA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_23AEFFFA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x914E96DD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x914E96DD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x914E96DD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x914E96DD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_914E96DD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_914E96DD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_914E96DD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_914E96DD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_914E96DD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_914E96DD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBF04D386 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBF04D386 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBF04D386 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBF04D386 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_BF04D386: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BF04D386 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BF04D386] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BF04D386 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BF04D386: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BF04D386: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF2AFBA82 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF2AFBA82 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF2AFBA82 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF2AFBA82 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F2AFBA82: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F2AFBA82 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F2AFBA82] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F2AFBA82 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F2AFBA82: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F2AFBA82: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDB46EEF8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB46EEF8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB46EEF8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB46EEF8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DB46EEF8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB46EEF8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB46EEF8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB46EEF8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB46EEF8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB46EEF8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFE67E3F6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFE67E3F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFE67E3F6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFE67E3F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FE67E3F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FE67E3F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FE67E3F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FE67E3F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FE67E3F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FE67E3F6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1A2EFD76 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A2EFD76 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A2EFD76 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A2EFD76 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1A2EFD76: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A2EFD76 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A2EFD76] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A2EFD76 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A2EFD76: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A2EFD76: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x632C876D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x632C876D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x632C876D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x632C876D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_632C876D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_632C876D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_632C876D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_632C876D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_632C876D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_632C876D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x173172AC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x173172AC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x173172AC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x173172AC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_173172AC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_173172AC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_173172AC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_173172AC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_173172AC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_173172AC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3772D223 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3772D223 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3772D223 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3772D223 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3772D223: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3772D223 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3772D223] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3772D223 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3772D223: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3772D223: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x63317C9A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63317C9A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63317C9A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63317C9A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_63317C9A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63317C9A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63317C9A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63317C9A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63317C9A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63317C9A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x78F2797C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78F2797C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78F2797C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78F2797C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_78F2797C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78F2797C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78F2797C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78F2797C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78F2797C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78F2797C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE57FC4D1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE57FC4D1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE57FC4D1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE57FC4D1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_E57FC4D1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E57FC4D1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E57FC4D1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E57FC4D1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E57FC4D1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E57FC4D1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x76B70D3B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76B70D3B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x76B70D3B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x76B70D3B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_76B70D3B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_76B70D3B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_76B70D3B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_76B70D3B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_76B70D3B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_76B70D3B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFD59BDFD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFD59BDFD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFD59BDFD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFD59BDFD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FD59BDFD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FD59BDFD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FD59BDFD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FD59BDFD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FD59BDFD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FD59BDFD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0F92EAC0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0F92EAC0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0F92EAC0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0F92EAC0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0F92EAC0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0F92EAC0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0F92EAC0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0F92EAC0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0F92EAC0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0F92EAC0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6FCB5E10 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6FCB5E10 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6FCB5E10 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6FCB5E10 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_6FCB5E10: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6FCB5E10 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6FCB5E10] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6FCB5E10 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6FCB5E10: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6FCB5E10: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x568A4902 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x568A4902 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x568A4902 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x568A4902 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_568A4902: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_568A4902 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_568A4902] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_568A4902 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_568A4902: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_568A4902: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3CB1C5BC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3CB1C5BC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3CB1C5BC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3CB1C5BC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_3CB1C5BC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3CB1C5BC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3CB1C5BC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3CB1C5BC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3CB1C5BC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3CB1C5BC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x029B2007 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x029B2007 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x029B2007 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x029B2007 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_029B2007: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_029B2007 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_029B2007] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_029B2007 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_029B2007: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_029B2007: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDE223565 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE223565 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE223565 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE223565 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DE223565: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE223565 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE223565] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE223565 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE223565: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE223565: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE834EAA9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE834EAA9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE834EAA9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE834EAA9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E834EAA9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E834EAA9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E834EAA9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E834EAA9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E834EAA9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E834EAA9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x179D26D0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x179D26D0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x179D26D0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x179D26D0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_179D26D0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_179D26D0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_179D26D0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_179D26D0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_179D26D0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_179D26D0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x12B03800 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12B03800 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12B03800 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12B03800 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_12B03800: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12B03800 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12B03800] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12B03800 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12B03800: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12B03800: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8E9450C3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8E9450C3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8E9450C3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8E9450C3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8E9450C3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8E9450C3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8E9450C3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8E9450C3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8E9450C3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8E9450C3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3F9CF1BA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F9CF1BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3F9CF1BA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3F9CF1BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3F9CF1BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3F9CF1BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3F9CF1BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3F9CF1BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3F9CF1BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3F9CF1BA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x99B3866D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x99B3866D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x99B3866D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x99B3866D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_99B3866D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_99B3866D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_99B3866D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_99B3866D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_99B3866D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_99B3866D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x359B0130 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x359B0130 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x359B0130 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x359B0130 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_359B0130: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_359B0130 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_359B0130] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_359B0130 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_359B0130: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_359B0130: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCE029ABC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCE029ABC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCE029ABC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCE029ABC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CE029ABC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CE029ABC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CE029ABC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CE029ABC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CE029ABC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CE029ABC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6B264A7B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6B264A7B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6B264A7B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6B264A7B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6B264A7B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6B264A7B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6B264A7B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6B264A7B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6B264A7B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6B264A7B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x414A45DD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x414A45DD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x414A45DD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x414A45DD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_414A45DD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_414A45DD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_414A45DD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_414A45DD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_414A45DD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_414A45DD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC348FFEA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC348FFEA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC348FFEA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC348FFEA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C348FFEA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C348FFEA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C348FFEA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C348FFEA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C348FFEA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C348FFEA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB2D2BB65 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB2D2BB65 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB2D2BB65 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB2D2BB65 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B2D2BB65: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B2D2BB65 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B2D2BB65] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B2D2BB65 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B2D2BB65: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B2D2BB65: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x23A83701 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x23A83701 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x23A83701 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x23A83701 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_23A83701: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_23A83701 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_23A83701] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_23A83701 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_23A83701: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_23A83701: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x60DC2008 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x60DC2008 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x60DC2008 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x60DC2008 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_60DC2008: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_60DC2008 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_60DC2008] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_60DC2008 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_60DC2008: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_60DC2008: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6CB7085E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6CB7085E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6CB7085E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6CB7085E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_6CB7085E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6CB7085E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6CB7085E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6CB7085E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6CB7085E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6CB7085E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompleteConnectPort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6531805B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6531805B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6531805B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6531805B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_6531805B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6531805B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6531805B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6531805B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6531805B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6531805B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCompressKey(
	IN HANDLE Key)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF84DE3DD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF84DE3DD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF84DE3DD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF84DE3DD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_F84DE3DD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F84DE3DD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F84DE3DD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F84DE3DD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F84DE3DD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F84DE3DD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x20BF1F7C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x20BF1F7C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x20BF1F7C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x20BF1F7C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_20BF1F7C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_20BF1F7C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_20BF1F7C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_20BF1F7C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_20BF1F7C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_20BF1F7C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D85D5CF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D85D5CF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D85D5CF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D85D5CF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0D85D5CF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D85D5CF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D85D5CF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D85D5CF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D85D5CF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D85D5CF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAF08BD96 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAF08BD96 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAF08BD96 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAF08BD96 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_AF08BD96: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AF08BD96 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AF08BD96] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AF08BD96 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AF08BD96: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AF08BD96: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDAEB26EB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDAEB26EB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDAEB26EB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDAEB26EB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DAEB26EB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DAEB26EB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DAEB26EB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DAEB26EB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DAEB26EB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DAEB26EB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFC01B530 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFC01B530 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFC01B530 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFC01B530 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_FC01B530: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FC01B530 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FC01B530] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FC01B530 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FC01B530: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FC01B530: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5E902C58 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5E902C58 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5E902C58 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5E902C58 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_5E902C58: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5E902C58 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5E902C58] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5E902C58 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5E902C58: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5E902C58: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x51D7141D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x51D7141D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x51D7141D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x51D7141D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_51D7141D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_51D7141D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_51D7141D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_51D7141D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_51D7141D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_51D7141D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3790A697 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3790A697 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3790A697 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3790A697 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3790A697: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3790A697 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3790A697] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3790A697 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3790A697: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3790A697: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCD962FC6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD962FC6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD962FC6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD962FC6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CD962FC6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD962FC6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD962FC6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD962FC6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD962FC6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD962FC6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x40297E85 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x40297E85 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x40297E85 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x40297E85 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_40297E85: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_40297E85 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_40297E85] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_40297E85 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_40297E85: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_40297E85: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x34A14C55 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x34A14C55 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x34A14C55 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x34A14C55 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_34A14C55: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_34A14C55 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_34A14C55] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_34A14C55 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_34A14C55: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_34A14C55: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF35FD9E2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF35FD9E2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF35FD9E2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF35FD9E2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F35FD9E2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F35FD9E2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F35FD9E2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F35FD9E2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F35FD9E2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F35FD9E2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBC9F24A2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC9F24A2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC9F24A2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC9F24A2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_BC9F24A2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC9F24A2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC9F24A2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC9F24A2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC9F24A2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC9F24A2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04AC2CF8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04AC2CF8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04AC2CF8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04AC2CF8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_04AC2CF8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04AC2CF8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04AC2CF8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04AC2CF8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04AC2CF8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04AC2CF8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAC4DF4E7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAC4DF4E7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAC4DF4E7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAC4DF4E7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_AC4DF4E7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AC4DF4E7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AC4DF4E7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AC4DF4E7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AC4DF4E7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AC4DF4E7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDEC9A4DE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDEC9A4DE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDEC9A4DE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDEC9A4DE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_DEC9A4DE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DEC9A4DE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DEC9A4DE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DEC9A4DE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DEC9A4DE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DEC9A4DE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x34965906 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x34965906 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x34965906 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x34965906 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_34965906: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_34965906 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_34965906] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_34965906 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_34965906: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_34965906: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E99E88A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E99E88A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E99E88A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E99E88A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_1E99E88A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E99E88A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E99E88A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E99E88A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E99E88A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E99E88A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x29B32153 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x29B32153 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x29B32153 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x29B32153 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_29B32153: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_29B32153 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_29B32153] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_29B32153 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_29B32153: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_29B32153: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x062DC67F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x062DC67F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x062DC67F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x062DC67F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_062DC67F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_062DC67F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_062DC67F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_062DC67F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_062DC67F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_062DC67F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6AF75534 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6AF75534 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6AF75534 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6AF75534 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_6AF75534: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6AF75534 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6AF75534] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6AF75534 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6AF75534: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6AF75534: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x316914B1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x316914B1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x316914B1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x316914B1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_316914B1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_316914B1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_316914B1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_316914B1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_316914B1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_316914B1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE697E71B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE697E71B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE697E71B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE697E71B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_E697E71B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E697E71B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E697E71B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E697E71B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E697E71B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E697E71B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE9AEC72B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE9AEC72B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE9AEC72B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE9AEC72B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_E9AEC72B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E9AEC72B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E9AEC72B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E9AEC72B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E9AEC72B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E9AEC72B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2686E9C0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2686E9C0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2686E9C0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2686E9C0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_2686E9C0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2686E9C0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2686E9C0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2686E9C0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2686E9C0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2686E9C0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x148E361F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x148E361F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x148E361F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x148E361F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_148E361F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_148E361F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_148E361F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_148E361F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_148E361F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_148E361F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x02299D24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02299D24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02299D24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02299D24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_02299D24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02299D24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02299D24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02299D24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02299D24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02299D24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDA883009 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDA883009 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDA883009 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDA883009 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_DA883009: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DA883009 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DA883009] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DA883009 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DA883009: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DA883009: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x284900D5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x284900D5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x284900D5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x284900D5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_284900D5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_284900D5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_284900D5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_284900D5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_284900D5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_284900D5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD62F28A9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD62F28A9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD62F28A9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD62F28A9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_D62F28A9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D62F28A9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D62F28A9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D62F28A9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D62F28A9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D62F28A9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3D970936 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3D970936 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3D970936 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3D970936 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3D970936: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3D970936 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3D970936] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3D970936 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3D970936: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3D970936: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0BAB4C3B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BAB4C3B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BAB4C3B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BAB4C3B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0BAB4C3B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BAB4C3B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BAB4C3B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BAB4C3B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BAB4C3B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BAB4C3B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3D990D30 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3D990D30 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3D990D30 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3D990D30 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xd \n"
	"push_argument_3D990D30: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3D990D30 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3D990D30] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3D990D30 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3D990D30: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3D990D30: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38AB767C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38AB767C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38AB767C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38AB767C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_38AB767C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38AB767C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38AB767C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38AB767C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38AB767C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38AB767C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x484468D7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x484468D7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x484468D7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x484468D7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_484468D7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_484468D7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_484468D7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_484468D7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_484468D7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_484468D7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x883D9097 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x883D9097 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x883D9097 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x883D9097 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_883D9097: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_883D9097 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_883D9097] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_883D9097 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_883D9097: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_883D9097: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x82027D6F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x82027D6F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x82027D6F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x82027D6F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_82027D6F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_82027D6F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_82027D6F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_82027D6F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_82027D6F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_82027D6F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x753375A4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x753375A4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x753375A4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x753375A4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_753375A4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_753375A4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_753375A4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_753375A4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_753375A4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_753375A4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFD74F4E9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFD74F4E9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFD74F4E9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFD74F4E9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_FD74F4E9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FD74F4E9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FD74F4E9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FD74F4E9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FD74F4E9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FD74F4E9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCF1DA8C4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCF1DA8C4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCF1DA8C4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCF1DA8C4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_CF1DA8C4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CF1DA8C4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CF1DA8C4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CF1DA8C4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CF1DA8C4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CF1DA8C4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x46924E04 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x46924E04 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x46924E04 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x46924E04 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_46924E04: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_46924E04 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_46924E04] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_46924E04 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_46924E04: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_46924E04: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA23BA9A7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA23BA9A7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA23BA9A7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA23BA9A7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A23BA9A7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A23BA9A7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A23BA9A7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A23BA9A7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A23BA9A7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A23BA9A7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCA4EDDC2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCA4EDDC2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCA4EDDC2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCA4EDDC2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_CA4EDDC2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CA4EDDC2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CA4EDDC2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CA4EDDC2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CA4EDDC2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CA4EDDC2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteAtom(
	IN USHORT Atom)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x58D4A7BE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58D4A7BE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58D4A7BE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58D4A7BE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_58D4A7BE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58D4A7BE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58D4A7BE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58D4A7BE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58D4A7BE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58D4A7BE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteBootEntry(
	IN ULONG Id)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x01953DD0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01953DD0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01953DD0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01953DD0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_01953DD0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01953DD0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01953DD0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01953DD0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01953DD0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01953DD0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteDriverEntry(
	IN ULONG Id)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x29B8332A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x29B8332A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x29B8332A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x29B8332A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_29B8332A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_29B8332A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_29B8332A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_29B8332A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_29B8332A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_29B8332A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x58F3AA66 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58F3AA66 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58F3AA66 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58F3AA66 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_58F3AA66: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58F3AA66 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58F3AA66] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58F3AA66 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58F3AA66: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58F3AA66: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x75CF1C2C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x75CF1C2C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x75CF1C2C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x75CF1C2C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_75CF1C2C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_75CF1C2C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_75CF1C2C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_75CF1C2C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_75CF1C2C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_75CF1C2C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x18B7FEE6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18B7FEE6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18B7FEE6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18B7FEE6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_18B7FEE6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18B7FEE6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18B7FEE6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18B7FEE6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18B7FEE6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18B7FEE6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeletePrivateNamespace(
	IN HANDLE NamespaceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x62B27703 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x62B27703 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x62B27703 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x62B27703 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_62B27703: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_62B27703 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_62B27703] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_62B27703 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_62B27703: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_62B27703: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFD3DD8A6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFD3DD8A6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFD3DD8A6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFD3DD8A6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FD3DD8A6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FD3DD8A6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FD3DD8A6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FD3DD8A6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FD3DD8A6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FD3DD8A6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA705B1B3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA705B1B3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA705B1B3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA705B1B3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A705B1B3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A705B1B3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A705B1B3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A705B1B3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A705B1B3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A705B1B3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9EBC4E86 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9EBC4E86 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9EBC4E86 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9EBC4E86 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9EBC4E86: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9EBC4E86 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9EBC4E86] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9EBC4E86 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9EBC4E86: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9EBC4E86: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDisableLastKnownGood()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA1325B24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA1325B24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA1325B24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA1325B24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_A1325B24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A1325B24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A1325B24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A1325B24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A1325B24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A1325B24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDisplayString(
	IN PUNICODE_STRING String)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x42C25672 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x42C25672 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x42C25672 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x42C25672 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_42C25672: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_42C25672 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_42C25672] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_42C25672 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_42C25672: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_42C25672: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtDrawText(
	IN PUNICODE_STRING String)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x90D59545 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x90D59545 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x90D59545 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x90D59545 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_90D59545: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_90D59545 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_90D59545] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_90D59545 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_90D59545: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_90D59545: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnableLastKnownGood()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5B75CE7C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5B75CE7C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5B75CE7C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5B75CE7C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_5B75CE7C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5B75CE7C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5B75CE7C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5B75CE7C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5B75CE7C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5B75CE7C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF6A602CA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF6A602CA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF6A602CA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF6A602CA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F6A602CA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F6A602CA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F6A602CA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F6A602CA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F6A602CA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F6A602CA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x38AF4143 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x38AF4143 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x38AF4143 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x38AF4143 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_38AF4143: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_38AF4143 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_38AF4143] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_38AF4143 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_38AF4143: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_38AF4143: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x737E2DAB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x737E2DAB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x737E2DAB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x737E2DAB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_737E2DAB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_737E2DAB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_737E2DAB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_737E2DAB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_737E2DAB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_737E2DAB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0DC91B6A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0DC91B6A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0DC91B6A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0DC91B6A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0DC91B6A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0DC91B6A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0DC91B6A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0DC91B6A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0DC91B6A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0DC91B6A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x56827417 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x56827417 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x56827417 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x56827417 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_56827417: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_56827417 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_56827417] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_56827417 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_56827417: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_56827417: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C98080D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C98080D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C98080D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C98080D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0C98080D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C98080D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C98080D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C98080D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C98080D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C98080D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x259A1F12 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x259A1F12 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x259A1F12 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x259A1F12 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_259A1F12: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_259A1F12 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_259A1F12] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_259A1F12 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_259A1F12: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_259A1F12: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC28B0DDD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC28B0DDD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC28B0DDD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC28B0DDD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_C28B0DDD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C28B0DDD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C28B0DDD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C28B0DDD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C28B0DDD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C28B0DDD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x208BF3D0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x208BF3D0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x208BF3D0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x208BF3D0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_208BF3D0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_208BF3D0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_208BF3D0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_208BF3D0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_208BF3D0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_208BF3D0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2B89682C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B89682C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B89682C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B89682C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2B89682C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B89682C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B89682C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B89682C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B89682C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B89682C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x80205217 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x80205217 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x80205217 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x80205217 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_80205217: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_80205217 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_80205217] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_80205217 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_80205217: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_80205217: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE0C012B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE0C012B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE0C012B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE0C012B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_E0C012B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E0C012B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E0C012B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E0C012B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E0C012B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E0C012B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushProcessWriteBuffers()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x90BBB6EE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x90BBB6EE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x90BBB6EE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x90BBB6EE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_90BBB6EE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_90BBB6EE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_90BBB6EE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_90BBB6EE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_90BBB6EE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_90BBB6EE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB52ED9BB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB52ED9BB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB52ED9BB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB52ED9BB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_B52ED9BB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B52ED9BB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B52ED9BB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B52ED9BB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B52ED9BB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B52ED9BB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFlushWriteBuffer()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF85B0859 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF85B0859 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF85B0859 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF85B0859 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_F85B0859: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F85B0859 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F85B0859] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F85B0859 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F85B0859: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F85B0859: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x79DE88B0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x79DE88B0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x79DE88B0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x79DE88B0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_79DE88B0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_79DE88B0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_79DE88B0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_79DE88B0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_79DE88B0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_79DE88B0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreezeRegistry(
	IN ULONG TimeOutInSeconds)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x028C1C15 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x028C1C15 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x028C1C15 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x028C1C15 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_028C1C15: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_028C1C15 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_028C1C15] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_028C1C15 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_028C1C15: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_028C1C15: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD515F597 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD515F597 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD515F597 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD515F597 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D515F597: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D515F597 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D515F597] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D515F597 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D515F597: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D515F597: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2C9713DC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2C9713DC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2C9713DC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2C9713DC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2C9713DC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2C9713DC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2C9713DC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2C9713DC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2C9713DC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2C9713DC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFAB21EE3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFAB21EE3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFAB21EE3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFAB21EE3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FAB21EE3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FAB21EE3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FAB21EE3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FAB21EE3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FAB21EE3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FAB21EE3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x64BC5463 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64BC5463 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64BC5463 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64BC5463 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_64BC5463: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64BC5463 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64BC5463] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64BC5463 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64BC5463: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64BC5463: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCurrentProcessorNumber()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6C2B04F0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6C2B04F0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6C2B04F0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6C2B04F0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_6C2B04F0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6C2B04F0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6C2B04F0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6C2B04F0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6C2B04F0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6C2B04F0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4CD40E6E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4CD40E6E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4CD40E6E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4CD40E6E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_4CD40E6E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4CD40E6E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4CD40E6E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4CD40E6E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4CD40E6E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4CD40E6E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00AEFF2C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00AEFF2C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00AEFF2C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00AEFF2C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_00AEFF2C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00AEFF2C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00AEFF2C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00AEFF2C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00AEFF2C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00AEFF2C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8221BC8F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8221BC8F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8221BC8F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8221BC8F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8221BC8F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8221BC8F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8221BC8F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8221BC8F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8221BC8F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8221BC8F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCF31DCBE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCF31DCBE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCF31DCBE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCF31DCBE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_CF31DCBE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CF31DCBE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CF31DCBE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CF31DCBE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CF31DCBE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CF31DCBE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8C69CEC7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8C69CEC7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8C69CEC7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8C69CEC7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8C69CEC7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8C69CEC7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8C69CEC7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8C69CEC7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8C69CEC7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8C69CEC7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2B6DEF5B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B6DEF5B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B6DEF5B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B6DEF5B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_2B6DEF5B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B6DEF5B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B6DEF5B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B6DEF5B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B6DEF5B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B6DEF5B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDF87F15B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDF87F15B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDF87F15B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDF87F15B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_DF87F15B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DF87F15B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DF87F15B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DF87F15B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DF87F15B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DF87F15B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x76CB8B5E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76CB8B5E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x76CB8B5E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x76CB8B5E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_76CB8B5E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_76CB8B5E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_76CB8B5E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_76CB8B5E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_76CB8B5E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_76CB8B5E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateAnonymousToken(
	IN HANDLE ThreadHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2395B49C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2395B49C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2395B49C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2395B49C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2395B49C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2395B49C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2395B49C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2395B49C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2395B49C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2395B49C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8CA0558A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8CA0558A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8CA0558A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8CA0558A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8CA0558A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8CA0558A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8CA0558A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8CA0558A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8CA0558A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8CA0558A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x58998824 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58998824 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58998824 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58998824 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_58998824: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58998824 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58998824] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58998824 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58998824: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58998824: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xED581D3B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xED581D3B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xED581D3B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xED581D3B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_ED581D3B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ED581D3B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ED581D3B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ED581D3B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ED581D3B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ED581D3B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitializeRegistry(
	IN USHORT BootCondition)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3C90083D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3C90083D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3C90083D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3C90083D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3C90083D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3C90083D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3C90083D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3C90083D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3C90083D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3C90083D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1AB2FCE7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AB2FCE7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AB2FCE7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AB2FCE7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1AB2FCE7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AB2FCE7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AB2FCE7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AB2FCE7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AB2FCE7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AB2FCE7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsSystemResumeAutomatic()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0AF887D6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AF887D6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AF887D6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AF887D6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0AF887D6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AF887D6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AF887D6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AF887D6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AF887D6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AF887D6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtIsUILanguageComitted()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE3ADFB11 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE3ADFB11 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE3ADFB11 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE3ADFB11 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_E3ADFB11: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E3ADFB11 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E3ADFB11] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E3ADFB11 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E3ADFB11: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E3ADFB11: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDCB639E4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDCB639E4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDCB639E4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDCB639E4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DCB639E4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DCB639E4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DCB639E4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DCB639E4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DCB639E4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DCB639E4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x775D0DB2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x775D0DB2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x775D0DB2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x775D0DB2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_775D0DB2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_775D0DB2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_775D0DB2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_775D0DB2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_775D0DB2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_775D0DB2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE74FB47D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE74FB47D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE74FB47D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE74FB47D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_E74FB47D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E74FB47D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E74FB47D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E74FB47D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E74FB47D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E74FB47D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xECB8C834 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xECB8C834 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xECB8C834 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xECB8C834 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_ECB8C834: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ECB8C834 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ECB8C834] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ECB8C834 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ECB8C834: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ECB8C834: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x051D30AF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x051D30AF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x051D30AF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x051D30AF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_051D30AF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_051D30AF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_051D30AF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_051D30AF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_051D30AF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_051D30AF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAA18631F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAA18631F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAA18631F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAA18631F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_AA18631F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AA18631F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AA18631F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AA18631F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AA18631F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AA18631F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD5B206E9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD5B206E9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD5B206E9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD5B206E9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_D5B206E9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D5B206E9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D5B206E9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D5B206E9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D5B206E9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D5B206E9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x64A47610 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64A47610 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64A47610 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64A47610 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_64A47610: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64A47610 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64A47610] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64A47610 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64A47610: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64A47610: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3B244EC2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3B244EC2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3B244EC2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3B244EC2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3B244EC2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3B244EC2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3B244EC2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3B244EC2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3B244EC2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3B244EC2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockRegistryKey(
	IN HANDLE KeyHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1210378D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1210378D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1210378D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1210378D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1210378D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1210378D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1210378D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1210378D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1210378D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1210378D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x23B12923 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x23B12923 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x23B12923 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x23B12923 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_23B12923: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_23B12923 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_23B12923] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_23B12923 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_23B12923: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_23B12923: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMakePermanentObject(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA9B7DB49 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA9B7DB49 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA9B7DB49 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA9B7DB49 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A9B7DB49: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A9B7DB49 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A9B7DB49] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A9B7DB49 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A9B7DB49: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A9B7DB49: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMakeTemporaryObject(
	IN HANDLE Handle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x069A6E07 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x069A6E07 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x069A6E07 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x069A6E07 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_069A6E07: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_069A6E07 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_069A6E07] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_069A6E07 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_069A6E07: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_069A6E07: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7AE296A1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7AE296A1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7AE296A1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7AE296A1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_7AE296A1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7AE296A1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7AE296A1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7AE296A1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7AE296A1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7AE296A1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x108281B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x108281B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x108281B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x108281B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_108281B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_108281B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_108281B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_108281B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_108281B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_108281B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x99BC46FC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x99BC46FC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x99BC46FC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x99BC46FC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_99BC46FC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_99BC46FC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_99BC46FC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_99BC46FC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_99BC46FC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_99BC46FC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF8130765 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF8130765 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF8130765 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF8130765 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_F8130765: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F8130765 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F8130765] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F8130765 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F8130765: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F8130765: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtModifyBootEntry(
	IN PBOOT_ENTRY BootEntry)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x49A4C2A6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x49A4C2A6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x49A4C2A6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x49A4C2A6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_49A4C2A6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_49A4C2A6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_49A4C2A6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_49A4C2A6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_49A4C2A6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_49A4C2A6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x19A73D78 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x19A73D78 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x19A73D78 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x19A73D78 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_19A73D78: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_19A73D78 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_19A73D78] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_19A73D78 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_19A73D78: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_19A73D78: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x70DA6E62 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x70DA6E62 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x70DA6E62 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x70DA6E62 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_70DA6E62: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_70DA6E62 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_70DA6E62] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_70DA6E62 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_70DA6E62: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_70DA6E62: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0AB9CCC7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AB9CCC7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AB9CCC7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AB9CCC7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_0AB9CCC7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AB9CCC7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AB9CCC7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AB9CCC7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AB9CCC7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AB9CCC7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9F1A7F02 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9F1A7F02 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9F1A7F02 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9F1A7F02 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_9F1A7F02: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9F1A7F02 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9F1A7F02] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9F1A7F02 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9F1A7F02: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9F1A7F02: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x403BB97C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x403BB97C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x403BB97C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x403BB97C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_403BB97C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_403BB97C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_403BB97C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_403BB97C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_403BB97C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_403BB97C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x31A77D74 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x31A77D74 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x31A77D74 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x31A77D74 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_31A77D74: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_31A77D74 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_31A77D74] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_31A77D74 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_31A77D74: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_31A77D74: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x71EB041D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x71EB041D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x71EB041D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x71EB041D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_71EB041D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_71EB041D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_71EB041D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_71EB041D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_71EB041D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_71EB041D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00D50853 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00D50853 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00D50853 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00D50853 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_00D50853: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00D50853 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00D50853] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00D50853 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00D50853: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00D50853: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0AA52831 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AA52831 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AA52831 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AA52831 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0AA52831: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AA52831 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AA52831] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AA52831 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AA52831: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AA52831: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x12B8FCE5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12B8FCE5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12B8FCE5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12B8FCE5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_12B8FCE5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12B8FCE5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12B8FCE5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12B8FCE5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12B8FCE5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12B8FCE5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2B9C7F40 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B9C7F40 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B9C7F40 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B9C7F40 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_2B9C7F40: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B9C7F40 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B9C7F40] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B9C7F40 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B9C7F40: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B9C7F40: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAC80CA59 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAC80CA59 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAC80CA59 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAC80CA59 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_AC80CA59: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AC80CA59 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AC80CA59] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AC80CA59 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AC80CA59: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AC80CA59: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x60D95362 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x60D95362 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x60D95362 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x60D95362 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_60D95362: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_60D95362 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_60D95362] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_60D95362 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_60D95362: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_60D95362: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E9E2134 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E9E2134 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E9E2134 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E9E2134 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1E9E2134: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E9E2134 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E9E2134] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E9E2134 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E9E2134: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E9E2134: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8CCEAB1D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8CCEAB1D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8CCEAB1D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8CCEAB1D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8CCEAB1D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8CCEAB1D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8CCEAB1D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8CCEAB1D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8CCEAB1D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8CCEAB1D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC2A3E27D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC2A3E27D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC2A3E27D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC2A3E27D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_C2A3E27D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C2A3E27D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C2A3E27D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C2A3E27D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C2A3E27D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C2A3E27D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF26B96B1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF26B96B1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF26B96B1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF26B96B1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F26B96B1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F26B96B1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F26B96B1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F26B96B1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F26B96B1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F26B96B1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x08B2D00F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08B2D00F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08B2D00F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08B2D00F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_08B2D00F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08B2D00F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08B2D00F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08B2D00F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08B2D00F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08B2D00F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC64333D8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC64333D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC64333D8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC64333D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_C64333D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C64333D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C64333D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C64333D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C64333D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C64333D8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x84CE4396 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x84CE4396 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x84CE4396 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x84CE4396 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_84CE4396: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_84CE4396 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_84CE4396] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_84CE4396 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_84CE4396: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_84CE4396: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE25ED6E4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE25ED6E4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE25ED6E4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE25ED6E4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E25ED6E4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E25ED6E4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E25ED6E4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E25ED6E4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E25ED6E4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E25ED6E4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x46D3127C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x46D3127C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x46D3127C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x46D3127C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_46D3127C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_46D3127C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_46D3127C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_46D3127C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_46D3127C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_46D3127C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x742D52FC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x742D52FC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x742D52FC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x742D52FC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_742D52FC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_742D52FC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_742D52FC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_742D52FC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_742D52FC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_742D52FC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA837B89B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA837B89B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA837B89B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA837B89B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_A837B89B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A837B89B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A837B89B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A837B89B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A837B89B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A837B89B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB490B820 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB490B820 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB490B820 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB490B820 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_B490B820: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B490B820 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B490B820] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B490B820 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B490B820: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B490B820: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7F9898CA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7F9898CA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7F9898CA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7F9898CA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7F9898CA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7F9898CA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7F9898CA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7F9898CA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7F9898CA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7F9898CA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00C91C7B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00C91C7B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00C91C7B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00C91C7B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_00C91C7B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00C91C7B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00C91C7B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00C91C7B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00C91C7B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00C91C7B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0937C06C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0937C06C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0937C06C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0937C06C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0937C06C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0937C06C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0937C06C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0937C06C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0937C06C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0937C06C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0751C00A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0751C00A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0751C00A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0751C00A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0751C00A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0751C00A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0751C00A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0751C00A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0751C00A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0751C00A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3AB3687C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AB3687C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AB3687C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AB3687C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3AB3687C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AB3687C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AB3687C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AB3687C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AB3687C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AB3687C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FC0084B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FC0084B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FC0084B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FC0084B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0FC0084B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FC0084B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FC0084B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FC0084B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FC0084B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FC0084B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3A933430 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A933430 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A933430 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A933430 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3A933430: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A933430 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A933430] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A933430 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A933430: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A933430: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD255EDFE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD255EDFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD255EDFE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD255EDFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D255EDFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D255EDFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D255EDFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D255EDFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D255EDFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D255EDFE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x009F0901 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x009F0901 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x009F0901 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x009F0901 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_009F0901: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_009F0901 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_009F0901] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_009F0901 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_009F0901: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_009F0901: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x26983E16 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26983E16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26983E16 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26983E16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_26983E16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26983E16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26983E16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26983E16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26983E16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26983E16: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAEA1A03C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAEA1A03C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAEA1A03C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAEA1A03C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_AEA1A03C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AEA1A03C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AEA1A03C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AEA1A03C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AEA1A03C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AEA1A03C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2E97489C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2E97489C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2E97489C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2E97489C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_2E97489C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2E97489C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2E97489C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2E97489C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2E97489C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2E97489C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFA22CAFE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA22CAFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA22CAFE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA22CAFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_FA22CAFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA22CAFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA22CAFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA22CAFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA22CAFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA22CAFE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x58C14742 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58C14742 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58C14742 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58C14742 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_58C14742: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58C14742 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58C14742] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58C14742 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58C14742: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58C14742: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3685CFFB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3685CFFB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3685CFFB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3685CFFB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3685CFFB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3685CFFB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3685CFFB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3685CFFB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3685CFFB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3685CFFB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x070A019F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x070A019F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x070A019F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x070A019F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_070A019F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_070A019F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_070A019F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_070A019F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_070A019F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_070A019F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x541B528D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x541B528D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x541B528D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x541B528D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_541B528D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_541B528D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_541B528D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_541B528D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_541B528D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_541B528D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCE94F858 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCE94F858 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCE94F858 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCE94F858 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CE94F858: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CE94F858 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CE94F858] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CE94F858 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CE94F858: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CE94F858: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1A3942F8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A3942F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A3942F8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A3942F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_1A3942F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A3942F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A3942F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A3942F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A3942F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A3942F8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1880121D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1880121D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1880121D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1880121D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_1880121D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1880121D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1880121D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1880121D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1880121D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1880121D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1FBC6939 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1FBC6939 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1FBC6939 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1FBC6939 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1FBC6939: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1FBC6939 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1FBC6939] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1FBC6939 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1FBC6939: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1FBC6939: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2EB84A62 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2EB84A62 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2EB84A62 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2EB84A62 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_2EB84A62: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2EB84A62 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2EB84A62] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2EB84A62 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2EB84A62: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2EB84A62: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF279F8EE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF279F8EE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF279F8EE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF279F8EE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F279F8EE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F279F8EE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F279F8EE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F279F8EE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F279F8EE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F279F8EE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF16ADEFF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF16ADEFF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF16ADEFF \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF16ADEFF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F16ADEFF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F16ADEFF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F16ADEFF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F16ADEFF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F16ADEFF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F16ADEFF: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x29963C1C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x29963C1C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x29963C1C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x29963C1C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_29963C1C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_29963C1C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_29963C1C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_29963C1C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_29963C1C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_29963C1C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x019F1019 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x019F1019 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x019F1019 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x019F1019 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_019F1019: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_019F1019 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_019F1019] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_019F1019 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_019F1019: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_019F1019: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3A941419 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A941419 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A941419 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A941419 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_3A941419: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A941419 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A941419] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A941419 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A941419: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A941419: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x20B02922 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x20B02922 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x20B02922 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x20B02922 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_20B02922: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_20B02922 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_20B02922] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_20B02922 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_20B02922: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_20B02922: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBFA0DD70 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBFA0DD70 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBFA0DD70 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBFA0DD70 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BFA0DD70: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BFA0DD70 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BFA0DD70] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BFA0DD70 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BFA0DD70: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BFA0DD70: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD68AF41F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD68AF41F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD68AF41F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD68AF41F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_D68AF41F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D68AF41F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D68AF41F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D68AF41F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D68AF41F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D68AF41F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBDE063AC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBDE063AC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBDE063AC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBDE063AC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BDE063AC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BDE063AC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BDE063AC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BDE063AC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BDE063AC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BDE063AC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC89DF852 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC89DF852 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC89DF852 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC89DF852 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C89DF852: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C89DF852 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C89DF852] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C89DF852 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C89DF852: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C89DF852: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFD4F220E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFD4F220E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFD4F220E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFD4F220E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_FD4F220E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FD4F220E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FD4F220E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FD4F220E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FD4F220E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FD4F220E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1EB9363A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EB9363A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EB9363A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EB9363A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1EB9363A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EB9363A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EB9363A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EB9363A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EB9363A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EB9363A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D0AA580 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D0AA580 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D0AA580 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D0AA580 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9D0AA580: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D0AA580 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D0AA580] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D0AA580 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D0AA580: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D0AA580: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1A8E1B24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A8E1B24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A8E1B24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A8E1B24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1A8E1B24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A8E1B24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A8E1B24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A8E1B24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A8E1B24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A8E1B24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCEBBD729 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCEBBD729 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCEBBD729 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCEBBD729 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_CEBBD729: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CEBBD729 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CEBBD729] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CEBBD729 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CEBBD729: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CEBBD729: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE45DD79A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE45DD79A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE45DD79A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE45DD79A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E45DD79A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E45DD79A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E45DD79A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E45DD79A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E45DD79A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E45DD79A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3AA60F01 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AA60F01 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AA60F01 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AA60F01 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3AA60F01: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AA60F01 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AA60F01] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AA60F01 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AA60F01: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AA60F01: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC3A736DB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC3A736DB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC3A736DB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC3A736DB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C3A736DB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C3A736DB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C3A736DB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C3A736DB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C3A736DB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C3A736DB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryPortInformationProcess()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A188595 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A188595 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A188595 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A188595 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_8A188595: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A188595 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A188595] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A188595 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A188595: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A188595: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x28BC4C3E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x28BC4C3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x28BC4C3E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x28BC4C3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_28BC4C3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_28BC4C3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_28BC4C3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_28BC4C3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_28BC4C3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_28BC4C3E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB124E186 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB124E186 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB124E186 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB124E186 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_B124E186: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B124E186 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B124E186] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B124E186 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B124E186: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B124E186: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xEAB4F82A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEAB4F82A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEAB4F82A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEAB4F82A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_EAB4F82A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EAB4F82A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EAB4F82A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EAB4F82A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EAB4F82A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EAB4F82A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x849EFD60 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x849EFD60 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x849EFD60 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x849EFD60 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_849EFD60: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_849EFD60 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_849EFD60] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_849EFD60 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_849EFD60: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_849EFD60: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x08D86214 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08D86214 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08D86214 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08D86214 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_08D86214: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08D86214 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08D86214] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08D86214 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08D86214: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08D86214: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x60BD48E1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x60BD48E1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x60BD48E1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x60BD48E1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_60BD48E1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_60BD48E1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_60BD48E1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_60BD48E1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_60BD48E1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_60BD48E1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E8C2F00 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E8C2F00 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E8C2F00 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E8C2F00 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0E8C2F00: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E8C2F00 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E8C2F00] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E8C2F00 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E8C2F00: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E8C2F00: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x238D6948 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x238D6948 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x238D6948 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x238D6948 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_238D6948: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_238D6948 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_238D6948] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_238D6948 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_238D6948: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_238D6948: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFA9135D7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA9135D7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA9135D7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA9135D7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FA9135D7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA9135D7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA9135D7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA9135D7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA9135D7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA9135D7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C96F2D7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C96F2D7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C96F2D7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C96F2D7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0C96F2D7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C96F2D7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C96F2D7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C96F2D7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C96F2D7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C96F2D7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA239CE36 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA239CE36 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA239CE36 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA239CE36 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A239CE36: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A239CE36 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A239CE36] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A239CE36 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A239CE36: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A239CE36: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x94946FD0 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x94946FD0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x94946FD0 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x94946FD0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_94946FD0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_94946FD0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_94946FD0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_94946FD0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_94946FD0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_94946FD0: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x948E24B5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x948E24B5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x948E24B5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x948E24B5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_948E24B5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_948E24B5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_948E24B5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_948E24B5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_948E24B5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_948E24B5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04E3E673 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04E3E673 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04E3E673 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04E3E673 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_04E3E673: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04E3E673 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04E3E673] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04E3E673 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04E3E673: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04E3E673: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x05936185 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x05936185 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x05936185 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x05936185 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_05936185: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_05936185 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_05936185] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_05936185 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_05936185: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_05936185: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x97BA54ED \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x97BA54ED \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x97BA54ED \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x97BA54ED \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_97BA54ED: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_97BA54ED \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_97BA54ED] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_97BA54ED \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_97BA54ED: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_97BA54ED: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0BAC083B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BAC083B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BAC083B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BAC083B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0BAC083B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BAC083B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BAC083B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BAC083B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BAC083B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BAC083B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverResourceManager(
	IN HANDLE ResourceManagerHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x87B39311 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x87B39311 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x87B39311 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x87B39311 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_87B39311: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_87B39311 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_87B39311] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_87B39311 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_87B39311: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_87B39311: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x09B15B6A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x09B15B6A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x09B15B6A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x09B15B6A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_09B15B6A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_09B15B6A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_09B15B6A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_09B15B6A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_09B15B6A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_09B15B6A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDC37DCA5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC37DCA5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC37DCA5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC37DCA5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_DC37DCA5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC37DCA5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC37DCA5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC37DCA5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC37DCA5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC37DCA5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRegisterThreadTerminatePort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x52F2411C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x52F2411C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x52F2411C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x52F2411C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_52F2411C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_52F2411C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_52F2411C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_52F2411C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_52F2411C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_52F2411C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4ECB6756 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ECB6756 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ECB6756 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ECB6756 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_4ECB6756: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ECB6756 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ECB6756] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ECB6756 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ECB6756: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ECB6756: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x529A6659 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x529A6659 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x529A6659 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x529A6659 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_529A6659: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_529A6659 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_529A6659] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_529A6659 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_529A6659: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_529A6659: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x809322A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x809322A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x809322A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x809322A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_809322A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_809322A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_809322A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_809322A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_809322A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_809322A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9A2EA964 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9A2EA964 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9A2EA964 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9A2EA964 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_9A2EA964: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9A2EA964 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9A2EA964] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9A2EA964 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9A2EA964: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9A2EA964: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFB331A68 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFB331A68 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFB331A68 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFB331A68 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FB331A68: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FB331A68 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FB331A68] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FB331A68 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FB331A68: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FB331A68: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FB6919E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FB6919E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FB6919E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FB6919E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0FB6919E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FB6919E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FB6919E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FB6919E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FB6919E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FB6919E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D136573 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D136573 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D136573 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D136573 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_9D136573: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D136573 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D136573] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D136573 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D136573: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D136573: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x06AC1806 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06AC1806 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06AC1806 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06AC1806 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_06AC1806: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06AC1806 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06AC1806] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06AC1806 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06AC1806: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06AC1806: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x24A92F36 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24A92F36 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24A92F36 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24A92F36 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_24A92F36: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24A92F36 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24A92F36] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24A92F36 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24A92F36: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24A92F36: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA0B0DEBA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA0B0DEBA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA0B0DEBA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA0B0DEBA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A0B0DEBA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A0B0DEBA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A0B0DEBA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A0B0DEBA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A0B0DEBA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A0B0DEBA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA2B8AB3C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA2B8AB3C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA2B8AB3C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA2B8AB3C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A2B8AB3C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A2B8AB3C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A2B8AB3C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A2B8AB3C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A2B8AB3C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A2B8AB3C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2EEF663E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2EEF663E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2EEF663E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2EEF663E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_2EEF663E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2EEF663E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2EEF663E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2EEF663E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2EEF663E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2EEF663E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCD3EF69C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD3EF69C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD3EF69C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD3EF69C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_CD3EF69C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD3EF69C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD3EF69C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD3EF69C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD3EF69C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD3EF69C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeProcess(
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x772B9E36 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x772B9E36 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x772B9E36 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x772B9E36 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_772B9E36: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_772B9E36 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_772B9E36] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_772B9E36 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_772B9E36: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_772B9E36: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRevertContainerImpersonation()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD48BF415 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD48BF415 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD48BF415 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD48BF415 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_D48BF415: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D48BF415 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D48BF415] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D48BF415 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D48BF415: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D48BF415: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5921B370 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5921B370 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5921B370 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5921B370 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_5921B370: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5921B370 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5921B370] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5921B370 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5921B370: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5921B370: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x13B20825 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x13B20825 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x13B20825 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x13B20825 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_13B20825: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_13B20825 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_13B20825] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_13B20825 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_13B20825: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_13B20825: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x92CC5697 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x92CC5697 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x92CC5697 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x92CC5697 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_92CC5697: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_92CC5697 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_92CC5697] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_92CC5697 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_92CC5697: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_92CC5697: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00AB263B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00AB263B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00AB263B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00AB263B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_00AB263B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00AB263B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00AB263B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00AB263B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00AB263B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00AB263B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCE12DA8F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCE12DA8F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCE12DA8F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCE12DA8F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CE12DA8F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CE12DA8F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CE12DA8F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CE12DA8F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CE12DA8F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CE12DA8F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFFBCDC16 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFFBCDC16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFFBCDC16 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFFBCDC16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FFBCDC16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FFBCDC16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FFBCDC16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FFBCDC16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FFBCDC16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FFBCDC16: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x285418DD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x285418DD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x285418DD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x285418DD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_285418DD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_285418DD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_285418DD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_285418DD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_285418DD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_285418DD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3DE2527A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3DE2527A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3DE2527A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3DE2527A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3DE2527A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3DE2527A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3DE2527A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3DE2527A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3DE2527A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3DE2527A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x6EF76D78 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6EF76D78 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6EF76D78 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6EF76D78 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_6EF76D78: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6EF76D78 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6EF76D78] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6EF76D78 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6EF76D78: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6EF76D78: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSerializeBoot()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8C5DE045 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8C5DE045 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8C5DE045 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8C5DE045 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_8C5DE045: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8C5DE045 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8C5DE045] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8C5DE045 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8C5DE045: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8C5DE045: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD3EC04B4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD3EC04B4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD3EC04B4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD3EC04B4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D3EC04B4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D3EC04B4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D3EC04B4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D3EC04B4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D3EC04B4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D3EC04B4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1B89F899 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1B89F899 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1B89F899 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1B89F899 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1B89F899: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1B89F899 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1B89F899] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1B89F899 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1B89F899: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1B89F899: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9CA506A8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9CA506A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9CA506A8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9CA506A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_9CA506A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9CA506A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9CA506A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9CA506A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9CA506A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9CA506A8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3439F52A \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3439F52A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3439F52A \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3439F52A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_3439F52A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3439F52A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3439F52A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3439F52A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3439F52A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3439F52A: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF45EBCF3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF45EBCF3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF45EBCF3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF45EBCF3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_F45EBCF3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F45EBCF3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F45EBCF3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F45EBCF3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F45EBCF3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F45EBCF3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1C42FD0C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C42FD0C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C42FD0C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C42FD0C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1C42FD0C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C42FD0C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C42FD0C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C42FD0C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C42FD0C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C42FD0C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultHardErrorPort(
	IN HANDLE PortHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE072EDE8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE072EDE8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE072EDE8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE072EDE8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_E072EDE8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E072EDE8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E072EDE8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E072EDE8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E072EDE8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E072EDE8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x11A28799 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x11A28799 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x11A28799 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x11A28799 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_11A28799: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_11A28799 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_11A28799] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_11A28799 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_11A28799: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_11A28799: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x2FB1146C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2FB1146C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2FB1146C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2FB1146C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2FB1146C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2FB1146C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2FB1146C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2FB1146C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2FB1146C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2FB1146C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD58E8157 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD58E8157 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD58E8157 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD58E8157 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D58E8157: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D58E8157 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D58E8157] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D58E8157 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D58E8157: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D58E8157: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x793BD18C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x793BD18C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x793BD18C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x793BD18C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_793BD18C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_793BD18C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_793BD18C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_793BD18C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_793BD18C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_793BD18C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetHighEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D2EA180 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D2EA180 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D2EA180 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D2EA180 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9D2EA180: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D2EA180 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D2EA180] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D2EA180 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D2EA180: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D2EA180: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C9C381D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C9C381D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C9C381D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C9C381D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0C9C381D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C9C381D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C9C381D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C9C381D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C9C381D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C9C381D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x279609CE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x279609CE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x279609CE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x279609CE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_279609CE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_279609CE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_279609CE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_279609CE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_279609CE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_279609CE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x041F9433 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x041F9433 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x041F9433 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x041F9433 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_041F9433: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_041F9433 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_041F9433] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_041F9433 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_041F9433: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_041F9433: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1842C315 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1842C315 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1842C315 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1842C315 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1842C315: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1842C315 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1842C315] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1842C315 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1842C315: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1842C315: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x07B8E3D7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07B8E3D7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07B8E3D7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07B8E3D7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_07B8E3D7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07B8E3D7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07B8E3D7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07B8E3D7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07B8E3D7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07B8E3D7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8081AD25 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8081AD25 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8081AD25 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8081AD25 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_8081AD25: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8081AD25 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8081AD25] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8081AD25 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8081AD25: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8081AD25: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x863F0824 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x863F0824 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x863F0824 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x863F0824 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_863F0824: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_863F0824 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_863F0824] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_863F0824 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_863F0824: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_863F0824: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE2B5E62C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE2B5E62C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE2B5E62C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE2B5E62C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E2B5E62C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E2B5E62C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E2B5E62C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E2B5E62C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E2B5E62C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E2B5E62C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D2F7BAC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D2F7BAC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D2F7BAC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D2F7BAC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0D2F7BAC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D2F7BAC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D2F7BAC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D2F7BAC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D2F7BAC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D2F7BAC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x00C8261D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00C8261D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00C8261D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00C8261D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_00C8261D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00C8261D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00C8261D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00C8261D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00C8261D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00C8261D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3C26A42C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3C26A42C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3C26A42C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3C26A42C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3C26A42C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3C26A42C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3C26A42C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3C26A42C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3C26A42C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3C26A42C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x01A4654B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01A4654B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01A4654B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01A4654B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_01A4654B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01A4654B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01A4654B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01A4654B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01A4654B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01A4654B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A9EFA67 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A9EFA67 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A9EFA67 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A9EFA67 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_8A9EFA67: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A9EFA67 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A9EFA67] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A9EFA67 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A9EFA67: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A9EFA67: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0CDE85C8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0CDE85C8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0CDE85C8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0CDE85C8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0CDE85C8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0CDE85C8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0CDE85C8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0CDE85C8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0CDE85C8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0CDE85C8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x48922841 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48922841 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48922841 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48922841 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_48922841: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48922841 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48922841] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48922841 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48922841: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48922841: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE0D2B208 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE0D2B208 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE0D2B208 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE0D2B208 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_E0D2B208: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E0D2B208 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E0D2B208] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E0D2B208 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E0D2B208: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E0D2B208: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFEA20ADE \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFEA20ADE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFEA20ADE \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFEA20ADE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_FEA20ADE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FEA20ADE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FEA20ADE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FEA20ADE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FEA20ADE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FEA20ADE: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLowEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x875B8DCC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x875B8DCC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x875B8DCC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x875B8DCC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_875B8DCC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_875B8DCC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_875B8DCC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_875B8DCC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_875B8DCC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_875B8DCC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x075601C6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x075601C6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x075601C6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x075601C6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_075601C6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_075601C6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_075601C6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_075601C6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_075601C6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_075601C6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC25B10EC \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC25B10EC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC25B10EC \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC25B10EC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C25B10EC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C25B10EC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C25B10EC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C25B10EC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C25B10EC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C25B10EC: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0AB9FBD5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AB9FBD5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AB9FBD5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AB9FBD5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0AB9FBD5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AB9FBD5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AB9FBD5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AB9FBD5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AB9FBD5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AB9FBD5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBC3BEB80 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC3BEB80 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC3BEB80 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC3BEB80 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_BC3BEB80: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC3BEB80 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC3BEB80] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC3BEB80 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC3BEB80: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC3BEB80: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x47BB8206 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x47BB8206 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x47BB8206 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x47BB8206 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_47BB8206: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_47BB8206 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_47BB8206] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_47BB8206 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_47BB8206: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_47BB8206: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1D831B10 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1D831B10 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1D831B10 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1D831B10 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1D831B10: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1D831B10 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1D831B10] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1D831B10 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1D831B10: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1D831B10: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xEF17C7DB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEF17C7DB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEF17C7DB \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEF17C7DB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_EF17C7DB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EF17C7DB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EF17C7DB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EF17C7DB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EF17C7DB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EF17C7DB: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x222E2F84 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x222E2F84 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x222E2F84 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x222E2F84 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_222E2F84: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_222E2F84 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_222E2F84] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_222E2F84 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_222E2F84: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_222E2F84: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x33AD7309 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x33AD7309 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x33AD7309 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x33AD7309 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_33AD7309: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_33AD7309 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_33AD7309] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_33AD7309 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_33AD7309: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_33AD7309: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x191199C7 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x191199C7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x191199C7 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x191199C7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_191199C7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_191199C7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_191199C7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_191199C7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_191199C7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_191199C7: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE208C4B5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE208C4B5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE208C4B5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE208C4B5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E208C4B5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E208C4B5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E208C4B5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E208C4B5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E208C4B5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E208C4B5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C93EC81 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C93EC81 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C93EC81 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C93EC81 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0C93EC81: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C93EC81 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C93EC81] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C93EC81 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C93EC81: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C93EC81: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetUuidSeed(
	IN PUCHAR Seed)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9DBF1F82 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9DBF1F82 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9DBF1F82 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9DBF1F82 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9DBF1F82: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9DBF1F82 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9DBF1F82] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9DBF1F82 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9DBF1F82: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9DBF1F82: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xBE16D092 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBE16D092 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBE16D092 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBE16D092 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BE16D092: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BE16D092 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BE16D092] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BE16D092 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BE16D092: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BE16D092: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0AA10532 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AA10532 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AA10532 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AA10532 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0AA10532: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AA10532 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AA10532] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AA10532 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AA10532: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AA10532: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtShutdownSystem(
	IN SHUTDOWN_ACTION Action)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1892E09D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1892E09D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1892E09D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1892E09D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1892E09D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1892E09D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1892E09D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1892E09D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1892E09D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1892E09D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8C9EF67F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8C9EF67F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8C9EF67F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8C9EF67F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_8C9EF67F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8C9EF67F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8C9EF67F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8C9EF67F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8C9EF67F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8C9EF67F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x94A8BC34 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x94A8BC34 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x94A8BC34 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x94A8BC34 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_94A8BC34: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_94A8BC34 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_94A8BC34] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_94A8BC34 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_94A8BC34: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_94A8BC34: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C216CBD \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C216CBD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C216CBD \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C216CBD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0C216CBD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C216CBD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C216CBD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C216CBD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C216CBD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C216CBD: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStartProfile(
	IN HANDLE ProfileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCD53BE47 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD53BE47 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD53BE47 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD53BE47 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CD53BE47: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD53BE47 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD53BE47] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD53BE47 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD53BE47: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD53BE47: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStopProfile(
	IN HANDLE ProfileHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x189DD2AA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x189DD2AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x189DD2AA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x189DD2AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_189DD2AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_189DD2AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_189DD2AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_189DD2AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_189DD2AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_189DD2AA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xDE4ED9D2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE4ED9D2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE4ED9D2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE4ED9D2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_DE4ED9D2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE4ED9D2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE4ED9D2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE4ED9D2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE4ED9D2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE4ED9D2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendProcess(
	IN HANDLE ProcessHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC428CFB5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC428CFB5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC428CFB5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC428CFB5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C428CFB5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C428CFB5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C428CFB5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C428CFB5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C428CFB5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C428CFB5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7CD66469 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CD66469 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CD66469 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CD66469 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7CD66469: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CD66469 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CD66469] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CD66469 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CD66469: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CD66469: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x47972B4F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x47972B4F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x47972B4F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x47972B4F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_47972B4F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_47972B4F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_47972B4F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_47972B4F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_47972B4F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_47972B4F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x72B4427E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x72B4427E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x72B4427E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x72B4427E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_72B4427E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_72B4427E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_72B4427E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_72B4427E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_72B4427E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_72B4427E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAAB9C3A4 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAAB9C3A4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAAB9C3A4 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAAB9C3A4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_AAB9C3A4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AAB9C3A4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AAB9C3A4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AAB9C3A4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AAB9C3A4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AAB9C3A4: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTestAlert()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E946B44 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E946B44 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E946B44 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E946B44 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0E946B44: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E946B44 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E946B44] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E946B44 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E946B44: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E946B44: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtThawRegistry()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCC96E237 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCC96E237 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCC96E237 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCC96E237 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_CC96E237: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CC96E237 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CC96E237] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CC96E237 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CC96E237: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CC96E237: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtThawTransactions()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFFA520F6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFFA520F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFFA520F6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFFA520F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_FFA520F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FFA520F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FFA520F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FFA520F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FFA520F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FFA520F6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF7DD0CCA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF7DD0CCA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF7DD0CCA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF7DD0CCA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_F7DD0CCA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F7DD0CCA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F7DD0CCA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F7DD0CCA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F7DD0CCA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F7DD0CCA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x36A94146 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36A94146 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36A94146 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36A94146 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_36A94146: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36A94146 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36A94146] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36A94146 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36A94146: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36A94146: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUmsThreadYield(
	IN PVOID SchedulerParam)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3BD00443 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3BD00443 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3BD00443 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3BD00443 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3BD00443: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3BD00443 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3BD00443] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3BD00443 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3BD00443: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3BD00443: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadDriver(
	IN PUNICODE_STRING DriverServiceName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x329E1220 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x329E1220 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x329E1220 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x329E1220 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_329E1220: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_329E1220 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_329E1220] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_329E1220 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_329E1220: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_329E1220: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xAB339694 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB339694 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB339694 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB339694 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AB339694: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB339694 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB339694] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB339694 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB339694: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB339694: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3F98D486 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F98D486 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3F98D486 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3F98D486 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3F98D486: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3F98D486 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3F98D486] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3F98D486 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3F98D486: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3F98D486: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x89A7E95F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x89A7E95F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x89A7E95F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x89A7E95F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_89A7E95F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_89A7E95F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_89A7E95F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_89A7E95F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_89A7E95F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_89A7E95F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x04851632 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04851632 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04851632 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04851632 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_04851632: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04851632 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04851632] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04851632 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04851632: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04851632: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID * BaseAddress,
	IN PSIZE_T NumberOfBytesToUnlock,
	IN ULONG LockType)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0391150F \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0391150F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0391150F \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0391150F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0391150F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0391150F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0391150F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0391150F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0391150F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0391150F: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1E9D5E24 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E9D5E24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E9D5E24 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E9D5E24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1E9D5E24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E9D5E24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E9D5E24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E9D5E24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E9D5E24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E9D5E24: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7C9FF982 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7C9FF982 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7C9FF982 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7C9FF982 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_7C9FF982: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7C9FF982 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7C9FF982] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7C9FF982 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7C9FF982: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7C9FF982: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x42BA31A6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x42BA31A6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x42BA31A6 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x42BA31A6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_42BA31A6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_42BA31A6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_42BA31A6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_42BA31A6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_42BA31A6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_42BA31A6: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0FE00B7B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FE00B7B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FE00B7B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FE00B7B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0FE00B7B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FE00B7B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FE00B7B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FE00B7B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FE00B7B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FE00B7B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x77A3EA93 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x77A3EA93 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x77A3EA93 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x77A3EA93 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_77A3EA93: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_77A3EA93 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_77A3EA93] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_77A3EA93 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_77A3EA93: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_77A3EA93: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7272E76B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7272E76B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7272E76B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7272E76B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_7272E76B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7272E76B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7272E76B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7272E76B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7272E76B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7272E76B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x42894F18 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x42894F18 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x42894F18 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x42894F18 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_42894F18: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_42894F18 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_42894F18] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_42894F18 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_42894F18: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_42894F18: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x988C6CF2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x988C6CF2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x988C6CF2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x988C6CF2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_988C6CF2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_988C6CF2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_988C6CF2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_988C6CF2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_988C6CF2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_988C6CF2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitHighEventPair(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD9B63FE1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD9B63FE1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD9B63FE1 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD9B63FE1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D9B63FE1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D9B63FE1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D9B63FE1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D9B63FE1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D9B63FE1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D9B63FE1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitLowEventPair(
	IN HANDLE EventHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF0B21525 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF0B21525 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF0B21525 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF0B21525 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_F0B21525: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F0B21525 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F0B21525] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F0B21525 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F0B21525: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F0B21525: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x684C0CD9 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x684C0CD9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x684C0CD9 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x684C0CD9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_684C0CD9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_684C0CD9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_684C0CD9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_684C0CD9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_684C0CD9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_684C0CD9: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x13991D02 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x13991D02 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x13991D02 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x13991D02 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_13991D02: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_13991D02 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_13991D02] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_13991D02 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_13991D02: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_13991D02: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9C17DCC5 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9C17DCC5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9C17DCC5 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9C17DCC5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_9C17DCC5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9C17DCC5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9C17DCC5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9C17DCC5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9C17DCC5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9C17DCC5: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4689005D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4689005D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4689005D \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4689005D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4689005D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4689005D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4689005D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4689005D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4689005D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4689005D: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1289321B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1289321B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1289321B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1289321B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1289321B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1289321B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1289321B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1289321B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1289321B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1289321B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x654DBB65 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x654DBB65 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x654DBB65 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x654DBB65 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_654DBB65: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_654DBB65 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_654DBB65] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_654DBB65 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_654DBB65: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_654DBB65: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x54B4B7FA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x54B4B7FA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x54B4B7FA \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x54B4B7FA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_54B4B7FA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_54B4B7FA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_54B4B7FA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_54B4B7FA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_54B4B7FA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_54B4B7FA: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x389EDDE3 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x389EDDE3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x389EDDE3 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x389EDDE3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_389EDDE3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_389EDDE3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_389EDDE3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_389EDDE3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_389EDDE3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_389EDDE3: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtCreateCrossVmEvent()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x025513F8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x025513F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x025513F8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x025513F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_025513F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_025513F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_025513F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_025513F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_025513F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_025513F8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x201D158B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x201D158B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x201D158B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x201D158B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_201D158B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_201D158B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_201D158B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_201D158B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_201D158B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_201D158B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtListTransactions()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5F90510B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5F90510B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5F90510B \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5F90510B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_5F90510B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5F90510B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5F90510B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5F90510B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5F90510B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5F90510B: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtMarshallTransaction()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1258C0F8 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1258C0F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1258C0F8 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1258C0F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1258C0F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1258C0F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1258C0F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1258C0F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1258C0F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1258C0F8: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtPullTransaction()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x148C3259 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x148C3259 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x148C3259 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x148C3259 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_148C3259: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_148C3259 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_148C3259] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_148C3259 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_148C3259: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_148C3259: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtReleaseCMFViewOwnership()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xA234A4A2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA234A4A2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA234A4A2 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA234A4A2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_A234A4A2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A234A4A2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A234A4A2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A234A4A2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A234A4A2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A234A4A2: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtWaitForWnfNotifications()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x099B2D09 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x099B2D09 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x099B2D09 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x099B2D09 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_099B2D09: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_099B2D09 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_099B2D09] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_099B2D09 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_099B2D09: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_099B2D09: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtStartTm()
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE589D504 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE589D504 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE589D504 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE589D504 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_E589D504: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E589D504 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E589D504] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E589D504 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E589D504: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E589D504: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9D31855C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D31855C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D31855C \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D31855C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9D31855C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D31855C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D31855C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D31855C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D31855C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D31855C: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestDeviceWakeup(
	IN HANDLE DeviceHandle)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x318B2922 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x318B2922 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x318B2922 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x318B2922 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_318B2922: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_318B2922 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_318B2922] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_318B2922 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_318B2922: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_318B2922: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtRequestWakeupLatency(
	IN ULONG LatencyTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0E8D1310 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E8D1310 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E8D1310 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E8D1310 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0E8D1310: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E8D1310 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E8D1310] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E8D1310 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E8D1310: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E8D1310: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE3A7F600 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE3A7F600 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE3A7F600 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE3A7F600 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_E3A7F600: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E3A7F600 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E3A7F600] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E3A7F600 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E3A7F600: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E3A7F600: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE8A72700 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE8A72700 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE8A72700 \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE8A72700 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E8A72700: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E8A72700 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E8A72700] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E8A72700 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E8A72700: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E8A72700: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

__declspec(naked) NTSTATUS Sw3NtContinueEx(
	IN PCONTEXT ContextRecord,
	IN PKCONTINUE_ARGUMENT ContinueArgument)
{
	asm(
#if defined(_WIN64)
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xE9CB972E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE9CB972E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE9CB972E \n"
		"call _SW3_GetSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE9CB972E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E9CB972E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E9CB972E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E9CB972E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E9CB972E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E9CB972E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E9CB972E: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

#endif
