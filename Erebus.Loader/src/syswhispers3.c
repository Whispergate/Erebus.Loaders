#include "syswhispers3.h"
#include <stdio.h>

//#define DEBUG

#define JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

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
		"mov ecx, 0xE55FE8CE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE55FE8CE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE55FE8CE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE55FE8CE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_E55FE8CE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E55FE8CE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E55FE8CE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E55FE8CE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E55FE8CE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E55FE8CE: \n"
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
		"mov ecx, 0xBF9D9F24 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBF9D9F24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBF9D9F24 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBF9D9F24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_BF9D9F24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BF9D9F24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BF9D9F24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BF9D9F24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BF9D9F24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BF9D9F24: \n"
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
		"mov ecx, 0x2E894556 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2E894556 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2E894556 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2E894556 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2E894556: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2E894556 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2E894556] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2E894556 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2E894556: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2E894556: \n"
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
		"mov ecx, 0x01AC2AF1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01AC2AF1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01AC2AF1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01AC2AF1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_01AC2AF1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01AC2AF1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01AC2AF1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01AC2AF1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01AC2AF1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01AC2AF1: \n"
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
		"mov ecx, 0x7EA2187F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7EA2187F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7EA2187F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7EA2187F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7EA2187F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7EA2187F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7EA2187F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7EA2187F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7EA2187F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7EA2187F: \n"
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
		"mov ecx, 0x3092D09C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3092D09C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3092D09C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3092D09C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3092D09C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3092D09C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3092D09C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3092D09C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3092D09C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3092D09C: \n"
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
		"mov ecx, 0xE07BF2C2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE07BF2C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE07BF2C2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE07BF2C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_E07BF2C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E07BF2C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E07BF2C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E07BF2C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E07BF2C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E07BF2C2: \n"
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
		"mov ecx, 0x00B8C8EB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00B8C8EB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00B8C8EB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00B8C8EB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_00B8C8EB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00B8C8EB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00B8C8EB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00B8C8EB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00B8C8EB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00B8C8EB: \n"
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
		"mov ecx, 0xAC9A64B8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAC9A64B8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAC9A64B8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAC9A64B8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_AC9A64B8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AC9A64B8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AC9A64B8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AC9A64B8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AC9A64B8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AC9A64B8: \n"
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
		"mov ecx, 0x8B95AB07 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B95AB07 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B95AB07 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B95AB07 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8B95AB07: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B95AB07 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B95AB07] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B95AB07 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B95AB07: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B95AB07: \n"
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
		"mov ecx, 0x02A86C24 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02A86C24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02A86C24 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02A86C24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_02A86C24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02A86C24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02A86C24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02A86C24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02A86C24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02A86C24: \n"
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
		"mov ecx, 0x18B11B3E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18B11B3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18B11B3E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18B11B3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_18B11B3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18B11B3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18B11B3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18B11B3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18B11B3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18B11B3E: \n"
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
		"mov ecx, 0xA33EBAAB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA33EBAAB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA33EBAAB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA33EBAAB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A33EBAAB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A33EBAAB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A33EBAAB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A33EBAAB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A33EBAAB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A33EBAAB: \n"
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
		"mov ecx, 0x1C3CDF13 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C3CDF13 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C3CDF13 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C3CDF13 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1C3CDF13: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C3CDF13 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C3CDF13] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C3CDF13 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C3CDF13: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C3CDF13: \n"
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
		"mov ecx, 0xD08BD31D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD08BD31D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD08BD31D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD08BD31D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D08BD31D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D08BD31D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D08BD31D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D08BD31D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D08BD31D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D08BD31D: \n"
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
		"mov ecx, 0x069E8EB3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x069E8EB3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x069E8EB3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x069E8EB3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_069E8EB3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_069E8EB3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_069E8EB3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_069E8EB3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_069E8EB3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_069E8EB3: \n"
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
		"mov ecx, 0x923D82A1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x923D82A1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x923D82A1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x923D82A1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_923D82A1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_923D82A1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_923D82A1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_923D82A1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_923D82A1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_923D82A1: \n"
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
		"mov ecx, 0xA0FA635C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA0FA635C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA0FA635C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA0FA635C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A0FA635C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A0FA635C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A0FA635C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A0FA635C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A0FA635C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A0FA635C: \n"
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
		"mov ecx, 0x14947109 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14947109 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14947109 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14947109 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_14947109: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14947109 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14947109] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14947109 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14947109: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14947109: \n"
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
		"mov ecx, 0x419D7224 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x419D7224 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x419D7224 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x419D7224 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_419D7224: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_419D7224 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_419D7224] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_419D7224 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_419D7224: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_419D7224: \n"
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
		"mov ecx, 0xDC46D7D8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC46D7D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC46D7D8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC46D7D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DC46D7D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC46D7D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC46D7D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC46D7D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC46D7D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC46D7D8: \n"
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
		"mov ecx, 0xD090E847 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD090E847 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD090E847 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD090E847 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D090E847: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D090E847 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D090E847] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D090E847 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D090E847: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D090E847: \n"
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
		"mov ecx, 0x8F08D4AA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8F08D4AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8F08D4AA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8F08D4AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8F08D4AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8F08D4AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8F08D4AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8F08D4AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8F08D4AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8F08D4AA: \n"
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
		"mov ecx, 0x8820A1F1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8820A1F1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8820A1F1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8820A1F1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8820A1F1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8820A1F1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8820A1F1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8820A1F1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8820A1F1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8820A1F1: \n"
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
		"mov ecx, 0x059916F3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x059916F3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x059916F3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x059916F3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_059916F3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_059916F3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_059916F3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_059916F3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_059916F3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_059916F3: \n"
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
		"mov ecx, 0x0185E4EC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0185E4EC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0185E4EC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0185E4EC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0185E4EC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0185E4EC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0185E4EC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0185E4EC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0185E4EC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0185E4EC: \n"
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
		"mov ecx, 0x88991536 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x88991536 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x88991536 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x88991536 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_88991536: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_88991536 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_88991536] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_88991536 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_88991536: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_88991536: \n"
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
		"mov ecx, 0xD5883290 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD5883290 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD5883290 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD5883290 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_D5883290: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D5883290 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D5883290] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D5883290 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D5883290: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D5883290: \n"
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
		"mov ecx, 0x01C32864 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01C32864 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01C32864 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01C32864 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_01C32864: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01C32864 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01C32864] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01C32864 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01C32864: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01C32864: \n"
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
		"mov ecx, 0x4B5A5DC5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4B5A5DC5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4B5A5DC5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4B5A5DC5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_4B5A5DC5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4B5A5DC5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4B5A5DC5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4B5A5DC5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4B5A5DC5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4B5A5DC5: \n"
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
		"mov ecx, 0x78AC6122 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78AC6122 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78AC6122 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78AC6122 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_78AC6122: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78AC6122 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78AC6122] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78AC6122 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78AC6122: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78AC6122: \n"
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
		"mov ecx, 0x1EBF715C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EBF715C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EBF715C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EBF715C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1EBF715C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EBF715C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EBF715C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EBF715C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EBF715C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EBF715C: \n"
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
		"mov ecx, 0x350703A4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x350703A4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x350703A4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x350703A4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_350703A4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_350703A4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_350703A4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_350703A4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_350703A4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_350703A4: \n"
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
		"mov ecx, 0x22F45B18 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22F45B18 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22F45B18 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22F45B18 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_22F45B18: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22F45B18 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22F45B18] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22F45B18 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22F45B18: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22F45B18: \n"
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
		"mov ecx, 0x0190E1F9 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0190E1F9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0190E1F9 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0190E1F9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0190E1F9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0190E1F9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0190E1F9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0190E1F9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0190E1F9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0190E1F9: \n"
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
		"mov ecx, 0x75A40142 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x75A40142 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x75A40142 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x75A40142 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_75A40142: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_75A40142 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_75A40142] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_75A40142 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_75A40142: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_75A40142: \n"
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
		"mov ecx, 0xAEAA138C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAEAA138C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAEAA138C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAEAA138C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_AEAA138C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AEAA138C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AEAA138C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AEAA138C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AEAA138C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AEAA138C: \n"
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
		"mov ecx, 0xC5A4DC08 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC5A4DC08 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC5A4DC08 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC5A4DC08 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C5A4DC08: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C5A4DC08 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C5A4DC08] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C5A4DC08 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C5A4DC08: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C5A4DC08: \n"
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
		"mov ecx, 0x993F653B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x993F653B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x993F653B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x993F653B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_993F653B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_993F653B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_993F653B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_993F653B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_993F653B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_993F653B: \n"
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
		"mov ecx, 0x3A163C86 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A163C86 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A163C86 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A163C86 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_3A163C86: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A163C86 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A163C86] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A163C86 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A163C86: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A163C86: \n"
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
		"mov ecx, 0x30973606 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x30973606 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x30973606 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x30973606 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_30973606: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_30973606 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_30973606] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_30973606 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_30973606: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_30973606: \n"
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
		"mov ecx, 0x8AA849F8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8AA849F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8AA849F8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8AA849F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_8AA849F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8AA849F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8AA849F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8AA849F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8AA849F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8AA849F8: \n"
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
		"mov ecx, 0x818ED552 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x818ED552 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x818ED552 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x818ED552 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_818ED552: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_818ED552 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_818ED552] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_818ED552 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_818ED552: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_818ED552: \n"
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
		"mov ecx, 0x3B833A0E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3B833A0E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3B833A0E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3B833A0E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3B833A0E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3B833A0E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3B833A0E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3B833A0E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3B833A0E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3B833A0E: \n"
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
		"mov ecx, 0x1690101C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1690101C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1690101C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1690101C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1690101C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1690101C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1690101C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1690101C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1690101C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1690101C: \n"
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
		"mov ecx, 0x058F2F17 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x058F2F17 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x058F2F17 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x058F2F17 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_058F2F17: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_058F2F17 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_058F2F17] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_058F2F17 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_058F2F17: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_058F2F17: \n"
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
		"mov ecx, 0x7AE50402 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7AE50402 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7AE50402 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7AE50402 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_7AE50402: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7AE50402 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7AE50402] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7AE50402 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7AE50402: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7AE50402: \n"
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
		"mov ecx, 0x209B6E5C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x209B6E5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x209B6E5C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x209B6E5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_209B6E5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_209B6E5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_209B6E5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_209B6E5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_209B6E5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_209B6E5C: \n"
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
		"mov ecx, 0x1F9E291B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F9E291B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F9E291B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F9E291B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1F9E291B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F9E291B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F9E291B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F9E291B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F9E291B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F9E291B: \n"
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
		"mov ecx, 0x4BFF95AD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4BFF95AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4BFF95AD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4BFF95AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_4BFF95AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4BFF95AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4BFF95AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4BFF95AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4BFF95AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4BFF95AD: \n"
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
		"mov ecx, 0x32BC2A0E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x32BC2A0E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x32BC2A0E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x32BC2A0E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_32BC2A0E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_32BC2A0E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_32BC2A0E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_32BC2A0E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_32BC2A0E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_32BC2A0E: \n"
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
		"mov ecx, 0xB32CB3BE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB32CB3BE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB32CB3BE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB32CB3BE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B32CB3BE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B32CB3BE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B32CB3BE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B32CB3BE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B32CB3BE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B32CB3BE: \n"
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
		"mov ecx, 0xB6214428 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB6214428 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB6214428 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB6214428 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_B6214428: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B6214428 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B6214428] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B6214428 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B6214428: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B6214428: \n"
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
		"mov ecx, 0xE18FE11D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE18FE11D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE18FE11D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE18FE11D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E18FE11D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E18FE11D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E18FE11D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E18FE11D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E18FE11D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E18FE11D: \n"
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
		"mov ecx, 0x36AF363D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36AF363D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36AF363D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36AF363D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_36AF363D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36AF363D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36AF363D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36AF363D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36AF363D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36AF363D: \n"
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
		"mov ecx, 0x87BBFF50 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x87BBFF50 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x87BBFF50 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x87BBFF50 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_87BBFF50: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_87BBFF50 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_87BBFF50] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_87BBFF50 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_87BBFF50: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_87BBFF50: \n"
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
		"mov ecx, 0x881BBE88 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x881BBE88 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x881BBE88 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x881BBE88 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_881BBE88: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_881BBE88 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_881BBE88] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_881BBE88 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_881BBE88: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_881BBE88: \n"
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
		"mov ecx, 0x03950907 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x03950907 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x03950907 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x03950907 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_03950907: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_03950907 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_03950907] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_03950907 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_03950907: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_03950907: \n"
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
		"mov ecx, 0x32B5D222 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x32B5D222 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x32B5D222 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x32B5D222 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_32B5D222: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_32B5D222 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_32B5D222] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_32B5D222 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_32B5D222: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_32B5D222: \n"
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
		"mov ecx, 0x74561CAA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74561CAA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74561CAA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74561CAA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_74561CAA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74561CAA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74561CAA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74561CAA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74561CAA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74561CAA: \n"
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
		"mov ecx, 0x63D81749 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63D81749 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63D81749 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63D81749 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_63D81749: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63D81749 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63D81749] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63D81749 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63D81749: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63D81749: \n"
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
		"mov ecx, 0x5AD9D7C0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5AD9D7C0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5AD9D7C0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5AD9D7C0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_5AD9D7C0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5AD9D7C0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5AD9D7C0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5AD9D7C0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5AD9D7C0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5AD9D7C0: \n"
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
		"mov ecx, 0x8091FC54 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8091FC54 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8091FC54 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8091FC54 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8091FC54: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8091FC54 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8091FC54] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8091FC54 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8091FC54: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8091FC54: \n"
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
		"mov ecx, 0x108A111E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x108A111E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x108A111E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x108A111E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_108A111E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_108A111E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_108A111E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_108A111E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_108A111E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_108A111E: \n"
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
		"mov ecx, 0xD39B429F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD39B429F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD39B429F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD39B429F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_D39B429F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D39B429F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D39B429F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D39B429F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D39B429F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D39B429F: \n"
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
		"mov ecx, 0x27111794 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x27111794 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x27111794 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x27111794 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_27111794: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_27111794 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_27111794] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_27111794 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_27111794: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_27111794: \n"
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
		"mov ecx, 0x1E7A2FA6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E7A2FA6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E7A2FA6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E7A2FA6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1E7A2FA6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E7A2FA6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E7A2FA6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E7A2FA6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E7A2FA6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E7A2FA6: \n"
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
		"mov ecx, 0xAB3DD8A0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB3DD8A0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB3DD8A0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB3DD8A0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AB3DD8A0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB3DD8A0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB3DD8A0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB3DD8A0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB3DD8A0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB3DD8A0: \n"
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
		"mov ecx, 0xA613F4A5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA613F4A5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA613F4A5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA613F4A5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A613F4A5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A613F4A5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A613F4A5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A613F4A5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A613F4A5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A613F4A5: \n"
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
		"mov ecx, 0x2882362F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2882362F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2882362F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2882362F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_2882362F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2882362F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2882362F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2882362F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2882362F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2882362F: \n"
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
		"mov ecx, 0x277F2CDA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x277F2CDA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x277F2CDA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x277F2CDA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_277F2CDA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_277F2CDA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_277F2CDA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_277F2CDA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_277F2CDA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_277F2CDA: \n"
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
		"mov ecx, 0x36A06E84 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36A06E84 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36A06E84 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36A06E84 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_36A06E84: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36A06E84 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36A06E84] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36A06E84 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36A06E84: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36A06E84: \n"
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
		"mov ecx, 0xF5560F47 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF5560F47 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF5560F47 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF5560F47 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F5560F47: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F5560F47 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F5560F47] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F5560F47 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F5560F47: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F5560F47: \n"
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
		"mov ecx, 0x3A9C3401 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A9C3401 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A9C3401 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A9C3401 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_3A9C3401: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A9C3401 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A9C3401] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A9C3401 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A9C3401: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A9C3401: \n"
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
		"mov ecx, 0x58F37266 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58F37266 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58F37266 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58F37266 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_58F37266: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58F37266 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58F37266] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58F37266 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58F37266: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58F37266: \n"
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
		"mov ecx, 0xC793C179 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC793C179 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC793C179 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC793C179 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C793C179: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C793C179 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C793C179] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C793C179 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C793C179: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C793C179: \n"
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
		"mov ecx, 0x239F1E2A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x239F1E2A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x239F1E2A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x239F1E2A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_239F1E2A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_239F1E2A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_239F1E2A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_239F1E2A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_239F1E2A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_239F1E2A: \n"
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
		"mov ecx, 0x3EAA4443 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3EAA4443 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3EAA4443 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3EAA4443 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_3EAA4443: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3EAA4443 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3EAA4443] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3EAA4443 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3EAA4443: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3EAA4443: \n"
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
		"mov ecx, 0xD8212C70 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD8212C70 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD8212C70 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD8212C70 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D8212C70: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D8212C70 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D8212C70] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D8212C70 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D8212C70: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D8212C70: \n"
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
		"mov ecx, 0xC053D8B2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC053D8B2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC053D8B2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC053D8B2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C053D8B2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C053D8B2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C053D8B2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C053D8B2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C053D8B2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C053D8B2: \n"
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
		"mov ecx, 0x36AA1033 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36AA1033 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36AA1033 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36AA1033 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_36AA1033: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36AA1033 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36AA1033] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36AA1033 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36AA1033: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36AA1033: \n"
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
		"mov ecx, 0x05394F97 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x05394F97 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x05394F97 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x05394F97 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_05394F97: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_05394F97 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_05394F97] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_05394F97 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_05394F97: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_05394F97: \n"
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
		"mov ecx, 0x4ADB0409 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ADB0409 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ADB0409 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ADB0409 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4ADB0409: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ADB0409 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ADB0409] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ADB0409 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ADB0409: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ADB0409: \n"
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
		"mov ecx, 0xA23E8EAC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA23E8EAC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA23E8EAC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA23E8EAC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A23E8EAC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A23E8EAC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A23E8EAC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A23E8EAC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A23E8EAC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A23E8EAC: \n"
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
		"mov ecx, 0x5ED80864 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5ED80864 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5ED80864 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5ED80864 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_5ED80864: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5ED80864 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5ED80864] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5ED80864 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5ED80864: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5ED80864: \n"
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
		"mov ecx, 0xA8ABAB3C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA8ABAB3C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA8ABAB3C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA8ABAB3C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A8ABAB3C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A8ABAB3C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A8ABAB3C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A8ABAB3C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A8ABAB3C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A8ABAB3C: \n"
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
		"mov ecx, 0xA005CE8A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA005CE8A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA005CE8A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA005CE8A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A005CE8A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A005CE8A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A005CE8A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A005CE8A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A005CE8A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A005CE8A: \n"
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
		"mov ecx, 0xAE32A4AF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAE32A4AF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAE32A4AF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAE32A4AF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_AE32A4AF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AE32A4AF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AE32A4AF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AE32A4AF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AE32A4AF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AE32A4AF: \n"
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
		"mov ecx, 0x9E149488 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9E149488 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9E149488 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9E149488 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_9E149488: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9E149488 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9E149488] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9E149488 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9E149488: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9E149488: \n"
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
		"mov ecx, 0x079E0907 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x079E0907 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x079E0907 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x079E0907 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_079E0907: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_079E0907 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_079E0907] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_079E0907 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_079E0907: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_079E0907: \n"
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
		"mov ecx, 0x163EC561 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x163EC561 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x163EC561 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x163EC561 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_163EC561: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_163EC561 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_163EC561] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_163EC561 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_163EC561: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_163EC561: \n"
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
		"mov ecx, 0x3AB9781E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3AB9781E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3AB9781E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3AB9781E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3AB9781E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3AB9781E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3AB9781E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3AB9781E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3AB9781E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3AB9781E: \n"
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
		"mov ecx, 0xDE9F2FFA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE9F2FFA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE9F2FFA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE9F2FFA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_DE9F2FFA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE9F2FFA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE9F2FFA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE9F2FFA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE9F2FFA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE9F2FFA: \n"
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
		"mov ecx, 0xC592C70F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC592C70F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC592C70F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC592C70F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C592C70F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C592C70F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C592C70F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C592C70F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C592C70F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C592C70F: \n"
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
		"mov ecx, 0x55FAAC7A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x55FAAC7A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x55FAAC7A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x55FAAC7A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_55FAAC7A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_55FAAC7A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_55FAAC7A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_55FAAC7A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_55FAAC7A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_55FAAC7A: \n"
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
		"mov ecx, 0x21A6373E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x21A6373E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x21A6373E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x21A6373E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_21A6373E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_21A6373E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_21A6373E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_21A6373E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_21A6373E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_21A6373E: \n"
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
		"mov ecx, 0xFF58CFF9 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFF58CFF9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFF58CFF9 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFF58CFF9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_FF58CFF9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FF58CFF9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FF58CFF9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FF58CFF9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FF58CFF9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FF58CFF9: \n"
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
		"mov ecx, 0x08A22428 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08A22428 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08A22428 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08A22428 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_08A22428: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08A22428 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08A22428] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08A22428 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08A22428: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08A22428: \n"
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
		"mov ecx, 0x14B53C29 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14B53C29 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14B53C29 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14B53C29 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_14B53C29: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14B53C29 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14B53C29] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14B53C29 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14B53C29: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14B53C29: \n"
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
		"mov ecx, 0x9EB17AE0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9EB17AE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9EB17AE0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9EB17AE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_9EB17AE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9EB17AE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9EB17AE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9EB17AE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9EB17AE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9EB17AE0: \n"
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
		"mov ecx, 0xBF92EDA7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBF92EDA7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBF92EDA7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBF92EDA7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_BF92EDA7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BF92EDA7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BF92EDA7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BF92EDA7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BF92EDA7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BF92EDA7: \n"
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
		"mov ecx, 0x76C1777C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76C1777C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x76C1777C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x76C1777C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_76C1777C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_76C1777C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_76C1777C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_76C1777C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_76C1777C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_76C1777C: \n"
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
		"mov ecx, 0x31A47F52 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x31A47F52 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x31A47F52 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x31A47F52 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_31A47F52: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_31A47F52 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_31A47F52] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_31A47F52 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_31A47F52: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_31A47F52: \n"
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
		"mov ecx, 0xCB1AFFD6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB1AFFD6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB1AFFD6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB1AFFD6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CB1AFFD6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB1AFFD6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB1AFFD6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB1AFFD6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB1AFFD6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB1AFFD6: \n"
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
		"mov ecx, 0x59C5B5A0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x59C5B5A0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x59C5B5A0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x59C5B5A0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_59C5B5A0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_59C5B5A0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_59C5B5A0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_59C5B5A0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_59C5B5A0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_59C5B5A0: \n"
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
		"mov ecx, 0x84838C18 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x84838C18 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x84838C18 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x84838C18 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_84838C18: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_84838C18 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_84838C18] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_84838C18 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_84838C18: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_84838C18: \n"
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
		"mov ecx, 0xE076C6E0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE076C6E0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE076C6E0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE076C6E0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x10 \n"
	"push_argument_E076C6E0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E076C6E0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E076C6E0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E076C6E0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E076C6E0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E076C6E0: \n"
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
		"mov ecx, 0x1C8EC2BF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1C8EC2BF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1C8EC2BF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1C8EC2BF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1C8EC2BF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1C8EC2BF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1C8EC2BF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1C8EC2BF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1C8EC2BF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1C8EC2BF: \n"
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
		"mov ecx, 0x2883ADAA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2883ADAA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2883ADAA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2883ADAA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2883ADAA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2883ADAA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2883ADAA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2883ADAA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2883ADAA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2883ADAA: \n"
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
		"mov ecx, 0xCA3738A1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCA3738A1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCA3738A1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCA3738A1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CA3738A1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CA3738A1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CA3738A1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CA3738A1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CA3738A1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CA3738A1: \n"
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
		"mov ecx, 0x0989D1CD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0989D1CD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0989D1CD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0989D1CD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0989D1CD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0989D1CD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0989D1CD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0989D1CD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0989D1CD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0989D1CD: \n"
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
		"mov ecx, 0x08D56849 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08D56849 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08D56849 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08D56849 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_08D56849: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08D56849 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08D56849] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08D56849 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08D56849: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08D56849: \n"
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
		"mov ecx, 0xB58F88CF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB58F88CF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB58F88CF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB58F88CF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B58F88CF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B58F88CF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B58F88CF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B58F88CF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B58F88CF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B58F88CF: \n"
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
		"mov ecx, 0x06B690AD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06B690AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06B690AD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06B690AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_06B690AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06B690AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06B690AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06B690AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06B690AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06B690AD: \n"
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
		"mov ecx, 0x9D69DDD1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D69DDD1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D69DDD1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D69DDD1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_9D69DDD1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D69DDD1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D69DDD1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D69DDD1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D69DDD1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D69DDD1: \n"
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
		"mov ecx, 0x60F5677E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x60F5677E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x60F5677E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x60F5677E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_60F5677E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_60F5677E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_60F5677E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_60F5677E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_60F5677E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_60F5677E: \n"
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
		"mov ecx, 0xF3ACC676 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF3ACC676 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF3ACC676 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF3ACC676 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F3ACC676: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F3ACC676 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F3ACC676] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F3ACC676 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F3ACC676: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F3ACC676: \n"
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
		"mov ecx, 0xB6A15D3E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB6A15D3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB6A15D3E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB6A15D3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_B6A15D3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B6A15D3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B6A15D3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B6A15D3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B6A15D3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B6A15D3E: \n"
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
		"mov ecx, 0x539EAEEA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x539EAEEA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x539EAEEA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x539EAEEA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_539EAEEA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_539EAEEA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_539EAEEA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_539EAEEA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_539EAEEA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_539EAEEA: \n"
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
		"mov ecx, 0x6AF84D62 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6AF84D62 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6AF84D62 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6AF84D62 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_6AF84D62: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6AF84D62 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6AF84D62] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6AF84D62 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6AF84D62: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6AF84D62: \n"
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
		"mov ecx, 0x12823BD9 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12823BD9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12823BD9 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12823BD9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_12823BD9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12823BD9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12823BD9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12823BD9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12823BD9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12823BD9: \n"
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
		"mov ecx, 0xF25BFAE9 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF25BFAE9 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF25BFAE9 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF25BFAE9 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F25BFAE9: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F25BFAE9 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F25BFAE9] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F25BFAE9 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F25BFAE9: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F25BFAE9: \n"
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
		"mov ecx, 0x64B2452D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64B2452D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64B2452D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64B2452D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_64B2452D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64B2452D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64B2452D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64B2452D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64B2452D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64B2452D: \n"
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
		"mov ecx, 0xF76ACAE3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF76ACAE3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF76ACAE3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF76ACAE3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F76ACAE3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F76ACAE3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F76ACAE3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F76ACAE3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F76ACAE3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F76ACAE3: \n"
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
		"mov ecx, 0x3EAE143B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3EAE143B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3EAE143B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3EAE143B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3EAE143B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3EAE143B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3EAE143B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3EAE143B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3EAE143B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3EAE143B: \n"
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
		"mov ecx, 0xD2DF0A62 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD2DF0A62 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD2DF0A62 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD2DF0A62 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_D2DF0A62: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D2DF0A62 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D2DF0A62] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D2DF0A62 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D2DF0A62: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D2DF0A62: \n"
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
		"mov ecx, 0x86A0FB4A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x86A0FB4A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x86A0FB4A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x86A0FB4A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_86A0FB4A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_86A0FB4A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_86A0FB4A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_86A0FB4A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_86A0FB4A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_86A0FB4A: \n"
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
		"mov ecx, 0xCD590001 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD590001 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD590001 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD590001 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_CD590001: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD590001 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD590001] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD590001 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD590001: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD590001: \n"
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
		"mov ecx, 0x58FFA390 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58FFA390 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58FFA390 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58FFA390 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_58FFA390: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58FFA390 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58FFA390] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58FFA390 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58FFA390: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58FFA390: \n"
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
		"mov ecx, 0xDC2EA5C0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDC2EA5C0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDC2EA5C0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDC2EA5C0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DC2EA5C0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DC2EA5C0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DC2EA5C0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DC2EA5C0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DC2EA5C0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DC2EA5C0: \n"
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
		"mov ecx, 0xF972FAFD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF972FAFD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF972FAFD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF972FAFD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F972FAFD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F972FAFD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F972FAFD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F972FAFD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F972FAFD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F972FAFD: \n"
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
		"mov ecx, 0x0FAF0E3E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0FAF0E3E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0FAF0E3E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0FAF0E3E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0FAF0E3E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0FAF0E3E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0FAF0E3E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0FAF0E3E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0FAF0E3E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0FAF0E3E: \n"
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
		"mov ecx, 0x1788CA39 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1788CA39 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1788CA39 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1788CA39 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1788CA39: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1788CA39 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1788CA39] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1788CA39 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1788CA39: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1788CA39: \n"
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
		"mov ecx, 0xD842BA97 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD842BA97 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD842BA97 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD842BA97 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_D842BA97: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D842BA97 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D842BA97] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D842BA97 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D842BA97: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D842BA97: \n"
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
		"mov ecx, 0xED4D1E50 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xED4D1E50 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xED4D1E50 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xED4D1E50 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_ED4D1E50: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ED4D1E50 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ED4D1E50] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ED4D1E50 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ED4D1E50: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ED4D1E50: \n"
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
		"mov ecx, 0x368A291A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x368A291A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x368A291A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x368A291A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_368A291A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_368A291A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_368A291A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_368A291A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_368A291A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_368A291A: \n"
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
		"mov ecx, 0x66B34D6C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66B34D6C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66B34D6C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66B34D6C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_66B34D6C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66B34D6C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66B34D6C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66B34D6C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66B34D6C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66B34D6C: \n"
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
		"mov ecx, 0x0AAC360F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AAC360F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AAC360F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AAC360F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0AAC360F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AAC360F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AAC360F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AAC360F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AAC360F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AAC360F: \n"
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
		"mov ecx, 0x0DB64660 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0DB64660 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0DB64660 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0DB64660 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0DB64660: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0DB64660 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0DB64660] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0DB64660 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0DB64660: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0DB64660: \n"
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
		"mov ecx, 0x7EC1165D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7EC1165D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7EC1165D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7EC1165D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7EC1165D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7EC1165D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7EC1165D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7EC1165D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7EC1165D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7EC1165D: \n"
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
		"mov ecx, 0xB9ED8961 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB9ED8961 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB9ED8961 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB9ED8961 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_B9ED8961: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B9ED8961 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B9ED8961] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B9ED8961 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B9ED8961: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B9ED8961: \n"
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
		"mov ecx, 0xABAD53B0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xABAD53B0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xABAD53B0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xABAD53B0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_ABAD53B0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ABAD53B0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ABAD53B0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ABAD53B0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ABAD53B0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ABAD53B0: \n"
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
		"mov ecx, 0xB8A68E18 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB8A68E18 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB8A68E18 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB8A68E18 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B8A68E18: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B8A68E18 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B8A68E18] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B8A68E18 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B8A68E18: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B8A68E18: \n"
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
		"mov ecx, 0x49DB4D63 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x49DB4D63 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x49DB4D63 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x49DB4D63 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_49DB4D63: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_49DB4D63 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_49DB4D63] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_49DB4D63 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_49DB4D63: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_49DB4D63: \n"
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
		"mov ecx, 0x1F87A309 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F87A309 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F87A309 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F87A309 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1F87A309: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F87A309 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F87A309] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F87A309 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F87A309: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F87A309: \n"
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
		"mov ecx, 0x3E180CA6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3E180CA6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3E180CA6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3E180CA6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3E180CA6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3E180CA6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3E180CA6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3E180CA6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3E180CA6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3E180CA6: \n"
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
		"mov ecx, 0x4ED57E7E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ED57E7E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ED57E7E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ED57E7E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_4ED57E7E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ED57E7E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ED57E7E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ED57E7E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ED57E7E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ED57E7E: \n"
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
		"mov ecx, 0xCD57F0C1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD57F0C1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD57F0C1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD57F0C1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CD57F0C1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD57F0C1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD57F0C1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD57F0C1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD57F0C1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD57F0C1: \n"
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
		"mov ecx, 0x13055FA7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x13055FA7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x13055FA7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x13055FA7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_13055FA7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_13055FA7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_13055FA7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_13055FA7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_13055FA7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_13055FA7: \n"
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
		"mov ecx, 0x620B449B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x620B449B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x620B449B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x620B449B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_620B449B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_620B449B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_620B449B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_620B449B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_620B449B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_620B449B: \n"
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
		"mov ecx, 0x6DF54A5E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6DF54A5E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6DF54A5E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6DF54A5E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6DF54A5E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6DF54A5E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6DF54A5E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6DF54A5E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6DF54A5E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6DF54A5E: \n"
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
		"mov ecx, 0x402338B7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x402338B7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x402338B7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x402338B7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_402338B7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_402338B7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_402338B7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_402338B7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_402338B7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_402338B7: \n"
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
		"mov ecx, 0x64CA6E5C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64CA6E5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64CA6E5C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64CA6E5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_64CA6E5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64CA6E5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64CA6E5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64CA6E5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64CA6E5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64CA6E5C: \n"
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
		"mov ecx, 0x85A4BD0F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x85A4BD0F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x85A4BD0F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x85A4BD0F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_85A4BD0F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_85A4BD0F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_85A4BD0F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_85A4BD0F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_85A4BD0F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_85A4BD0F: \n"
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
		"mov ecx, 0xD24CC3C2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD24CC3C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD24CC3C2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD24CC3C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D24CC3C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D24CC3C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D24CC3C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D24CC3C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D24CC3C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D24CC3C2: \n"
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
		"mov ecx, 0x8B956E8E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B956E8E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B956E8E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B956E8E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_8B956E8E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B956E8E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B956E8E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B956E8E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B956E8E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B956E8E: \n"
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
		"mov ecx, 0xE470C5A2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE470C5A2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE470C5A2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE470C5A2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_E470C5A2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E470C5A2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E470C5A2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E470C5A2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E470C5A2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E470C5A2: \n"
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
		"mov ecx, 0x6FF2456B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6FF2456B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6FF2456B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6FF2456B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_6FF2456B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6FF2456B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6FF2456B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6FF2456B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6FF2456B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6FF2456B: \n"
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
		"mov ecx, 0x8A28D485 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A28D485 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A28D485 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A28D485 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_8A28D485: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A28D485 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A28D485] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A28D485 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A28D485: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A28D485: \n"
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
		"mov ecx, 0x288619CB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x288619CB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x288619CB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x288619CB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_288619CB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_288619CB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_288619CB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_288619CB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_288619CB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_288619CB: \n"
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
		"mov ecx, 0x8F4D3378 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8F4D3378 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8F4D3378 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8F4D3378 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8F4D3378: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8F4D3378 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8F4D3378] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8F4D3378 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8F4D3378: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8F4D3378: \n"
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
		"mov ecx, 0x351A61AA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x351A61AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x351A61AA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x351A61AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_351A61AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_351A61AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_351A61AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_351A61AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_351A61AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_351A61AA: \n"
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
		"mov ecx, 0xB966FEAD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB966FEAD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB966FEAD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB966FEAD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_B966FEAD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B966FEAD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B966FEAD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B966FEAD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B966FEAD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B966FEAD: \n"
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
		"mov ecx, 0x1EB13825 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EB13825 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EB13825 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EB13825 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1EB13825: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EB13825 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EB13825] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EB13825 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EB13825: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EB13825: \n"
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
		"mov ecx, 0x47DB2534 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x47DB2534 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x47DB2534 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x47DB2534 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_47DB2534: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_47DB2534 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_47DB2534] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_47DB2534 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_47DB2534: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_47DB2534: \n"
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
		"mov ecx, 0xD242D0D1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD242D0D1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD242D0D1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD242D0D1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_D242D0D1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D242D0D1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D242D0D1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D242D0D1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D242D0D1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D242D0D1: \n"
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
		"mov ecx, 0xC458E2C5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC458E2C5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC458E2C5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC458E2C5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_C458E2C5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C458E2C5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C458E2C5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C458E2C5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C458E2C5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C458E2C5: \n"
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
		"mov ecx, 0x08DDEE8F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x08DDEE8F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x08DDEE8F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x08DDEE8F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_08DDEE8F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_08DDEE8F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_08DDEE8F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_08DDEE8F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_08DDEE8F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_08DDEE8F: \n"
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
		"mov ecx, 0x14ACEEB2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x14ACEEB2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x14ACEEB2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x14ACEEB2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_14ACEEB2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_14ACEEB2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_14ACEEB2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_14ACEEB2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_14ACEEB2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_14ACEEB2: \n"
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
		"mov ecx, 0xC08BE7D8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC08BE7D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC08BE7D8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC08BE7D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C08BE7D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C08BE7D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C08BE7D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C08BE7D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C08BE7D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C08BE7D8: \n"
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
		"mov ecx, 0x7DD5736E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7DD5736E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7DD5736E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7DD5736E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_7DD5736E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7DD5736E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7DD5736E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7DD5736E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7DD5736E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7DD5736E: \n"
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
		"mov ecx, 0x4ED8575E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4ED8575E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4ED8575E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4ED8575E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_4ED8575E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4ED8575E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4ED8575E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4ED8575E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4ED8575E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4ED8575E: \n"
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
		"mov ecx, 0x16B61F22 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x16B61F22 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x16B61F22 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x16B61F22 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_16B61F22: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_16B61F22 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_16B61F22] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_16B61F22 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_16B61F22: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_16B61F22: \n"
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
		"mov ecx, 0x9703BB8B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9703BB8B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9703BB8B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9703BB8B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_9703BB8B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9703BB8B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9703BB8B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9703BB8B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9703BB8B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9703BB8B: \n"
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
		"mov ecx, 0x5AC35072 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5AC35072 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5AC35072 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5AC35072 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_5AC35072: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5AC35072 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5AC35072] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5AC35072 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5AC35072: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5AC35072: \n"
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
		"mov ecx, 0x3975DB25 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3975DB25 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3975DB25 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3975DB25 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3975DB25: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3975DB25 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3975DB25] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3975DB25 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3975DB25: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3975DB25: \n"
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
		"mov ecx, 0x62F26B6E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x62F26B6E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x62F26B6E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x62F26B6E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_62F26B6E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_62F26B6E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_62F26B6E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_62F26B6E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_62F26B6E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_62F26B6E: \n"
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
		"mov ecx, 0x36ACCE31 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36ACCE31 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36ACCE31 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36ACCE31 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_36ACCE31: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36ACCE31 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36ACCE31] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36ACCE31 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36ACCE31: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36ACCE31: \n"
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
		"mov ecx, 0x5603779C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5603779C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5603779C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5603779C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_5603779C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5603779C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5603779C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5603779C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5603779C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5603779C: \n"
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
		"mov ecx, 0x4D1B8BB8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4D1B8BB8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4D1B8BB8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4D1B8BB8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_4D1B8BB8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4D1B8BB8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4D1B8BB8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4D1B8BB8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4D1B8BB8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4D1B8BB8: \n"
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
		"mov ecx, 0x48A30271 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48A30271 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48A30271 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48A30271 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_48A30271: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48A30271 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48A30271] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48A30271 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48A30271: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48A30271: \n"
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
		"mov ecx, 0x168E361D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x168E361D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x168E361D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x168E361D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_168E361D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_168E361D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_168E361D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_168E361D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_168E361D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_168E361D: \n"
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
		"mov ecx, 0x6FB6A1EE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6FB6A1EE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6FB6A1EE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6FB6A1EE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_6FB6A1EE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6FB6A1EE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6FB6A1EE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6FB6A1EE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6FB6A1EE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6FB6A1EE: \n"
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
		"mov ecx, 0x0A90443C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0A90443C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0A90443C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0A90443C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0A90443C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0A90443C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0A90443C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0A90443C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0A90443C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0A90443C: \n"
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
		"mov ecx, 0x351E0DB5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x351E0DB5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x351E0DB5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x351E0DB5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_351E0DB5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_351E0DB5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_351E0DB5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_351E0DB5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_351E0DB5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_351E0DB5: \n"
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
		"mov ecx, 0x78E8B69E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78E8B69E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78E8B69E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78E8B69E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_78E8B69E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78E8B69E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78E8B69E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78E8B69E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78E8B69E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78E8B69E: \n"
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
		"mov ecx, 0x3BAF6762 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3BAF6762 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3BAF6762 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3BAF6762 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3BAF6762: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3BAF6762 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3BAF6762] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3BAF6762 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3BAF6762: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3BAF6762: \n"
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
		"mov ecx, 0x59949A05 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x59949A05 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x59949A05 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x59949A05 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_59949A05: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_59949A05 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_59949A05] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_59949A05 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_59949A05: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_59949A05: \n"
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
		"mov ecx, 0x2B89732C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B89732C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B89732C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B89732C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xd \n"
	"push_argument_2B89732C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B89732C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B89732C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B89732C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B89732C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B89732C: \n"
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
		"mov ecx, 0x50A292F8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x50A292F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x50A292F8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x50A292F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x11 \n"
	"push_argument_50A292F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_50A292F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_50A292F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_50A292F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_50A292F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_50A292F8: \n"
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
		"mov ecx, 0x90CA7792 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x90CA7792 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x90CA7792 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x90CA7792 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_90CA7792: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_90CA7792 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_90CA7792] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_90CA7792 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_90CA7792: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_90CA7792: \n"
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
		"mov ecx, 0xA1E18F7D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA1E18F7D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA1E18F7D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA1E18F7D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_A1E18F7D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A1E18F7D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A1E18F7D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A1E18F7D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A1E18F7D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A1E18F7D: \n"
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
		"mov ecx, 0x922089AD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x922089AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x922089AD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x922089AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xb \n"
	"push_argument_922089AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_922089AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_922089AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_922089AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_922089AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_922089AD: \n"
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
		"mov ecx, 0x0B1D7BD1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0B1D7BD1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0B1D7BD1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0B1D7BD1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0B1D7BD1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0B1D7BD1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0B1D7BD1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0B1D7BD1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0B1D7BD1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0B1D7BD1: \n"
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
		"mov ecx, 0x64F0866E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64F0866E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64F0866E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64F0866E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_64F0866E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64F0866E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64F0866E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64F0866E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64F0866E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64F0866E: \n"
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
		"mov ecx, 0x04BBCD9F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04BBCD9F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04BBCD9F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04BBCD9F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_04BBCD9F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04BBCD9F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04BBCD9F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04BBCD9F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04BBCD9F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04BBCD9F: \n"
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
		"mov ecx, 0x88D966BC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x88D966BC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x88D966BC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x88D966BC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_88D966BC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_88D966BC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_88D966BC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_88D966BC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_88D966BC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_88D966BC: \n"
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
		"mov ecx, 0x763B4F94 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x763B4F94 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x763B4F94 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x763B4F94 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_763B4F94: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_763B4F94 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_763B4F94] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_763B4F94 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_763B4F94: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_763B4F94: \n"
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
		"mov ecx, 0x00932F20 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00932F20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00932F20 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00932F20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_00932F20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00932F20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00932F20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00932F20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00932F20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00932F20: \n"
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
		"mov ecx, 0xDD4EFCDD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDD4EFCDD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDD4EFCDD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDD4EFCDD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DD4EFCDD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DD4EFCDD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DD4EFCDD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DD4EFCDD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DD4EFCDD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DD4EFCDD: \n"
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
		"mov ecx, 0x0D951502 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D951502 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D951502 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D951502 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0D951502: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D951502 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D951502] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D951502 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D951502: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D951502: \n"
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
		"mov ecx, 0x8313978E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8313978E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8313978E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8313978E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_8313978E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8313978E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8313978E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8313978E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8313978E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8313978E: \n"
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
		"mov ecx, 0xD53DEFAB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD53DEFAB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD53DEFAB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD53DEFAB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_D53DEFAB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D53DEFAB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D53DEFAB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D53DEFAB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D53DEFAB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D53DEFAB: \n"
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
		"mov ecx, 0x5A2B4DB0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5A2B4DB0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5A2B4DB0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5A2B4DB0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_5A2B4DB0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5A2B4DB0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5A2B4DB0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5A2B4DB0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5A2B4DB0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5A2B4DB0: \n"
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
		"mov ecx, 0x1AB3CC9A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AB3CC9A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AB3CC9A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AB3CC9A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1AB3CC9A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AB3CC9A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AB3CC9A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AB3CC9A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AB3CC9A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AB3CC9A: \n"
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
		"mov ecx, 0xCB50807E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB50807E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB50807E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB50807E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_CB50807E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB50807E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB50807E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB50807E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB50807E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB50807E: \n"
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
		"mov ecx, 0x0AC32B19 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0AC32B19 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0AC32B19 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0AC32B19 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0AC32B19: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0AC32B19 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0AC32B19] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0AC32B19 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0AC32B19: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0AC32B19: \n"
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
		"mov ecx, 0xBC024910 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC024910 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC024910 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC024910 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_BC024910: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC024910 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC024910] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC024910 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC024910: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC024910: \n"
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
		"mov ecx, 0x5A1CB64E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5A1CB64E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5A1CB64E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5A1CB64E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_5A1CB64E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5A1CB64E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5A1CB64E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5A1CB64E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5A1CB64E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5A1CB64E: \n"
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
		"mov ecx, 0xB7A577B6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB7A577B6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB7A577B6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB7A577B6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_B7A577B6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B7A577B6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B7A577B6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B7A577B6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B7A577B6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B7A577B6: \n"
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
		"mov ecx, 0x1087C6BA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1087C6BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1087C6BA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1087C6BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1087C6BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1087C6BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1087C6BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1087C6BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1087C6BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1087C6BA: \n"
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
		"mov ecx, 0x2CB33B38 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2CB33B38 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2CB33B38 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2CB33B38 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2CB33B38: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2CB33B38 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2CB33B38] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2CB33B38 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2CB33B38: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2CB33B38: \n"
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
		"mov ecx, 0xF86AE6D3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF86AE6D3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF86AE6D3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF86AE6D3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_F86AE6D3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F86AE6D3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F86AE6D3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F86AE6D3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F86AE6D3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F86AE6D3: \n"
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
		"mov ecx, 0xCAA9D206 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCAA9D206 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCAA9D206 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCAA9D206 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CAA9D206: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CAA9D206 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CAA9D206] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CAA9D206 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CAA9D206: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CAA9D206: \n"
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
		"mov ecx, 0x009C0D1F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x009C0D1F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x009C0D1F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x009C0D1F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_009C0D1F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_009C0D1F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_009C0D1F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_009C0D1F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_009C0D1F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_009C0D1F: \n"
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
		"mov ecx, 0x879B7AFF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x879B7AFF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x879B7AFF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x879B7AFF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_879B7AFF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_879B7AFF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_879B7AFF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_879B7AFF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_879B7AFF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_879B7AFF: \n"
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
		"mov ecx, 0xFCC8943D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFCC8943D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFCC8943D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFCC8943D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_FCC8943D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FCC8943D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FCC8943D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FCC8943D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FCC8943D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FCC8943D: \n"
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
		"mov ecx, 0xC28A1826 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC28A1826 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC28A1826 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC28A1826 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C28A1826: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C28A1826 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C28A1826] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C28A1826 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C28A1826: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C28A1826: \n"
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
		"mov ecx, 0x8E96CE38 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8E96CE38 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8E96CE38 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8E96CE38 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8E96CE38: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8E96CE38 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8E96CE38] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8E96CE38 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8E96CE38: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8E96CE38: \n"
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
		"mov ecx, 0x63C43104 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x63C43104 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x63C43104 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x63C43104 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_63C43104: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_63C43104 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_63C43104] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_63C43104 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_63C43104: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_63C43104: \n"
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
		"mov ecx, 0x5CC76604 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5CC76604 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5CC76604 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5CC76604 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xe \n"
	"push_argument_5CC76604: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5CC76604 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5CC76604] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5CC76604 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5CC76604: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5CC76604: \n"
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
		"mov ecx, 0x1694C8F2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1694C8F2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1694C8F2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1694C8F2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1694C8F2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1694C8F2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1694C8F2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1694C8F2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1694C8F2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1694C8F2: \n"
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
		"mov ecx, 0x885FFF83 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x885FFF83 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x885FFF83 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x885FFF83 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_885FFF83: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_885FFF83 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_885FFF83] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_885FFF83 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_885FFF83: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_885FFF83: \n"
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
		"mov ecx, 0x1735C47C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1735C47C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1735C47C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1735C47C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1735C47C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1735C47C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1735C47C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1735C47C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1735C47C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1735C47C: \n"
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
		"mov ecx, 0x78A18DDD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x78A18DDD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x78A18DDD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x78A18DDD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_78A18DDD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_78A18DDD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_78A18DDD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_78A18DDD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_78A18DDD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_78A18DDD: \n"
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
		"mov ecx, 0x48997230 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48997230 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48997230 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48997230 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_48997230: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48997230 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48997230] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48997230 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48997230: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48997230: \n"
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
		"mov ecx, 0x2385210F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2385210F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2385210F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2385210F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_2385210F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2385210F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2385210F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2385210F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2385210F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2385210F: \n"
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
		"mov ecx, 0x9DB8AB3D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9DB8AB3D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9DB8AB3D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9DB8AB3D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_9DB8AB3D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9DB8AB3D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9DB8AB3D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9DB8AB3D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9DB8AB3D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9DB8AB3D: \n"
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
		"mov ecx, 0x00130D93 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00130D93 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00130D93 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00130D93 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_00130D93: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00130D93 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00130D93] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00130D93 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00130D93: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00130D93: \n"
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
		"mov ecx, 0x0C5B06DF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C5B06DF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C5B06DF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C5B06DF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0C5B06DF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C5B06DF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C5B06DF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C5B06DF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C5B06DF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C5B06DF: \n"
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
		"mov ecx, 0x0F9A2909 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0F9A2909 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0F9A2909 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0F9A2909 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0F9A2909: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0F9A2909 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0F9A2909] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0F9A2909 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0F9A2909: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0F9A2909: \n"
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
		"mov ecx, 0x8A9B7B89 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A9B7B89 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8A9B7B89 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8A9B7B89 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_8A9B7B89: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8A9B7B89 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8A9B7B89] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8A9B7B89 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8A9B7B89: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8A9B7B89: \n"
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
		"mov ecx, 0x0137591D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0137591D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0137591D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0137591D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0137591D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0137591D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0137591D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0137591D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0137591D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0137591D: \n"
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
		"mov ecx, 0x93B3CF03 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x93B3CF03 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x93B3CF03 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x93B3CF03 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_93B3CF03: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_93B3CF03 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_93B3CF03] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_93B3CF03 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_93B3CF03: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_93B3CF03: \n"
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
		"mov ecx, 0x3A1B02B1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A1B02B1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A1B02B1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A1B02B1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_3A1B02B1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A1B02B1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A1B02B1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A1B02B1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A1B02B1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A1B02B1: \n"
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
		"mov ecx, 0x36AA7276 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36AA7276 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36AA7276 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36AA7276 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_36AA7276: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36AA7276 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36AA7276] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36AA7276 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36AA7276: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36AA7276: \n"
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
		"mov ecx, 0x74DFA192 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74DFA192 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74DFA192 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74DFA192 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_74DFA192: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74DFA192 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74DFA192] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74DFA192 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74DFA192: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74DFA192: \n"
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
		"mov ecx, 0xBE2DB4B7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBE2DB4B7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBE2DB4B7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBE2DB4B7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_BE2DB4B7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BE2DB4B7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BE2DB4B7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BE2DB4B7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BE2DB4B7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BE2DB4B7: \n"
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
		"mov ecx, 0xF2BC1B20 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF2BC1B20 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF2BC1B20 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF2BC1B20 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_F2BC1B20: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F2BC1B20 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F2BC1B20] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F2BC1B20 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F2BC1B20: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F2BC1B20: \n"
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
		"mov ecx, 0xEC5E37E1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEC5E37E1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEC5E37E1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEC5E37E1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_EC5E37E1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EC5E37E1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EC5E37E1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EC5E37E1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EC5E37E1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EC5E37E1: \n"
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
		"mov ecx, 0x229C270B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x229C270B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x229C270B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x229C270B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_229C270B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_229C270B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_229C270B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_229C270B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_229C270B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_229C270B: \n"
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
		"mov ecx, 0xBDA778F7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBDA778F7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBDA778F7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBDA778F7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_BDA778F7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BDA778F7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BDA778F7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BDA778F7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BDA778F7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BDA778F7: \n"
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
		"mov ecx, 0xEEE616B6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEEE616B6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEEE616B6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEEE616B6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_EEE616B6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EEE616B6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EEE616B6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EEE616B6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EEE616B6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EEE616B6: \n"
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
		"mov ecx, 0x45D13548 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x45D13548 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x45D13548 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x45D13548 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_45D13548: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_45D13548 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_45D13548] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_45D13548 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_45D13548: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_45D13548: \n"
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
		"mov ecx, 0x7C2EA19F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7C2EA19F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7C2EA19F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7C2EA19F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_7C2EA19F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7C2EA19F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7C2EA19F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7C2EA19F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7C2EA19F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7C2EA19F: \n"
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
		"mov ecx, 0x0C93D8D8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C93D8D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C93D8D8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C93D8D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0C93D8D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C93D8D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C93D8D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C93D8D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C93D8D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C93D8D8: \n"
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
		"mov ecx, 0x445E23AC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x445E23AC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x445E23AC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x445E23AC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_445E23AC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_445E23AC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_445E23AC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_445E23AC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_445E23AC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_445E23AC: \n"
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
		"mov ecx, 0x0C8D060D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C8D060D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C8D060D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C8D060D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0C8D060D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C8D060D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C8D060D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C8D060D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C8D060D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C8D060D: \n"
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
		"mov ecx, 0x088285A1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x088285A1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x088285A1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x088285A1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_088285A1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_088285A1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_088285A1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_088285A1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_088285A1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_088285A1: \n"
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
		"mov ecx, 0x02DF710A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x02DF710A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x02DF710A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x02DF710A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_02DF710A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_02DF710A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_02DF710A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_02DF710A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_02DF710A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_02DF710A: \n"
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
		"mov ecx, 0x8F4040EB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8F4040EB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8F4040EB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8F4040EB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_8F4040EB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8F4040EB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8F4040EB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8F4040EB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8F4040EB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8F4040EB: \n"
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
		"mov ecx, 0x3ABF3930 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3ABF3930 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3ABF3930 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3ABF3930 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3ABF3930: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3ABF3930 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3ABF3930] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3ABF3930 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3ABF3930: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3ABF3930: \n"
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
		"mov ecx, 0x2A74D212 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2A74D212 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2A74D212 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2A74D212 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2A74D212: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2A74D212 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2A74D212] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2A74D212 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2A74D212: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2A74D212: \n"
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
		"mov ecx, 0xD28880BB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD28880BB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD28880BB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD28880BB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_D28880BB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D28880BB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D28880BB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D28880BB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D28880BB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D28880BB: \n"
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
		"mov ecx, 0xA8A72480 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA8A72480 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA8A72480 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA8A72480 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A8A72480: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A8A72480 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A8A72480] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A8A72480 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A8A72480: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A8A72480: \n"
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
		"mov ecx, 0x00986101 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00986101 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00986101 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00986101 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_00986101: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00986101 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00986101] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00986101 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00986101: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00986101: \n"
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
		"mov ecx, 0x01988B44 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x01988B44 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x01988B44 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x01988B44 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_01988B44: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_01988B44 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_01988B44] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_01988B44 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_01988B44: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_01988B44: \n"
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
		"mov ecx, 0x6B98AFC4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6B98AFC4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6B98AFC4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6B98AFC4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_6B98AFC4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6B98AFC4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6B98AFC4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6B98AFC4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6B98AFC4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6B98AFC4: \n"
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
		"mov ecx, 0xB4F79CB4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB4F79CB4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB4F79CB4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB4F79CB4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_B4F79CB4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B4F79CB4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B4F79CB4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B4F79CB4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B4F79CB4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B4F79CB4: \n"
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
		"mov ecx, 0xC137C4BE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC137C4BE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC137C4BE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC137C4BE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C137C4BE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C137C4BE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C137C4BE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C137C4BE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C137C4BE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C137C4BE: \n"
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
		"mov ecx, 0x230D396E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x230D396E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x230D396E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x230D396E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_230D396E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_230D396E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_230D396E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_230D396E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_230D396E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_230D396E: \n"
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
		"mov ecx, 0x17991D1B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x17991D1B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x17991D1B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x17991D1B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_17991D1B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_17991D1B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_17991D1B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_17991D1B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_17991D1B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_17991D1B: \n"
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
		"mov ecx, 0x065602C5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x065602C5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x065602C5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x065602C5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_065602C5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_065602C5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_065602C5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_065602C5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_065602C5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_065602C5: \n"
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
		"mov ecx, 0x1BA5574A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1BA5574A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1BA5574A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1BA5574A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1BA5574A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1BA5574A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1BA5574A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1BA5574A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1BA5574A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1BA5574A: \n"
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
		"mov ecx, 0x80AC45FF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x80AC45FF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x80AC45FF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x80AC45FF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_80AC45FF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_80AC45FF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_80AC45FF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_80AC45FF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_80AC45FF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_80AC45FF: \n"
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
		"mov ecx, 0xE27DD0E8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE27DD0E8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE27DD0E8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE27DD0E8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_E27DD0E8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E27DD0E8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E27DD0E8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E27DD0E8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E27DD0E8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E27DD0E8: \n"
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
		"mov ecx, 0x8BB2BC0A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8BB2BC0A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8BB2BC0A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8BB2BC0A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8BB2BC0A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8BB2BC0A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8BB2BC0A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8BB2BC0A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8BB2BC0A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8BB2BC0A: \n"
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
		"mov ecx, 0xFA90D82B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA90D82B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA90D82B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA90D82B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_FA90D82B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA90D82B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA90D82B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA90D82B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA90D82B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA90D82B: \n"
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
		"mov ecx, 0xBDA535A2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBDA535A2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBDA535A2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBDA535A2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_BDA535A2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BDA535A2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BDA535A2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BDA535A2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BDA535A2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BDA535A2: \n"
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
		"mov ecx, 0xC1504847 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC1504847 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC1504847 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC1504847 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C1504847: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C1504847 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C1504847] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C1504847 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C1504847: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C1504847: \n"
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
		"mov ecx, 0x22B91A2E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22B91A2E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22B91A2E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22B91A2E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_22B91A2E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22B91A2E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22B91A2E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22B91A2E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22B91A2E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22B91A2E: \n"
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
		"mov ecx, 0x24966843 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24966843 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24966843 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24966843 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_24966843: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24966843 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24966843] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24966843 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24966843: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24966843: \n"
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
		"mov ecx, 0xA71AB482 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA71AB482 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA71AB482 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA71AB482 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_A71AB482: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A71AB482 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A71AB482] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A71AB482 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A71AB482: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A71AB482: \n"
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
		"mov ecx, 0x0816C250 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0816C250 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0816C250 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0816C250 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_0816C250: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0816C250 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0816C250] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0816C250 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0816C250: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0816C250: \n"
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
		"mov ecx, 0xDA3623BD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDA3623BD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDA3623BD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDA3623BD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x8 \n"
	"push_argument_DA3623BD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DA3623BD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DA3623BD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DA3623BD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DA3623BD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DA3623BD: \n"
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
		"mov ecx, 0x0BD41043 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BD41043 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BD41043 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BD41043 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0BD41043: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BD41043 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BD41043] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BD41043 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BD41043: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BD41043: \n"
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
		"mov ecx, 0x9612BE8B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9612BE8B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9612BE8B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9612BE8B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_9612BE8B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9612BE8B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9612BE8B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9612BE8B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9612BE8B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9612BE8B: \n"
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
		"mov ecx, 0x66D00607 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x66D00607 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x66D00607 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x66D00607 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_66D00607: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_66D00607 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_66D00607] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_66D00607 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_66D00607: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_66D00607: \n"
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
		"mov ecx, 0x1331E24F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1331E24F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1331E24F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1331E24F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1331E24F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1331E24F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1331E24F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1331E24F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1331E24F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1331E24F: \n"
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
		"mov ecx, 0x6B9CB7D8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6B9CB7D8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6B9CB7D8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6B9CB7D8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_6B9CB7D8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6B9CB7D8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6B9CB7D8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6B9CB7D8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6B9CB7D8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6B9CB7D8: \n"
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
		"mov ecx, 0xBCBCE602 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBCBCE602 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBCBCE602 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBCBCE602 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_BCBCE602: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BCBCE602 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BCBCE602] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BCBCE602 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BCBCE602: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BCBCE602: \n"
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
		"mov ecx, 0x22BC6C7A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22BC6C7A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22BC6C7A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22BC6C7A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_22BC6C7A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22BC6C7A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22BC6C7A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22BC6C7A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22BC6C7A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22BC6C7A: \n"
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
		"mov ecx, 0x1A903D0A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A903D0A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A903D0A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A903D0A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1A903D0A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A903D0A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A903D0A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A903D0A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A903D0A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A903D0A: \n"
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
		"mov ecx, 0xD49FD90E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD49FD90E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD49FD90E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD49FD90E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_D49FD90E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D49FD90E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D49FD90E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D49FD90E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D49FD90E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D49FD90E: \n"
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
		"mov ecx, 0xFA65FCF0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA65FCF0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA65FCF0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA65FCF0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xc \n"
	"push_argument_FA65FCF0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA65FCF0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA65FCF0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA65FCF0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA65FCF0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA65FCF0: \n"
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
		"mov ecx, 0x3822388D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3822388D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3822388D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3822388D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3822388D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3822388D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3822388D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3822388D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3822388D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3822388D: \n"
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
		"mov ecx, 0x309FA9AB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x309FA9AB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x309FA9AB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x309FA9AB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_309FA9AB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_309FA9AB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_309FA9AB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_309FA9AB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_309FA9AB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_309FA9AB: \n"
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
		"mov ecx, 0x3D8B1D12 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3D8B1D12 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3D8B1D12 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3D8B1D12 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3D8B1D12: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3D8B1D12 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3D8B1D12] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3D8B1D12 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3D8B1D12: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3D8B1D12: \n"
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
		"mov ecx, 0x100B5ED7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x100B5ED7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x100B5ED7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x100B5ED7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_100B5ED7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_100B5ED7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_100B5ED7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_100B5ED7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_100B5ED7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_100B5ED7: \n"
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
		"mov ecx, 0x079D2F24 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x079D2F24 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x079D2F24 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x079D2F24 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_079D2F24: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_079D2F24 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_079D2F24] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_079D2F24 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_079D2F24: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_079D2F24: \n"
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
		"mov ecx, 0x1E940818 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1E940818 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1E940818 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1E940818 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_1E940818: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1E940818 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1E940818] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1E940818 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1E940818: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1E940818: \n"
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
		"mov ecx, 0xB56ED5F8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB56ED5F8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB56ED5F8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB56ED5F8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_B56ED5F8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B56ED5F8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B56ED5F8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B56ED5F8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B56ED5F8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B56ED5F8: \n"
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
		"mov ecx, 0xAB3BFF98 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB3BFF98 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB3BFF98 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB3BFF98 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_AB3BFF98: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB3BFF98 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB3BFF98] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB3BFF98 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB3BFF98: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB3BFF98: \n"
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
		"mov ecx, 0xF6D624F7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF6D624F7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF6D624F7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF6D624F7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_F6D624F7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F6D624F7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F6D624F7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F6D624F7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F6D624F7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F6D624F7: \n"
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
		"mov ecx, 0x37E4ADE8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x37E4ADE8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x37E4ADE8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x37E4ADE8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_37E4ADE8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_37E4ADE8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_37E4ADE8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_37E4ADE8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_37E4ADE8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_37E4ADE8: \n"
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
		"mov ecx, 0x0E932807 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E932807 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E932807 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E932807 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0E932807: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E932807 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E932807] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E932807 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E932807: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E932807: \n"
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
		"mov ecx, 0x319AE7C2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x319AE7C2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x319AE7C2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x319AE7C2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_319AE7C2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_319AE7C2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_319AE7C2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_319AE7C2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_319AE7C2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_319AE7C2: \n"
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
		"mov ecx, 0x07D76BCF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07D76BCF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07D76BCF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07D76BCF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_07D76BCF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07D76BCF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07D76BCF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07D76BCF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07D76BCF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07D76BCF: \n"
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
		"mov ecx, 0x0698FCC4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0698FCC4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0698FCC4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0698FCC4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0698FCC4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0698FCC4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0698FCC4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0698FCC4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0698FCC4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0698FCC4: \n"
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
		"mov ecx, 0xDB46C4CD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB46C4CD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB46C4CD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB46C4CD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DB46C4CD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB46C4CD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB46C4CD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB46C4CD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB46C4CD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB46C4CD: \n"
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
		"mov ecx, 0x04AA4216 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x04AA4216 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x04AA4216 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x04AA4216 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_04AA4216: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_04AA4216 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_04AA4216] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_04AA4216 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_04AA4216: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_04AA4216: \n"
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
		"mov ecx, 0x7DA3386B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7DA3386B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7DA3386B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7DA3386B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7DA3386B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7DA3386B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7DA3386B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7DA3386B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7DA3386B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7DA3386B: \n"
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
		"mov ecx, 0x36962B31 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36962B31 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36962B31 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36962B31 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_36962B31: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36962B31 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36962B31] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36962B31 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36962B31: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36962B31: \n"
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
		"mov ecx, 0x5A9CDD88 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5A9CDD88 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5A9CDD88 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5A9CDD88 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_5A9CDD88: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5A9CDD88 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5A9CDD88] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5A9CDD88 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5A9CDD88: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5A9CDD88: \n"
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
		"mov ecx, 0x3CB0FF1E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3CB0FF1E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3CB0FF1E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3CB0FF1E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_3CB0FF1E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3CB0FF1E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3CB0FF1E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3CB0FF1E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3CB0FF1E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3CB0FF1E: \n"
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
		"mov ecx, 0x1674FE3A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1674FE3A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1674FE3A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1674FE3A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1674FE3A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1674FE3A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1674FE3A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1674FE3A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1674FE3A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1674FE3A: \n"
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
		"mov ecx, 0x8511C5BD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8511C5BD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8511C5BD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8511C5BD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8511C5BD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8511C5BD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8511C5BD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8511C5BD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8511C5BD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8511C5BD: \n"
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
		"mov ecx, 0x21102C88 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x21102C88 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x21102C88 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x21102C88 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_21102C88: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_21102C88 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_21102C88] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_21102C88 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_21102C88: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_21102C88: \n"
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
		"mov ecx, 0x3F0B23AE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F0B23AE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3F0B23AE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3F0B23AE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3F0B23AE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3F0B23AE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3F0B23AE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3F0B23AE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3F0B23AE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3F0B23AE: \n"
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
		"mov ecx, 0x238CC8F1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x238CC8F1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x238CC8F1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x238CC8F1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_238CC8F1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_238CC8F1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_238CC8F1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_238CC8F1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_238CC8F1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_238CC8F1: \n"
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
		"mov ecx, 0x058B231B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x058B231B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x058B231B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x058B231B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_058B231B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_058B231B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_058B231B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_058B231B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_058B231B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_058B231B: \n"
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
		"mov ecx, 0x348E382C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x348E382C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x348E382C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x348E382C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_348E382C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_348E382C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_348E382C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_348E382C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_348E382C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_348E382C: \n"
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
		"mov ecx, 0xD20911B2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD20911B2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD20911B2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD20911B2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0xa \n"
	"push_argument_D20911B2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D20911B2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D20911B2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D20911B2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D20911B2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D20911B2: \n"
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
		"mov ecx, 0x083738BA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x083738BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x083738BA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x083738BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_083738BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_083738BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_083738BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_083738BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_083738BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_083738BA: \n"
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
		"mov ecx, 0x538E8DA5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x538E8DA5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x538E8DA5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x538E8DA5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_538E8DA5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_538E8DA5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_538E8DA5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_538E8DA5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_538E8DA5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_538E8DA5: \n"
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
		"mov ecx, 0xA606595E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA606595E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA606595E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA606595E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_A606595E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A606595E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A606595E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A606595E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A606595E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A606595E: \n"
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
		"mov ecx, 0xACF27249 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xACF27249 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xACF27249 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xACF27249 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_ACF27249: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_ACF27249 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_ACF27249] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_ACF27249 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_ACF27249: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_ACF27249: \n"
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
		"mov ecx, 0x90F37D63 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x90F37D63 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x90F37D63 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x90F37D63 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_90F37D63: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_90F37D63 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_90F37D63] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_90F37D63 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_90F37D63: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_90F37D63: \n"
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
		"mov ecx, 0xBBDEB1BB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBBDEB1BB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBBDEB1BB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBBDEB1BB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BBDEB1BB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BBDEB1BB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BBDEB1BB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BBDEB1BB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BBDEB1BB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BBDEB1BB: \n"
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
		"mov ecx, 0xB0BBCD59 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB0BBCD59 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB0BBCD59 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB0BBCD59 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_B0BBCD59: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B0BBCD59 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B0BBCD59] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B0BBCD59 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B0BBCD59: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B0BBCD59: \n"
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
		"mov ecx, 0xBB2B8384 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBB2B8384 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBB2B8384 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBB2B8384 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_BB2B8384: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BB2B8384 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BB2B8384] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BB2B8384 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BB2B8384: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BB2B8384: \n"
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
		"mov ecx, 0x64FE616C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x64FE616C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x64FE616C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x64FE616C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_64FE616C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_64FE616C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_64FE616C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_64FE616C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_64FE616C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_64FE616C: \n"
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
		"mov ecx, 0x39AF4D4E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x39AF4D4E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x39AF4D4E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x39AF4D4E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_39AF4D4E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_39AF4D4E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_39AF4D4E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_39AF4D4E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_39AF4D4E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_39AF4D4E: \n"
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
		"mov ecx, 0x010AE019 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x010AE019 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x010AE019 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x010AE019 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_010AE019: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_010AE019 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_010AE019] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_010AE019 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_010AE019: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_010AE019: \n"
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
		"mov ecx, 0xE9BE14D5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE9BE14D5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE9BE14D5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE9BE14D5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E9BE14D5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E9BE14D5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E9BE14D5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E9BE14D5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E9BE14D5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E9BE14D5: \n"
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
		"mov ecx, 0x089A7A62 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x089A7A62 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x089A7A62 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x089A7A62 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_089A7A62: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_089A7A62 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_089A7A62] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_089A7A62 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_089A7A62: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_089A7A62: \n"
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
		"mov ecx, 0xC85FFF83 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC85FFF83 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC85FFF83 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC85FFF83 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C85FFF83: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C85FFF83 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C85FFF83] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C85FFF83 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C85FFF83: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C85FFF83: \n"
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
		"mov ecx, 0xD88AC20E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD88AC20E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD88AC20E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD88AC20E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D88AC20E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D88AC20E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D88AC20E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D88AC20E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D88AC20E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D88AC20E: \n"
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
		"mov ecx, 0xC153E382 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC153E382 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC153E382 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC153E382 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_C153E382: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C153E382 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C153E382] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C153E382 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C153E382: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C153E382: \n"
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
		"mov ecx, 0xA4A0B1D2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA4A0B1D2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA4A0B1D2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA4A0B1D2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_A4A0B1D2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A4A0B1D2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A4A0B1D2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A4A0B1D2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A4A0B1D2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A4A0B1D2: \n"
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
		"mov ecx, 0x0B9E203C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0B9E203C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0B9E203C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0B9E203C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0B9E203C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0B9E203C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0B9E203C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0B9E203C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0B9E203C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0B9E203C: \n"
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
		"mov ecx, 0x004CED15 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x004CED15 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x004CED15 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x004CED15 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_004CED15: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_004CED15 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_004CED15] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_004CED15 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_004CED15: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_004CED15: \n"
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
		"mov ecx, 0x36943D01 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x36943D01 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x36943D01 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x36943D01 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_36943D01: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_36943D01 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_36943D01] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_36943D01 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_36943D01: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_36943D01: \n"
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
		"mov ecx, 0x9D94C948 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9D94C948 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9D94C948 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9D94C948 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9D94C948: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9D94C948 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9D94C948] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9D94C948 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9D94C948: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9D94C948: \n"
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
		"mov ecx, 0x8D1FAEB0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8D1FAEB0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8D1FAEB0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8D1FAEB0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_8D1FAEB0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8D1FAEB0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8D1FAEB0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8D1FAEB0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8D1FAEB0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8D1FAEB0: \n"
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
		"mov ecx, 0x1CB9E222 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1CB9E222 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1CB9E222 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1CB9E222 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_1CB9E222: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1CB9E222 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1CB9E222] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1CB9E222 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1CB9E222: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1CB9E222: \n"
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
		"mov ecx, 0x039D7744 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x039D7744 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x039D7744 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x039D7744 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_039D7744: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_039D7744 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_039D7744] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_039D7744 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_039D7744: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_039D7744: \n"
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
		"mov ecx, 0x07BDFDF3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07BDFDF3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x07BDFDF3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x07BDFDF3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_07BDFDF3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_07BDFDF3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_07BDFDF3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_07BDFDF3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_07BDFDF3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_07BDFDF3: \n"
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
		"mov ecx, 0x1447E933 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1447E933 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1447E933 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1447E933 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1447E933: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1447E933 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1447E933] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1447E933 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1447E933: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1447E933: \n"
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
		"mov ecx, 0x4EC65BB6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4EC65BB6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4EC65BB6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4EC65BB6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_4EC65BB6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4EC65BB6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4EC65BB6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4EC65BB6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4EC65BB6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4EC65BB6: \n"
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
		"mov ecx, 0x12886C65 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x12886C65 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x12886C65 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x12886C65 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_12886C65: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_12886C65 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_12886C65] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_12886C65 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_12886C65: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_12886C65: \n"
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
		"mov ecx, 0xC720C8B1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC720C8B1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC720C8B1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC720C8B1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_C720C8B1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C720C8B1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C720C8B1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C720C8B1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C720C8B1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C720C8B1: \n"
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
		"mov ecx, 0x8B9177EA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B9177EA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B9177EA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B9177EA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_8B9177EA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B9177EA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B9177EA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B9177EA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B9177EA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B9177EA: \n"
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
		"mov ecx, 0x0E91C3D7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0E91C3D7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0E91C3D7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0E91C3D7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0E91C3D7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0E91C3D7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0E91C3D7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0E91C3D7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0E91C3D7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0E91C3D7: \n"
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
		"mov ecx, 0xDE81FE13 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE81FE13 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE81FE13 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE81FE13 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DE81FE13: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE81FE13 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE81FE13] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE81FE13 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE81FE13: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE81FE13: \n"
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
		"mov ecx, 0x2E80703C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2E80703C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2E80703C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2E80703C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_2E80703C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2E80703C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2E80703C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2E80703C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2E80703C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2E80703C: \n"
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
		"mov ecx, 0x0C871005 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C871005 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C871005 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C871005 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_0C871005: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C871005 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C871005] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C871005 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C871005: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C871005: \n"
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
		"mov ecx, 0x58B687F1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x58B687F1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x58B687F1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x58B687F1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_58B687F1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_58B687F1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_58B687F1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_58B687F1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_58B687F1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_58B687F1: \n"
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
		"mov ecx, 0xC299C409 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC299C409 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC299C409 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC299C409 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_C299C409: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C299C409 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C299C409] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C299C409 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C299C409: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C299C409: \n"
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
		"mov ecx, 0x00592403 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x00592403 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x00592403 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x00592403 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_00592403: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_00592403 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_00592403] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_00592403 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_00592403: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_00592403: \n"
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
		"mov ecx, 0xDB45BA9F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB45BA9F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB45BA9F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB45BA9F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_DB45BA9F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB45BA9F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB45BA9F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB45BA9F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB45BA9F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB45BA9F: \n"
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
		"mov ecx, 0xB33BB4A8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB33BB4A8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB33BB4A8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB33BB4A8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B33BB4A8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B33BB4A8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B33BB4A8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B33BB4A8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B33BB4A8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B33BB4A8: \n"
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
		"mov ecx, 0x17370796 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x17370796 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x17370796 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x17370796 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_17370796: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_17370796 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_17370796] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_17370796 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_17370796: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_17370796: \n"
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
		"mov ecx, 0x8D319F92 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8D319F92 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8D319F92 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8D319F92 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_8D319F92: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8D319F92 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8D319F92] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8D319F92 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8D319F92: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8D319F92: \n"
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
		"mov ecx, 0x46CF445F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x46CF445F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x46CF445F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x46CF445F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_46CF445F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_46CF445F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_46CF445F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_46CF445F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_46CF445F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_46CF445F: \n"
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
		"mov ecx, 0xA237C1E8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA237C1E8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA237C1E8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA237C1E8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A237C1E8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A237C1E8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A237C1E8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A237C1E8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A237C1E8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A237C1E8: \n"
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
		"mov ecx, 0x3A9D4B60 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3A9D4B60 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3A9D4B60 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3A9D4B60 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_3A9D4B60: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3A9D4B60 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3A9D4B60] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3A9D4B60 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3A9D4B60: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3A9D4B60: \n"
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
		"mov ecx, 0x72CA4E79 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x72CA4E79 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x72CA4E79 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x72CA4E79 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_72CA4E79: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_72CA4E79 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_72CA4E79] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_72CA4E79 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_72CA4E79: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_72CA4E79: \n"
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
		"mov ecx, 0xB295E04C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB295E04C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB295E04C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB295E04C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_B295E04C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B295E04C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B295E04C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B295E04C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B295E04C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B295E04C: \n"
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
		"mov ecx, 0xC05EB552 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC05EB552 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC05EB552 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC05EB552 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C05EB552: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C05EB552 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C05EB552] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C05EB552 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C05EB552: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C05EB552: \n"
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
		"mov ecx, 0x52E32B11 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x52E32B11 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x52E32B11 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x52E32B11 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_52E32B11: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_52E32B11 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_52E32B11] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_52E32B11 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_52E32B11: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_52E32B11: \n"
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
		"mov ecx, 0xFA3DEEBF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFA3DEEBF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFA3DEEBF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFA3DEEBF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_FA3DEEBF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FA3DEEBF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FA3DEEBF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FA3DEEBF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FA3DEEBF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FA3DEEBF: \n"
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
		"mov ecx, 0xEEABCD31 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEEABCD31 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEEABCD31 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEEABCD31 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_EEABCD31: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EEABCD31 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EEABCD31] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EEABCD31 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EEABCD31: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EEABCD31: \n"
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
		"mov ecx, 0xF373CFF3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF373CFF3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF373CFF3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF373CFF3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_F373CFF3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F373CFF3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F373CFF3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F373CFF3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F373CFF3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F373CFF3: \n"
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
		"mov ecx, 0xE271CFE0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE271CFE0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE271CFE0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE271CFE0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E271CFE0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E271CFE0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E271CFE0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E271CFE0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E271CFE0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E271CFE0: \n"
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
		"mov ecx, 0x28BA0910 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x28BA0910 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x28BA0910 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x28BA0910 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_28BA0910: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_28BA0910 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_28BA0910] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_28BA0910 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_28BA0910: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_28BA0910: \n"
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
		"mov ecx, 0xEB71F2FD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xEB71F2FD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xEB71F2FD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xEB71F2FD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_EB71F2FD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_EB71F2FD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_EB71F2FD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_EB71F2FD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_EB71F2FD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_EB71F2FD: \n"
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
		"mov ecx, 0x056B03F4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x056B03F4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x056B03F4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x056B03F4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_056B03F4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_056B03F4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_056B03F4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_056B03F4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_056B03F4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_056B03F4: \n"
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
		"mov ecx, 0x4A9E3568 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4A9E3568 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4A9E3568 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4A9E3568 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_4A9E3568: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4A9E3568 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4A9E3568] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4A9E3568 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4A9E3568: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4A9E3568: \n"
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
		"mov ecx, 0x398921E4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x398921E4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x398921E4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x398921E4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_398921E4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_398921E4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_398921E4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_398921E4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_398921E4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_398921E4: \n"
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
		"mov ecx, 0x0C962C05 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C962C05 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0C962C05 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0C962C05 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0C962C05: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0C962C05 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0C962C05] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0C962C05 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0C962C05: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0C962C05: \n"
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
		"mov ecx, 0x1EA6FFAA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EA6FFAA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EA6FFAA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EA6FFAA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1EA6FFAA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EA6FFAA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EA6FFAA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EA6FFAA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EA6FFAA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EA6FFAA: \n"
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
		"mov ecx, 0xB4278F90 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB4278F90 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB4278F90 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB4278F90 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B4278F90: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B4278F90 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B4278F90] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B4278F90 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B4278F90: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B4278F90: \n"
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
		"mov ecx, 0x0099200B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0099200B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0099200B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0099200B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0099200B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0099200B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0099200B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0099200B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0099200B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0099200B: \n"
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
		"mov ecx, 0xBC0FE2A3 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBC0FE2A3 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBC0FE2A3 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBC0FE2A3 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_BC0FE2A3: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BC0FE2A3 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BC0FE2A3] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BC0FE2A3 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BC0FE2A3: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BC0FE2A3: \n"
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
		"mov ecx, 0x832FA872 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x832FA872 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x832FA872 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x832FA872 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_832FA872: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_832FA872 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_832FA872] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_832FA872 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_832FA872: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_832FA872: \n"
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
		"mov ecx, 0x9F01627A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9F01627A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9F01627A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9F01627A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_9F01627A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9F01627A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9F01627A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9F01627A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9F01627A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9F01627A: \n"
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
		"mov ecx, 0x737A7FC1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x737A7FC1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x737A7FC1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x737A7FC1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_737A7FC1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_737A7FC1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_737A7FC1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_737A7FC1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_737A7FC1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_737A7FC1: \n"
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
		"mov ecx, 0x479C4216 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x479C4216 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x479C4216 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x479C4216 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_479C4216: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_479C4216 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_479C4216] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_479C4216 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_479C4216: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_479C4216: \n"
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
		"mov ecx, 0x24B5031E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x24B5031E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x24B5031E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x24B5031E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_24B5031E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_24B5031E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_24B5031E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_24B5031E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_24B5031E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_24B5031E: \n"
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
		"mov ecx, 0x9F0E9598 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9F0E9598 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9F0E9598 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9F0E9598 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_9F0E9598: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9F0E9598 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9F0E9598] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9F0E9598 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9F0E9598: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9F0E9598: \n"
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
		"mov ecx, 0x8B0F9D6B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B0F9D6B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B0F9D6B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B0F9D6B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_8B0F9D6B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B0F9D6B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B0F9D6B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B0F9D6B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B0F9D6B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B0F9D6B: \n"
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
		"mov ecx, 0xD41CD296 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD41CD296 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD41CD296 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD41CD296 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_D41CD296: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D41CD296 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D41CD296] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D41CD296 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D41CD296: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D41CD296: \n"
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
		"mov ecx, 0x1D7CE210 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1D7CE210 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1D7CE210 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1D7CE210 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1D7CE210: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1D7CE210 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1D7CE210] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1D7CE210 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1D7CE210: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1D7CE210: \n"
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
		"mov ecx, 0x0D61CCF2 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D61CCF2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D61CCF2 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D61CCF2 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0D61CCF2: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D61CCF2 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D61CCF2] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D61CCF2 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D61CCF2: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D61CCF2: \n"
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
		"mov ecx, 0xB09F6BA1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB09F6BA1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB09F6BA1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB09F6BA1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B09F6BA1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B09F6BA1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B09F6BA1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B09F6BA1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B09F6BA1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B09F6BA1: \n"
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
		"mov ecx, 0x3697E4AA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3697E4AA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3697E4AA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3697E4AA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3697E4AA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3697E4AA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3697E4AA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3697E4AA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3697E4AA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3697E4AA: \n"
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
		"mov ecx, 0xA43FA7A0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA43FA7A0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA43FA7A0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA43FA7A0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A43FA7A0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A43FA7A0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A43FA7A0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A43FA7A0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A43FA7A0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A43FA7A0: \n"
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
		"mov ecx, 0x1FA7C481 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1FA7C481 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1FA7C481 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1FA7C481 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_1FA7C481: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1FA7C481 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1FA7C481] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1FA7C481 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1FA7C481: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1FA7C481: \n"
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
		"mov ecx, 0xDE4D22D4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDE4D22D4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDE4D22D4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDE4D22D4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DE4D22D4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DE4D22D4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DE4D22D4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DE4D22D4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DE4D22D4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DE4D22D4: \n"
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
		"mov ecx, 0xCB0FDD8B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB0FDD8B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB0FDD8B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB0FDD8B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_CB0FDD8B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB0FDD8B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB0FDD8B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB0FDD8B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB0FDD8B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB0FDD8B: \n"
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
		"mov ecx, 0x65242B86 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x65242B86 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x65242B86 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x65242B86 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_65242B86: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_65242B86 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_65242B86] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_65242B86 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_65242B86: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_65242B86: \n"
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
		"mov ecx, 0x213C37AB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x213C37AB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x213C37AB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x213C37AB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_213C37AB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_213C37AB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_213C37AB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_213C37AB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_213C37AB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_213C37AB: \n"
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
		"mov ecx, 0xAFB0AF26 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAFB0AF26 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAFB0AF26 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAFB0AF26 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AFB0AF26: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AFB0AF26 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AFB0AF26] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AFB0AF26 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AFB0AF26: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AFB0AF26: \n"
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
		"mov ecx, 0x805FE485 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x805FE485 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x805FE485 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x805FE485 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_805FE485: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_805FE485 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_805FE485] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_805FE485 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_805FE485: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_805FE485: \n"
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
		"mov ecx, 0xAB27C3FA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAB27C3FA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAB27C3FA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAB27C3FA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_AB27C3FA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AB27C3FA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AB27C3FA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AB27C3FA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AB27C3FA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AB27C3FA: \n"
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
		"mov ecx, 0x98F9A0BD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x98F9A0BD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x98F9A0BD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x98F9A0BD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_98F9A0BD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_98F9A0BD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_98F9A0BD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_98F9A0BD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_98F9A0BD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_98F9A0BD: \n"
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
		"mov ecx, 0x1AB45419 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1AB45419 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1AB45419 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1AB45419 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1AB45419: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1AB45419 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1AB45419] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1AB45419 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1AB45419: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1AB45419: \n"
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
		"mov ecx, 0x9791B40D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9791B40D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9791B40D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9791B40D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9791B40D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9791B40D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9791B40D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9791B40D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9791B40D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9791B40D: \n"
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
		"mov ecx, 0x1BC37D30 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1BC37D30 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1BC37D30 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1BC37D30 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_1BC37D30: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1BC37D30 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1BC37D30] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1BC37D30 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1BC37D30: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1BC37D30: \n"
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
		"mov ecx, 0xA7318BAA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA7318BAA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA7318BAA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA7318BAA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_A7318BAA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A7318BAA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A7318BAA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A7318BAA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A7318BAA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A7318BAA: \n"
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
		"mov ecx, 0x8B93FF14 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8B93FF14 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8B93FF14 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8B93FF14 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_8B93FF14: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8B93FF14 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8B93FF14] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8B93FF14 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8B93FF14: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8B93FF14: \n"
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
		"mov ecx, 0x9803FA97 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9803FA97 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9803FA97 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9803FA97 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_9803FA97: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9803FA97 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9803FA97] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9803FA97 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9803FA97: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9803FA97: \n"
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
		"mov ecx, 0x0B2361DB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0B2361DB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0B2361DB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0B2361DB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0B2361DB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0B2361DB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0B2361DB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0B2361DB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0B2361DB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0B2361DB: \n"
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
		"mov ecx, 0x1F940F1D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1F940F1D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1F940F1D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1F940F1D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_1F940F1D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1F940F1D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1F940F1D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1F940F1D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1F940F1D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1F940F1D: \n"
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
		"mov ecx, 0x408C5E14 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x408C5E14 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x408C5E14 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x408C5E14 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_408C5E14: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_408C5E14 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_408C5E14] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_408C5E14 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_408C5E14: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_408C5E14: \n"
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
		"mov ecx, 0x0293D4AE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0293D4AE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0293D4AE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0293D4AE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0293D4AE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0293D4AE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0293D4AE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0293D4AE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0293D4AE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0293D4AE: \n"
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
		"mov ecx, 0x1A075CAF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A075CAF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1A075CAF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1A075CAF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_1A075CAF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1A075CAF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1A075CAF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1A075CAF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1A075CAF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1A075CAF: \n"
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
		"mov ecx, 0x5CA8631F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5CA8631F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5CA8631F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5CA8631F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_5CA8631F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5CA8631F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5CA8631F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5CA8631F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5CA8631F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5CA8631F: \n"
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
		"mov ecx, 0x9100929E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9100929E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x9100929E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x9100929E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_9100929E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_9100929E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_9100929E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_9100929E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_9100929E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_9100929E: \n"
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
		"mov ecx, 0x13304DFC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x13304DFC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x13304DFC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x13304DFC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_13304DFC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_13304DFC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_13304DFC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_13304DFC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_13304DFC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_13304DFC: \n"
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
		"mov ecx, 0x2490043D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2490043D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2490043D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2490043D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2490043D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2490043D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2490043D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2490043D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2490043D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2490043D: \n"
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
		"mov ecx, 0x67A92513 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x67A92513 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x67A92513 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x67A92513 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_67A92513: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_67A92513 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_67A92513] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_67A92513 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_67A92513: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_67A92513: \n"
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
		"mov ecx, 0x8CA7E45B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8CA7E45B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x8CA7E45B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x8CA7E45B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_8CA7E45B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_8CA7E45B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_8CA7E45B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_8CA7E45B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_8CA7E45B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_8CA7E45B: \n"
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
		"mov ecx, 0x3CAFEBFC \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3CAFEBFC \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3CAFEBFC \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3CAFEBFC \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_3CAFEBFC: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3CAFEBFC \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3CAFEBFC] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3CAFEBFC \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3CAFEBFC: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3CAFEBFC: \n"
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
		"mov ecx, 0xCF521A0E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCF521A0E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCF521A0E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCF521A0E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_CF521A0E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CF521A0E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CF521A0E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CF521A0E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CF521A0E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CF521A0E: \n"
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
		"mov ecx, 0xDB8EBB5C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDB8EBB5C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDB8EBB5C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDB8EBB5C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_DB8EBB5C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DB8EBB5C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DB8EBB5C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DB8EBB5C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DB8EBB5C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DB8EBB5C: \n"
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
		"mov ecx, 0x0D4C13F6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D4C13F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D4C13F6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D4C13F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_0D4C13F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D4C13F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D4C13F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D4C13F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D4C13F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D4C13F6: \n"
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
		"mov ecx, 0xE9B3D8E5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE9B3D8E5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE9B3D8E5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE9B3D8E5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_E9B3D8E5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E9B3D8E5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E9B3D8E5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E9B3D8E5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E9B3D8E5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E9B3D8E5: \n"
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
		"mov ecx, 0x0CAEFCA4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0CAEFCA4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0CAEFCA4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0CAEFCA4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_0CAEFCA4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0CAEFCA4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0CAEFCA4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0CAEFCA4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0CAEFCA4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0CAEFCA4: \n"
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
		"mov ecx, 0x06A7C536 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06A7C536 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06A7C536 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06A7C536 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_06A7C536: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06A7C536 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06A7C536] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06A7C536 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06A7C536: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06A7C536: \n"
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
		"mov ecx, 0x30A1FDE4 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x30A1FDE4 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x30A1FDE4 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x30A1FDE4 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_30A1FDE4: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_30A1FDE4 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_30A1FDE4] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_30A1FDE4 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_30A1FDE4: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_30A1FDE4: \n"
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
		"mov ecx, 0x3C521CC5 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3C521CC5 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3C521CC5 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3C521CC5 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_3C521CC5: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3C521CC5 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3C521CC5] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3C521CC5 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3C521CC5: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3C521CC5: \n"
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
		"mov ecx, 0x7BAAF598 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7BAAF598 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7BAAF598 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7BAAF598 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_7BAAF598: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7BAAF598 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7BAAF598] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7BAAF598 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7BAAF598: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7BAAF598: \n"
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
		"mov ecx, 0xE97E122F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE97E122F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE97E122F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE97E122F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_E97E122F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E97E122F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E97E122F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E97E122F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E97E122F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E97E122F: \n"
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
		"mov ecx, 0x62CC6340 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x62CC6340 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x62CC6340 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x62CC6340 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_62CC6340: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_62CC6340 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_62CC6340] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_62CC6340 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_62CC6340: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_62CC6340: \n"
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
		"mov ecx, 0xC0903994 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC0903994 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC0903994 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC0903994 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_C0903994: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C0903994 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C0903994] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C0903994 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C0903994: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C0903994: \n"
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
		"mov ecx, 0x075E27F6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x075E27F6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x075E27F6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x075E27F6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_075E27F6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_075E27F6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_075E27F6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_075E27F6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_075E27F6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_075E27F6: \n"
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
		"mov ecx, 0x0BB8330C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BB8330C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BB8330C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BB8330C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0BB8330C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BB8330C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BB8330C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BB8330C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BB8330C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BB8330C: \n"
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
		"mov ecx, 0x2896182B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2896182B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2896182B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2896182B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2896182B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2896182B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2896182B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2896182B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2896182B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2896182B: \n"
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
		"mov ecx, 0x0D2B820E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D2B820E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0D2B820E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0D2B820E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0D2B820E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0D2B820E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0D2B820E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0D2B820E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0D2B820E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0D2B820E: \n"
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
		"mov ecx, 0x049DC2C0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x049DC2C0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x049DC2C0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x049DC2C0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_049DC2C0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_049DC2C0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_049DC2C0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_049DC2C0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_049DC2C0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_049DC2C0: \n"
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
		"mov ecx, 0x26B73B0E \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x26B73B0E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x26B73B0E \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x26B73B0E \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_26B73B0E: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_26B73B0E \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_26B73B0E] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_26B73B0E \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_26B73B0E: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_26B73B0E: \n"
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
		"mov ecx, 0x4D9F6A0C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4D9F6A0C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x4D9F6A0C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x4D9F6A0C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_4D9F6A0C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_4D9F6A0C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_4D9F6A0C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_4D9F6A0C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_4D9F6A0C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_4D9F6A0C: \n"
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
		"mov ecx, 0x16462410 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x16462410 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x16462410 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x16462410 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_16462410: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_16462410 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_16462410] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_16462410 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_16462410: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_16462410: \n"
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
		"mov ecx, 0x0BDC073F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BDC073F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BDC073F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BDC073F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_0BDC073F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BDC073F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BDC073F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BDC073F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BDC073F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BDC073F: \n"
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
		"mov ecx, 0x2B501FD8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2B501FD8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2B501FD8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2B501FD8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_2B501FD8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2B501FD8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2B501FD8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2B501FD8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2B501FD8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2B501FD8: \n"
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
		"mov ecx, 0xA92847BA \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA92847BA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA92847BA \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA92847BA \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_A92847BA: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A92847BA \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A92847BA] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A92847BA \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A92847BA: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A92847BA: \n"
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
		"mov ecx, 0xC957E309 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC957E309 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC957E309 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC957E309 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C957E309: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C957E309 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C957E309] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C957E309 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C957E309: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C957E309: \n"
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
		"mov ecx, 0x0ECE7433 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0ECE7433 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0ECE7433 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0ECE7433 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_0ECE7433: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0ECE7433 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0ECE7433] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0ECE7433 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0ECE7433: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0ECE7433: \n"
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
		"mov ecx, 0xC59C37FB \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC59C37FB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC59C37FB \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC59C37FB \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C59C37FB: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C59C37FB \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C59C37FB] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C59C37FB \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C59C37FB: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C59C37FB: \n"
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
		"mov ecx, 0xF8533C02 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF8533C02 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xF8533C02 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xF8533C02 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x6 \n"
	"push_argument_F8533C02: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_F8533C02 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_F8533C02] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_F8533C02 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_F8533C02: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_F8533C02: \n"
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
		"mov ecx, 0x71D3EDE7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x71D3EDE7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x71D3EDE7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x71D3EDE7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_71D3EDE7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_71D3EDE7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_71D3EDE7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_71D3EDE7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_71D3EDE7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_71D3EDE7: \n"
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
		"mov ecx, 0x0BA76273 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0BA76273 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0BA76273 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0BA76273 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_0BA76273: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0BA76273 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0BA76273] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0BA76273 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0BA76273: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0BA76273: \n"
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
		"mov ecx, 0x1EC76E06 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1EC76E06 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1EC76E06 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1EC76E06 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_1EC76E06: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1EC76E06 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1EC76E06] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1EC76E06 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1EC76E06: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1EC76E06: \n"
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
		"mov ecx, 0x2832099B \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x2832099B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x2832099B \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x2832099B \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_2832099B: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_2832099B \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_2832099B] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_2832099B \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_2832099B: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_2832099B: \n"
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
		"mov ecx, 0xB31A4936 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB31A4936 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB31A4936 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB31A4936 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_B31A4936: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B31A4936 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B31A4936] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B31A4936 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B31A4936: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B31A4936: \n"
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
		"mov ecx, 0xBBA9FF54 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xBBA9FF54 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xBBA9FF54 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xBBA9FF54 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_BBA9FF54: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_BBA9FF54 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_BBA9FF54] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_BBA9FF54 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_BBA9FF54: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_BBA9FF54: \n"
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
		"mov ecx, 0x22BF0A30 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22BF0A30 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x22BF0A30 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x22BF0A30 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x5 \n"
	"push_argument_22BF0A30: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_22BF0A30 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_22BF0A30] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_22BF0A30 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_22BF0A30: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_22BF0A30: \n"
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
		"mov ecx, 0x0291343C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0291343C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x0291343C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x0291343C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_0291343C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_0291343C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_0291343C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_0291343C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_0291343C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_0291343C: \n"
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
		"mov ecx, 0xCD510125 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCD510125 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCD510125 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCD510125 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_CD510125: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CD510125 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CD510125] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CD510125 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CD510125: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CD510125: \n"
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
		"mov ecx, 0xA625A780 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA625A780 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA625A780 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA625A780 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A625A780: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A625A780 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A625A780] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A625A780 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A625A780: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A625A780: \n"
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
		"mov ecx, 0x74DA80B0 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x74DA80B0 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x74DA80B0 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x74DA80B0 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x7 \n"
	"push_argument_74DA80B0: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_74DA80B0 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_74DA80B0] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_74DA80B0 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_74DA80B0: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_74DA80B0: \n"
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
		"mov ecx, 0x77A985EF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x77A985EF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x77A985EF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x77A985EF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_77A985EF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_77A985EF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_77A985EF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_77A985EF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_77A985EF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_77A985EF: \n"
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
		"mov ecx, 0x6AB4AC16 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6AB4AC16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6AB4AC16 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6AB4AC16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_6AB4AC16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6AB4AC16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6AB4AC16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6AB4AC16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6AB4AC16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6AB4AC16: \n"
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
		"mov ecx, 0x48814B16 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48814B16 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x48814B16 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x48814B16 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_48814B16: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_48814B16 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_48814B16] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_48814B16 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_48814B16: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_48814B16: \n"
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
		"mov ecx, 0xD009F598 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD009F598 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xD009F598 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xD009F598 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_D009F598: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_D009F598 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_D009F598] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_D009F598 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_D009F598: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_D009F598: \n"
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
		"mov ecx, 0x7CE36A72 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7CE36A72 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7CE36A72 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7CE36A72 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_7CE36A72: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7CE36A72 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7CE36A72] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7CE36A72 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7CE36A72: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7CE36A72: \n"
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
		"mov ecx, 0xB91EAD98 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB91EAD98 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xB91EAD98 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xB91EAD98 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_B91EAD98: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_B91EAD98 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_B91EAD98] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_B91EAD98 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_B91EAD98: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_B91EAD98: \n"
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
		"mov ecx, 0xA836AEA1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA836AEA1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA836AEA1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA836AEA1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_A836AEA1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A836AEA1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A836AEA1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A836AEA1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A836AEA1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A836AEA1: \n"
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
		"mov ecx, 0x910FC9A7 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x910FC9A7 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x910FC9A7 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x910FC9A7 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_910FC9A7: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_910FC9A7 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_910FC9A7] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_910FC9A7 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_910FC9A7: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_910FC9A7: \n"
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
		"mov ecx, 0xE78AF900 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE78AF900 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE78AF900 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE78AF900 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_E78AF900: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E78AF900 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E78AF900] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E78AF900 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E78AF900: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E78AF900: \n"
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
		"mov ecx, 0xDF43C7D6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xDF43C7D6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xDF43C7D6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xDF43C7D6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_DF43C7D6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_DF43C7D6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_DF43C7D6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_DF43C7D6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_DF43C7D6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_DF43C7D6: \n"
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
		"mov ecx, 0x978CF49D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x978CF49D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x978CF49D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x978CF49D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_978CF49D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_978CF49D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_978CF49D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_978CF49D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_978CF49D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_978CF49D: \n"
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
		"mov ecx, 0x183016AD \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x183016AD \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x183016AD \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x183016AD \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_183016AD: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_183016AD \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_183016AD] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_183016AD \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_183016AD: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_183016AD: \n"
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
		"mov ecx, 0x30AA1039 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x30AA1039 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x30AA1039 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x30AA1039 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x3 \n"
	"push_argument_30AA1039: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_30AA1039 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_30AA1039] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_30AA1039 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_30AA1039: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_30AA1039: \n"
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
		"mov ecx, 0x18C93682 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x18C93682 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x18C93682 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x18C93682 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_18C93682: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_18C93682 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_18C93682] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_18C93682 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_18C93682: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_18C93682: \n"
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
		"mov ecx, 0xFE9CCC26 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFE9CCC26 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xFE9CCC26 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xFE9CCC26 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x9 \n"
	"push_argument_FE9CCC26: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_FE9CCC26 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_FE9CCC26] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_FE9CCC26 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_FE9CCC26: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_FE9CCC26: \n"
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
		"mov ecx, 0x6C83611A \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x6C83611A \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x6C83611A \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x6C83611A \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_6C83611A: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_6C83611A \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_6C83611A] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_6C83611A \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_6C83611A: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_6C83611A: \n"
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
		"mov ecx, 0x06B8072C \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x06B8072C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x06B8072C \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x06B8072C \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_06B8072C: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_06B8072C \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_06B8072C] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_06B8072C \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_06B8072C: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_06B8072C: \n"
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
		"mov ecx, 0x7BE87D73 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7BE87D73 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x7BE87D73 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x7BE87D73 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_7BE87D73: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_7BE87D73 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_7BE87D73] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_7BE87D73 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_7BE87D73: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_7BE87D73: \n"
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
		"mov ecx, 0x5ACC4065 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5ACC4065 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x5ACC4065 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x5ACC4065 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_5ACC4065: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_5ACC4065 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_5ACC4065] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_5ACC4065 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_5ACC4065: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_5ACC4065: \n"
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
		"mov ecx, 0xA3F3DF19 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xA3F3DF19 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xA3F3DF19 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xA3F3DF19 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_A3F3DF19: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_A3F3DF19 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_A3F3DF19] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_A3F3DF19 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_A3F3DF19: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_A3F3DF19: \n"
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
		"mov ecx, 0xCB55000D \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCB55000D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xCB55000D \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xCB55000D \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_CB55000D: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_CB55000D \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_CB55000D] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_CB55000D \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_CB55000D: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_CB55000D: \n"
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
		"mov ecx, 0x1B5BFD2F \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1B5BFD2F \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x1B5BFD2F \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x1B5BFD2F \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_1B5BFD2F: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_1B5BFD2F \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_1B5BFD2F] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_1B5BFD2F \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_1B5BFD2F: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_1B5BFD2F: \n"
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
		"mov ecx, 0xC78A00FF \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC78A00FF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC78A00FF \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC78A00FF \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x0 \n"
	"push_argument_C78A00FF: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C78A00FF \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C78A00FF] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C78A00FF \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C78A00FF: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C78A00FF: \n"
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
		"mov ecx, 0x913E5A60 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x913E5A60 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x913E5A60 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x913E5A60 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_913E5A60: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_913E5A60 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_913E5A60] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_913E5A60 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_913E5A60: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_913E5A60: \n"
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
		"mov ecx, 0x3DA722C8 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3DA722C8 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x3DA722C8 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x3DA722C8 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_3DA722C8: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_3DA722C8 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_3DA722C8] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_3DA722C8 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_3DA722C8: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_3DA722C8: \n"
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
		"mov ecx, 0x130778D6 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x130778D6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0x130778D6 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0x130778D6 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_130778D6: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_130778D6 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_130778D6] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_130778D6 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_130778D6: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_130778D6: \n"
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
		"mov ecx, 0xAA8EA323 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xAA8EA323 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xAA8EA323 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xAA8EA323 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x1 \n"
	"push_argument_AA8EA323: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_AA8EA323 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_AA8EA323] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_AA8EA323 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_AA8EA323: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_AA8EA323: \n"
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
		"mov ecx, 0xE05AFCFE \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xE05AFCFE \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xE05AFCFE \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xE05AFCFE \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x4 \n"
	"push_argument_E05AFCFE: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_E05AFCFE \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_E05AFCFE] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_E05AFCFE \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_E05AFCFE: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_E05AFCFE: \n"
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
		"mov ecx, 0xC7DC02A1 \n"
		"call SW3_GetRandomSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC7DC02A1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
#else
		"push ebp \n"
		"mov ebp, esp \n"
		"push 0xC7DC02A1 \n"
		"call _SW3_GetRandomSyscallAddress \n"
		"mov edi, eax \n"
		"push 0xC7DC02A1 \n"
		"call _SW3_GetSyscallNumber \n"
		"lea esp, [esp+4] \n"
		"mov ecx, 0x2 \n"
	"push_argument_C7DC02A1: \n"
		"dec ecx \n"
		"push [ebp + 8 + ecx * 4] \n"
		"jnz push_argument_C7DC02A1 \n"
		"mov ecx, eax \n"
		"mov eax, ecx \n"
		"lea ebx, [ret_address_epilog_C7DC02A1] \n"
		"push ebx \n"
		"call do_sysenter_interrupt_C7DC02A1 \n"
		"lea esp, [esp+4] \n"
	"ret_address_epilog_C7DC02A1: \n"
		"mov esp, ebp \n"
		"pop ebp \n"
		"ret \n"
	"do_sysenter_interrupt_C7DC02A1: \n"
		"mov edx, esp \n"
		"jmp edi \n"
		"ret \n"
#endif
	);
}

#endif
