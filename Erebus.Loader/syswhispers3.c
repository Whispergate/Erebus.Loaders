#include "syswhispers3.h"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x238632EA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x238632EA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x48A586D2 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x48A586D2 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xC2BAA154 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xC2BAA154 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xF5C662EF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xF5C662EF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtTestAlert()
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x8A01E39C \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x8A01E39C \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x11B1D91D \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x11B1D91D \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendProcess(
	IN HANDLE ProcessHandle)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x472D48B6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x472D48B6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x7A5564EF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x7A5564EF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeProcess(
	IN HANDLE ProcessHandle)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x654F1ABF \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x654F1ABF \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xCC600EC6 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xCC600EC6 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x745FFA75 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x745FFA75 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x123E5D15 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x123E5D15 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtClose(
	IN HANDLE Handle)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB4159397 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB4159397 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0D9E8491 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0D9E8491 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x07910D03 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x07910D03 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0B9C13FB \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0B9C13FB \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x4D942373 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x4D942373 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x3F932501 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x3F932501 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x0C992C4B \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x0C992C4B \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1A38C21E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1A38C21E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x22B9B08E \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x22B9B08E \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x613E9A50 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x613E9A50 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x9C3B9AA1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x9C3B9AA1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x5A9C7441 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x5A9C7441 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xB220B0B1 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xB220B0B1 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x76AC1471 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x76AC1471 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

__declspec(naked) NTSTATUS Sw3NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress)
{
	asm(
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x108A0E07 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x108A0E07 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x67E15562 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x67E15562 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xD5430907 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xD5430907 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0x1520EA23 \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0x1520EA23 \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
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
		"mov [rsp +8], rcx \n"
		"mov [rsp+16], rdx \n"
		"mov [rsp+24], r8 \n"
		"mov [rsp+32], r9 \n"
		"sub rsp, 0x28 \n"
		"mov ecx, 0xFDA004CA \n"
		"call SW3_GetSyscallAddress \n"
		"mov r11, rax \n"
		"mov ecx, 0xFDA004CA \n"
		"call SW3_GetSyscallNumber \n"
		"add rsp, 0x28 \n"
		"mov rcx, [rsp+8] \n"
		"mov rdx, [rsp+16] \n"
		"mov r8, [rsp+24] \n"
		"mov r9, [rsp+32] \n"
		"mov r10, rcx \n"
		"jmp r11 \n"
	);
}

#endif
