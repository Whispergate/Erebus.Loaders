// Include Syscalls.h BEFORE loader.hpp to avoid redefinition of UNICODE_STRING,
// CLIENT_ID, IO_STATUS_BLOCK, and other NT types that loader.hpp also defines
// under its #ifndef _WINTERNL_ guard. After Syscalls.h defines them, we set
// _WINTERNL_ so loader.hpp skips its duplicate block. H() and the ImportModule/
// ImportFunction macros live outside that block and are still available.
#include "../../include/evasion/sw3/Syscalls.h"
#define _WINTERNL_
#include "../../include/loader.hpp"
#include "../../include/evasion/syscall_backend.hpp"

#if CONFIG_SYSCALL_BACKEND == 1

namespace erebus {
namespace evasion {

struct SW3Entry {
    ULONG Hash;
    PVOID Stub;
};

static SW3Entry g_sw3_table[] = {
    { H("NtProtectVirtualMemory"),    (PVOID)Sw3NtProtectVirtualMemory    },
    { H("NtAllocateVirtualMemory"),   (PVOID)Sw3NtAllocateVirtualMemory   },
    { H("NtWriteVirtualMemory"),      (PVOID)Sw3NtWriteVirtualMemory      },
    { H("NtReadVirtualMemory"),       (PVOID)Sw3NtReadVirtualMemory       },
    { H("NtFreeVirtualMemory"),       (PVOID)Sw3NtFreeVirtualMemory       },
    { H("NtCreateSection"),           (PVOID)Sw3NtCreateSection           },
    { H("NtMapViewOfSection"),        (PVOID)Sw3NtMapViewOfSection        },
    { H("NtUnmapViewOfSection"),      (PVOID)Sw3NtUnmapViewOfSection      },
    { H("NtCreateThreadEx"),          (PVOID)Sw3NtCreateThreadEx          },
    { H("NtQueueApcThread"),          (PVOID)Sw3NtQueueApcThread          },
    { H("NtOpenProcess"),             (PVOID)Sw3NtOpenProcess             },
    { H("NtQueryInformationProcess"), (PVOID)Sw3NtQueryInformationProcess },
    { H("NtSetInformationProcess"),   (PVOID)Sw3NtSetInformationProcess   },
    { H("NtWaitForSingleObject"),     (PVOID)Sw3NtWaitForSingleObject     },
    { H("NtClose"),                   (PVOID)Sw3NtClose                   },
};
static const SIZE_T g_sw3_count = sizeof(g_sw3_table) / sizeof(g_sw3_table[0]);

BOOL InitSyscallBackend()
{
    return SW3_PopulateSyscallList();
}

PVOID GetSyscallStub(ULONG funcHash)
{
    for (SIZE_T i = 0; i < g_sw3_count; i++)
        if (g_sw3_table[i].Hash == funcHash)
            return g_sw3_table[i].Stub;
    return NULL;
}

} // namespace evasion
} // namespace erebus

#endif // CONFIG_SYSCALL_BACKEND == 1
