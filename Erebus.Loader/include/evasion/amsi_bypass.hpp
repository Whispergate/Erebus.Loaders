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

    // Patchless bypass: arm a hardware execute breakpoint (Dr0) on the
    // first instruction of AmsiScanBuffer and install a vectored exception
    // handler that intercepts the resulting #DB. The handler writes
    // AMSI_RESULT_CLEAN to the caller's result pointer (6th arg), forges
    // a return (RAX=S_OK, RIP=[RSP], RSP+=8) and continues execution -
    // AmsiScanBuffer's code itself is never run and its bytes are never
    // modified, defeating PG/CFG integrity checks and signature scans
    // that look for the classic xor/ret patch. Coverage is limited to
    // threads with Dr0 set: this implementation arms the current thread
    // only - sufficient when the loader executes AMSI-relevant code on
    // its own thread (e.g. self-inject + .NET assembly load).
    // Refs: CCob patchless-AMSI gist, CrowdStrike patchless analysis.
    // Requires CONFIG_AMSI_BYPASS_TYPE >= 4.
    BOOL PatchlessAmsi();

} // namespace evasion
} // namespace erebus

#endif // EREBUS_AMSI_BYPASS_HPP
