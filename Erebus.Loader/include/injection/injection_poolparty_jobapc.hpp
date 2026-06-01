#ifndef EREBUS_INJECTION_POOLPARTY_JOBAPC_HPP
#define EREBUS_INJECTION_POOLPARTY_JOBAPC_HPP
#pragma once
#include <windows.h>
#include "../config.hpp"

// PoolParty – TpJobObjectApc / RemoteTpJobDirectInsertion (type 9)
// Credits: SafeBreach Labs, Alon Leviev (@_0xDeku), Black Hat EU 2023

namespace erebus {
#if CONFIG_INJECTION_TYPE == 9

    VOID InjectionPoolPartyJobApc(
        IN BYTE*   shellcode,
        IN SIZE_T  shellcode_size,
        IN HANDLE  process_handle,
        IN HANDLE  thread_handle
    );

#endif
} // namespace erebus
#endif // EREBUS_INJECTION_POOLPARTY_JOBAPC_HPP
