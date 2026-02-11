#ifndef EREBUS_INJECTION_CREATEFIBER_HPP
#define EREBUS_INJECTION_CREATEFIBER_HPP
#pragma once
#include <windows.h>
#include "config.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 3
	VOID InjectionCreateFiber(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
