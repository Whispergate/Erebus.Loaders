#ifndef EREBUS_INJECTION_EARLYCASCADE_HPP
#define EREBUS_INJECTION_EARLYCASCADE_HPP
#pragma once
#include <windows.h>
#include "../config.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 4
	VOID InjectionEarlyCascade(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
