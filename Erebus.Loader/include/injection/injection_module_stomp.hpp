#ifndef EREBUS_INJECTION_MODULE_STOMP_HPP
#define EREBUS_INJECTION_MODULE_STOMP_HPP
#pragma once
#include "../loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 6
	VOID InjectionModuleStomp(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
