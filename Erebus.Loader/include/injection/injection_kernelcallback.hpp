#ifndef EREBUS_INJECTION_KERNELCALLBACK_HPP
#define EREBUS_INJECTION_KERNELCALLBACK_HPP
#pragma once
#include "../loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 7
	VOID InjectionKernelCallback(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
