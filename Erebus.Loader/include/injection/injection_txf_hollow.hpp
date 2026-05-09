#ifndef EREBUS_INJECTION_TXF_HOLLOW_HPP
#define EREBUS_INJECTION_TXF_HOLLOW_HPP
#pragma once
#include "../loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 8
	VOID InjectionTxfHollow(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
#endif
}

#endif
