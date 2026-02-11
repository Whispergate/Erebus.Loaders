#include "../include/loader.hpp"

namespace erebus {
	//
	// Returns TEB pointer for current process.
	//
	PTEB GetTEB(void)
	{
		PTEB teb;
#ifdef _WIN64
	#ifdef _MSC_VER
		teb = reinterpret_cast<PTEB>(__readgsqword(0x30));
	#else
		// GCC/MinGW inline assembly
		__asm__("movq %%gs:0x30, %0" : "=r"(teb));
	#endif
#else
	#ifdef _MSC_VER
		teb = reinterpret_cast<PTEB>(__readfsdword(0x18));
	#else
		// GCC/MinGW inline assembly
		__asm__("movl %%fs:0x18, %0" : "=r"(teb));
	#endif
#endif
		return teb;
	}

	//
	// Returns PEB pointer for current process.
	//
	PPEB GetPEB(void)
	{
		PPEB peb;
#ifdef _WIN64
	#ifdef _MSC_VER
		peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
	#else
		// GCC/MinGW inline assembly
		__asm__("movq %%gs:0x60, %0" : "=r"(peb));
	#endif
#else
	#ifdef _MSC_VER
		peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
	#else
		// GCC/MinGW inline assembly
		__asm__("movl %%fs:0x30, %0" : "=r"(peb));
	#endif
#endif
		return peb;
	}

	PPEB GetPEBFromTEB(void)
	{
		PTEB teb;
		PPEB peb;
#ifdef _WIN64
	#ifdef _MSC_VER
		teb = reinterpret_cast<PTEB>(__readgsqword(0x30));
	#else
		// GCC/MinGW inline assembly
		__asm__("movq %%gs:0x30, %0" : "=r"(teb));
	#endif
#else
	#ifdef _MSC_VER
		teb = reinterpret_cast<PTEB>(__readfsdword(0x18));
	#else
		// GCC/MinGW inline assembly
		__asm__("movl %%fs:0x18, %0" : "=r"(teb));
	#endif
#endif
		peb = teb->ProcessEnvironmentBlock;
		return peb;
	}
} // namespace erebus
