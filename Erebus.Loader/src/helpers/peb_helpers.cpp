#include "../../include/loader.hpp"

namespace erebus {
	// IMPORTANT: The whole project is compiled with -masm=intel. Every
	// __asm__ block below must be written in Intel order (destination
	// FIRST, source SECOND) or the compiler silently encodes the wrong
	// direction. An earlier revision used AT&T syntax here, which meant
	// `movq %%gs:0x60, %0` was assembled as `mov %0, gs:0x60` - i.e. a
	// STORE into the TEB's PEB pointer. Every call to GetPEB()
	// overwrote gs:[0x60] with garbage from rax and returned that
	// garbage as the PEB, silently corrupting every subsequent PEB
	// walk. That broke both debug (stack overflow inside ntdll as the
	// corrupted PEB sent loader walks off into invalid memory) and
	// release (guardrails / injection silently no-op'd because every
	// PEB access returned garbage).
	//
	// The safe portable alternative is to use the GCC intrinsics
	// `__readgsqword` / `__readfsdword`, which emit a single correct
	// `mov reg, gs:offset` regardless of the assembler syntax flag.

	//
	// Returns TEB pointer for current process.
	//
	PTEB GetTEB(void)
	{
		PTEB teb;
#ifdef _WIN64
		teb = reinterpret_cast<PTEB>(__readgsqword(0x30));
#else
		teb = reinterpret_cast<PTEB>(__readfsdword(0x18));
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
		peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
		peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
		return peb;
	}

	PPEB GetPEBFromTEB(void)
	{
		PTEB teb = GetTEB();
		return teb ? teb->ProcessEnvironmentBlock : nullptr;
	}
} // namespace erebus
