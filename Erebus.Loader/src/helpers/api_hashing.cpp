#include "../../include/loader.hpp"

namespace erebus {
	//
	// GetModuleHandle implementation with API hashing.
	//
	HMODULE GetModuleHandleC(_In_ ULONG dllHash)
	{
		// https://revers.engineering/custom-getprocaddress-and-getmodulehandle-implementation-x64/
#if defined(_WIN64)
#define ldr_offset 0x18
#define list_offset 0x10
#elif defined(_WIN32)
#define ldr_offset 0x0C
#define list_offset 0x0C
#endif

		PLIST_ENTRY head = (PLIST_ENTRY)&erebus::GetPEB()->Ldr->InMemoryOrderModuleList;
		PLIST_ENTRY next = head->Flink;

		PLDR_MODULE module = (PLDR_MODULE)((PBYTE)next - list_offset);

		while (next != head)
		{
			module = (PLDR_MODULE)((PBYTE)next - list_offset);
			if (module->BaseDllName.Buffer != NULL)
			{
				if (dllHash - erebus::HashStringFowlerNollVoVariant1a(module->BaseDllName.Buffer) == 0)
					return (HMODULE)module->BaseAddress;
			}
			next = next->Flink;
		}

		return NULL;
	}

	//
	// GetProcAddress implementation with API hashing.
	//
	FARPROC GetProcAddressC(_In_ HMODULE dllBase, _In_ ULONG funcHash)
	{
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)(dllBase);
#if _WIN64
		PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((PBYTE)dos + (dos)->e_lfanew);
#else
		PIMAGE_NT_HEADERS32 nt = (PIMAGE_NT_HEADERS32)(dos + (dos)->e_lfanew);
#endif
		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dos + (nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		if (exports->AddressOfNames != 0)
		{
			PWORD ordinals = (PWORD)((UINT_PTR)dllBase + exports->AddressOfNameOrdinals);
			PDWORD names = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfNames);
			PDWORD functions = (PDWORD)((UINT_PTR)dllBase + exports->AddressOfFunctions);

			for (DWORD i = 0; i < exports->NumberOfNames; i++) {
				LPCSTR name = (LPCSTR)((UINT_PTR)dllBase + names[i]);
				if (HashStringFowlerNollVoVariant1a(name) == funcHash) {
					PBYTE function = (PBYTE)((UINT_PTR)dllBase + functions[ordinals[i]]);
					return (FARPROC)function;
				}
			}
		}
		return NULL;
	}

	//
	// LoadLibrary implementation.
	//
	HMODULE LoadLibraryC(_In_ PCWSTR dll_name)
	{
		UNICODE_STRING unicode_module = { 0 };
		HANDLE module_handle = INVALID_HANDLE_VALUE;
		ULONG flags = 0;

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) return NULL;

		typeRtlInitUnicodeString RtlInitUnicodeString = (typeRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
		typeLdrLoadDll LdrLoadDll = (typeLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");

		RtlInitUnicodeString(&unicode_module, dll_name);

		NTSTATUS status = LdrLoadDll(NULL, &flags, &unicode_module, &module_handle);
		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("LdrLoadDll failed with status: 0x%08lX", status);
			return NULL;
		}

		return (HMODULE)module_handle;
	}

	//
	// Cleanup Module After Use
	//
	VOID CleanupModule(_In_ HMODULE module_handle)
	{
		if (!module_handle)
		{
			LOG_ERROR("Module not found.");
			return;
		}

		return;
	}
} // namespace erebus
