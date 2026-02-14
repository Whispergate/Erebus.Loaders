#include "../../include/loader.hpp"

namespace erebus {
	VOID DecompressionLZNT(_Inout_ BYTE** Input, _Inout_ SIZE_T* InputLen)
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (!ntdll) { LOG_ERROR("Failed to get ntdll.dll"); return; }
		typeRtlDecompressBuffer RtlDecompressBuffer = (typeRtlDecompressBuffer)GetProcAddress(ntdll, "RtlDecompressBuffer");

		if (!Input || !*Input || !InputLen || *InputLen == 0)
		{
			LOG_ERROR("Invalid input buffer for LZNT decompression");
			return;
		}

		SIZE_T OutputLen = (*InputLen) * 2;
		if (OutputLen < *InputLen)
		{
			LOG_ERROR("Output length overflow in LZNT decompression");
			return;
		}

		BYTE* Output = (BYTE*)malloc(OutputLen);
		if (!Output)
		{
			LOG_ERROR("Failed to allocate LZNT output buffer");
			return;
		}
		ULONG FinalOutputSize;

		NTSTATUS status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, Output, OutputLen, *Input, *InputLen, &FinalOutputSize);

		if (!NT_SUCCESS(status))
		{
			LOG_ERROR("RtlDecompressBuffer failed 0x%08lX", status);
			free(Output);
			return;
		}

		BYTE* OldInput = *Input;
		*Input = Output;
		*InputLen = FinalOutputSize;
		free(OldInput);
		return;
	}

	VOID DecompressionRLE(_Inout_ BYTE** Input, _Inout_ SIZE_T* InputLen)
	{
		if (!Input || !*Input || !InputLen || *InputLen == 0)
		{
			LOG_ERROR("Invalid input buffer for RLE decompression");
			return;
		}

		SIZE_T OutputCapacity = (*InputLen) * 4;
		if (OutputCapacity < *InputLen)
		{
			LOG_ERROR("Output length overflow in RLE decompression");
			return;
		}

		BYTE* Output = (BYTE*)malloc(OutputCapacity);
		if (!Output)
		{
			LOG_ERROR("Failed to allocate RLE output buffer");
			return;
		}
		SIZE_T OutputIndex = 0;

		for (SIZE_T i = 0; i < *InputLen && OutputIndex < OutputCapacity; i++)
		{
			BYTE byte = (*Input)[i];

			// Check if this is a run byte (0xFF indicates a run)
			if (byte == 0xFF && i + 1 < *InputLen)
			{
				i++;
				BYTE count = (*Input)[i];
				if (i + 1 < *InputLen)
				{
					i++;
					BYTE value = (*Input)[i];
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

		BYTE* OldInput = *Input;
		*Input = Output;
		*InputLen = OutputIndex;
		free(OldInput);
		return;
	}

	// Calculate entropy using integer-based heuristic (CRT-less alternative)
	// Returns approximate entropy score without floating point math
	// Score: 0-100+ where high scores indicate encryption/compression
	DWORD CalculateEntropyInteger(_In_ const BYTE* Data, IN SIZE_T DataLen)
	{
		if (!Data || DataLen == 0) return 0;

		DWORD frequency[256] = { 0 };
		for (SIZE_T i = 0; i < DataLen; i++)
			frequency[Data[i]]++;

		// Count how many byte values appear
		DWORD uniqueBytes = 0;
		for (int i = 0; i < 256; i++)
		{
			if (frequency[i] > 0)
				uniqueBytes++;
		}

		// Simple entropy approximation:
		// - Uniform distribution (all 256 bytes appear) = high entropy (encrypted/compressed)
		// - Low diversity = low entropy (plaintext)
		// Score: (uniqueBytes / 256) * 100
		return (uniqueBytes * 100) / 256;
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

	CompressionFormat DetectCompressionFormat(_In_ const BYTE* Input, IN SIZE_T InputLen)
	{
	    if (!Input || InputLen < 2)
	        return FORMAT_NONE;

	    WORD Header = *(WORD*)Input;
	
	    // Check for LZNT1: bit 15 set AND signature bits [14:12] == 3
	    if ((Header & 0x8000) && ((Header & 0x7000) >> 12) == 0x3)
	    {
	        WORD ChunkSize = (Header & 0x0FFF) + 1;
	        if (ChunkSize > 0 && ChunkSize <= InputLen - 2)
	        {
	            LOG_INFO("Detected LZNT1 compression (chunk size: %d)", ChunkSize);
	            return FORMAT_LZNT1;
	        }
	    }

	    // Check for RLE markers
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

	EncodingFormat DetectEncodingFormat(_In_ const CHAR* Input, IN SIZE_T InputLen)
	{
		if (!Input || InputLen < 4)
			return ENCODING_NONE;

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
		return ENCODING_NONE;
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
				DecompressionLZNT(Shellcode, ShellcodeLen);
				break;
			}
			case FORMAT_RLE:
			{
				LOG_SUCCESS("Decompressing with RLE");
				DecompressionRLE(Shellcode, ShellcodeLen);
				break;
			}
			default:
				LOG_INFO("No binary compression detected, skipping decompression");
				break;
		}
	}

	BOOL AutoDetectAndDecodeString(_In_ CHAR* Input, IN SIZE_T InputLen, _Out_ BYTE** Output, _Out_ SIZE_T* OutputLen)
	{
		LOG_INFO("Analyzing encoding format...");

		EncodingFormat format = DetectEncodingFormat(Input, InputLen);

		switch (format)
		{
		case FORMAT_BASE64:
		{
			LOG_SUCCESS("Decoding Base64");
			return DecodeBase64(Input, InputLen, Output, OutputLen);
		}
		case FORMAT_ASCII85:
		{
			LOG_SUCCESS("Decoding ASCII85");
			return DecodeASCII85(Input, InputLen, Output, OutputLen);
		}
		case FORMAT_ALPHA32:
		{
			LOG_SUCCESS("Decoding ALPHA32");
			return DecodeALPHA32(Input, InputLen, Output, OutputLen);
		}
		case FORMAT_WORDS256:
		{
			LOG_SUCCESS("Decoding WORDS256");
			return DecodeWORDS256(Input, InputLen, Output, OutputLen);
		}
		default:
		{
			LOG_INFO("No encoding detected, returning raw input");
			*Output = new BYTE[InputLen];
			RtlCopyMemory(*Output, Input, InputLen);
			*OutputLen = InputLen;
			return TRUE;
		}
		}
	}

	// ============================================================
	// DECOMPRESSION ROUTINE
	// ============================================================
	
	VOID DecompressShellcode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
	{
		LOG_INFO("========================================");
		LOG_INFO("Shellcode Decompression (Auto-Detect)");
		LOG_INFO("========================================");

		CompressionFormat compressionFormat = DetectCompressionFormat(*Shellcode, *ShellcodeLen);

		switch (compressionFormat)
		{
		case int(FORMAT_LZNT1):
		{
			LOG_SUCCESS("Decompressing with LZNT1");
			DecompressionLZNT(Shellcode, ShellcodeLen);
			LOG_SUCCESS("Decompression complete: %zu bytes", *ShellcodeLen);
			break;
		}
		case int(FORMAT_RLE):
		{
			LOG_SUCCESS("Decompressing with RLE");
			DecompressionRLE(Shellcode, ShellcodeLen);
			LOG_SUCCESS("Decompression complete: %zu bytes", *ShellcodeLen);
			break;
		}
		default:
			LOG_INFO("No compression detected");
			break;
		}

		// Final validation
		LOG_INFO("========================================");
		LOG_INFO("Decompression complete");
		LOG_INFO("Final size: %zu bytes", *ShellcodeLen);

		DWORD finalEntropyScore = CalculateEntropyInteger(*Shellcode, *ShellcodeLen);
		LOG_INFO("Final entropy score: %lu/100", finalEntropyScore);

		if (*ShellcodeLen > 0 && (*Shellcode)[0] != 0x00)
		{
			LOG_SUCCESS("Shellcode appears valid (non-null start)");
		}
		else
		{
			LOG_ERROR("Shellcode may be invalid or corrupted");
		}

		LOG_INFO("========================================");
	}
} // namespace erebus
