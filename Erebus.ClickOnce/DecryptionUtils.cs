using System.Security.Cryptography;

namespace Erebus.ClickOnce
{
    /// <summary>
    /// Utility class for handling various encryption and decryption operations
    /// Supports: XOR, RC4, AES-ECB, AES-CBC
    /// </summary>
    public static class DecryptionUtils
    {
        /// <summary>
        /// Decrypts data using XOR with the provided key
        /// </summary>
        public static byte[] DecryptXOR(byte[] data, byte[] key)
        {
            if (key.Length == 0)
                return data;

            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            }
            return result;
        }

        /// <summary>
        /// Decrypts data using RC4 (Stream cipher) with the provided key
        /// </summary>
        public static byte[] DecryptRC4(byte[] data, byte[] key)
        {
            if (key.Length == 0)
                return data;

            byte[] S = new byte[256];
            byte[] K = new byte[256];

            // Key-scheduling algorithm (KSA)
            for (int i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
                K[i] = key[i % key.Length];
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + K[i]) % 256;
                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            // Pseudo-random generation algorithm (PRGA)
            byte[] result = new byte[data.Length];
            int x = 0;
            j = 0;

            for (int n = 0; n < data.Length; n++)
            {
                x = (x + 1) % 256;
                j = (j + S[x]) % 256;

                byte temp = S[x];
                S[x] = S[j];
                S[j] = temp;

                byte K_stream = S[(S[x] + S[j]) % 256];
                result[n] = (byte)(data[n] ^ K_stream);
            }

            return result;
        }

        /// <summary>
        /// Decrypts data using AES (ECB mode) with the provided key
        /// </summary>
        public static byte[] DecryptAES_ECB(byte[] data, byte[] key)
        {
            if (key.Length == 0)
                return data;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        return decryptor.TransformFinalBlock(data, 0, data.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] AES ECB decryption failed: {ex.Message}");
                return data;
            }
        }

        /// <summary>
        /// Decrypts data using AES (CBC mode) with the provided key and IV
        /// </summary>
        public static byte[] DecryptAES_CBC(byte[] data, byte[] key, byte[] iv)
        {
            if (key.Length == 0)
                return data;

            try
            {
                using (Aes aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    
                    if (iv != null && iv.Length == 16)
                        aes.IV = iv;

                    using (ICryptoTransform decryptor = aes.CreateDecryptor())
                    {
                        return decryptor.TransformFinalBlock(data, 0, data.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] AES CBC decryption failed: {ex.Message}");
                return data;
            }
        }

        /// <summary>
        /// Calculates entropy score of data (0-100) to detect encryption
        /// </summary>
        public static int CalculateEntropyScore(byte[] data)
        {
            if (data.Length == 0)
                return 0;

            int[] frequency = new int[256];
            for (int i = 0; i < data.Length; i++)
                frequency[data[i]]++;

            int uniqueBytes = 0;
            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                    uniqueBytes++;
            }

            // Score = (unique_bytes * 100) / 256
            return (uniqueBytes * 100) / 256;
        }

        /// <summary>
        /// Detects if data appears to be encrypted based on entropy
        /// </summary>
        public static bool IsHighEntropy(byte[] data)
        {
            int entropyScore = CalculateEntropyScore(data);
            return entropyScore > 70; // Score > 70 indicates likely encryption
        }

        /// <summary>
        /// Attempts to detect encryption type based on patterns and entropy
        /// </summary>
        public static string DetectEncryptionType(byte[] data)
        {
            if (data.Length < 16)
                return "none";

            int entropyScore = CalculateEntropyScore(data);
            DebugLogger.WriteLine($"[*] Data entropy score: {entropyScore}/100");

            if (entropyScore < 50)
            {
                DebugLogger.WriteLine("[*] Low entropy - likely unencrypted");
                return "none";
            }

            // Check for AES block alignment and PKCS#7 padding
            if (data.Length % 16 == 0 && entropyScore > 85)
            {
                byte lastByte = data[data.Length - 1];
                if (lastByte > 0 && lastByte <= 16)
                {
                    bool validPadding = true;
                    int paddingStart = data.Length - lastByte;
                    for (int i = paddingStart; i < data.Length; i++)
                    {
                        if (data[i] != lastByte)
                        {
                            validPadding = false;
                            break;
                        }
                    }
                    if (validPadding)
                    {
                        DebugLogger.WriteLine("[*] Detected: Likely AES encryption (PKCS#7 padding, 16-byte blocks)");
                        return "aes";
                    }
                }
            }

            // Check for XOR patterns (repeating key patterns)
            if (data.Length >= 256)
            {
                for (int keyLen = 2; keyLen <= 16; keyLen++)
                {
                    int matches = 0;
                    for (int i = 0; i + keyLen < Math.Min(data.Length, 256); i++)
                    {
                        if ((data[i] ^ data[i + keyLen]) == 0)
                            matches++;
                    }
                    if (matches > 10)
                    {
                        DebugLogger.WriteLine($"[*] Detected: Likely XOR encryption (key length ~{keyLen})");
                        return "xor";
                    }
                }
            }

            // High entropy but no specific pattern
            if (entropyScore > 75)
            {
                DebugLogger.WriteLine("[*] Detected: Likely RC4 or other stream cipher (high entropy, no specific pattern)");
                return "rc4";
            }

            DebugLogger.WriteLine("[*] Moderate entropy - encryption type unknown");
            return "unknown";
        }

        /// <summary>
        /// Automatically detects and applies appropriate decryption
        /// </summary>
        public static byte[] AutoDetectAndDecrypt(byte[] shellcode, byte[] key)
        {
            if (key.Length == 0)
            {
                DebugLogger.WriteLine("[*] No decryption key provided, skipping decryption");
                return shellcode;
            }

            string encryptionType = DetectEncryptionType(shellcode);
            
            switch (encryptionType.ToLower())
            {
                case "aes":
                    DebugLogger.WriteLine("[+] Applying AES-ECB decryption...");
                    shellcode = DecryptAES_ECB(shellcode, key);
                    DebugLogger.WriteLine($"[+] Decrypted shellcode size: {shellcode.Length} bytes");
                    break;

                case "rc4":
                    DebugLogger.WriteLine("[+] Applying RC4 decryption...");
                    shellcode = DecryptRC4(shellcode, key);
                    DebugLogger.WriteLine($"[+] Decrypted shellcode size: {shellcode.Length} bytes");
                    break;

                case "xor":
                    DebugLogger.WriteLine("[+] Applying XOR decryption...");
                    shellcode = DecryptXOR(shellcode, key);
                    DebugLogger.WriteLine($"[+] Decrypted shellcode size: {shellcode.Length} bytes");
                    break;

                case "unknown":
                    DebugLogger.WriteLine("[*] Unknown encryption detected, attempting XOR decryption...");
                    byte[] xorAttempt = DecryptXOR(shellcode, key);
                    if (IsHighEntropy(xorAttempt))
                    {
                        DebugLogger.WriteLine("[*] XOR didn't help, trying RC4...");
                        shellcode = DecryptRC4(shellcode, key);
                    }
                    else
                    {
                        shellcode = xorAttempt;
                    }
                    DebugLogger.WriteLine($"[+] Decrypted shellcode size: {shellcode.Length} bytes");
                    break;

                default:
                    DebugLogger.WriteLine("[*] No encryption detected, skipping decryption");
                    break;
            }

            return shellcode;
        }
    }
}
