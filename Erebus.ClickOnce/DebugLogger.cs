using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Erebus.ClickOnce.Evasion;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class DebugLogger
    {
        // Writes are gated on InjectionConfig.DebugLoggingEnabled, which the
        // Erebus builder renders into InjectionConfig.cs from the operator's
        // Guardrail Debug Mode BuildParameter. This is a RUNTIME toggle, not
        // a `[Conditional("DEBUG")]` compile-time one - previously every
        // Release-configured ClickOnce loader stripped out every DebugLogger
        // call, which meant that when a guardrail fired the operator saw
        // nothing. Operators building a test payload can now flip the toggle
        // to get visible output without rebuilding in Debug configuration.
        //
        // Output now goes through OutputDebugStringW (via D/Invoke against
        // kernel32) rather than Console.WriteLine. Two reasons:
        //
        //   1) The exe is compiled Subsystem=2 (Windows GUI). In a GUI
        //      process, Console.WriteLine has no well-defined sink - it
        //      sometimes triggers AllocConsole() when launched from a
        //      parent that has no stdout, creating a visible black console
        //      window. OutputDebugStringW never touches the console.
        //
        //   2) OutputDebugStringW lets an operator watch live logs via
        //      DbgView / Sysinternals without rebuilding the payload,
        //      which is exactly the original intent of the runtime toggle.
        //
        // SHIPPED BUILDS MUST LEAVE DebugLoggingEnabled = false.

        [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
        private delegate void FnOds(string lpOutputString);

        private static readonly Lazy<FnOds> _ods =
            DynamicApi.LazyDelegate<FnOds>(
                DynamicApi.Kernel32,
                new[] { 'O', 'u', 't', 'p', 'u', 't', 'D', 'e', 'b', 'u', 'g', 'S', 't', 'r', 'i', 'n', 'g', 'W' });

        public static void WriteLine(string message)
        {
            if (!InjectionConfig.DebugLoggingEnabled) return;
            try { _ods.Value(message + "\r\n"); } catch { /* silent */ }
        }

        public static void Write(string message)
        {
            if (!InjectionConfig.DebugLoggingEnabled) return;
            try { _ods.Value(message); } catch { /* silent */ }
        }
    }
}
