using System;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class DebugLogger
    {
        // Writes are gated on InjectionConfig.DebugLoggingEnabled, which the
        // Erebus builder renders into InjectionConfig.cs from the operator's
        // 3.E9q Guardrail Debug Mode BuildParameter equivalent. This is a
        // RUNTIME toggle, not a `[Conditional("DEBUG")]` compile-time one -
        // previously every Release-configured ClickOnce loader stripped out
        // every DebugLogger call, which meant that when a guardrail fired
        // the operator saw nothing, just Environment.Exit(1). Operators
        // building a test payload can now flip DebugLoggingEnabled to get
        // visible output without rebuilding in Debug configuration.
        //
        // SHIPPED BUILDS MUST LEAVE DebugLoggingEnabled = false.
        public static void WriteLine(string message)
        {
            if (!InjectionConfig.DebugLoggingEnabled) return;
            try { Console.WriteLine(message); } catch { /* silent */ }
        }

        public static void Write(string message)
        {
            if (!InjectionConfig.DebugLoggingEnabled) return;
            try { Console.Write(message); } catch { /* silent */ }
        }
    }
}
