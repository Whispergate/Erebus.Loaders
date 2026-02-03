using System.Diagnostics;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce
{
    [SupportedOSPlatform("windows")]
    public static class DebugLogger
    {
        [Conditional("DEBUG")]
        public static void WriteLine(string message)
        {
            Console.WriteLine(message);
        }

        [Conditional("DEBUG")]
        public static void Write(string message)
        {
            Console.Write(message);
        }
    }
}
