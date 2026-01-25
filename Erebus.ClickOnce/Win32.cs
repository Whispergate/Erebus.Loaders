using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Text;
using System.Threading.Tasks;

namespace Erebus.ClickOnce
{
    internal static class Win32
    {
        [UnmanagedFunctionPointerAttribute(CallingConvention.Winapi)]
        public unsafe delegate uint LPTHREAD_START_ROUTINE(void* lpThreadParameter);

        [Flags]
        public enum CREATION_FLAGS : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_SECURE_PROCESS = 0x00400000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
        }

        [Flags]
        public enum PAGE_PROTECTION_FLAGS : uint
        {
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400,
            PAGE_GRAPHICS_NOACCESS = 0x00000800,
            PAGE_GRAPHICS_READONLY = 0x00001000,
            PAGE_GRAPHICS_READWRITE = 0x00002000,
            PAGE_GRAPHICS_EXECUTE = 0x00004000,
            PAGE_GRAPHICS_EXECUTE_READ = 0x00008000,
            PAGE_GRAPHICS_EXECUTE_READWRITE = 0x00010000,
            PAGE_GRAPHICS_COHERENT = 0x00020000,
            PAGE_GRAPHICS_NOCACHE = 0x00040000,
            PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000,
            PAGE_REVERT_TO_FILE_MAP = 0x80000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_ENCLAVE_UNVALIDATED = 0x20000000,
            PAGE_ENCLAVE_MASK = 0x10000000,
            PAGE_ENCLAVE_DECOMMIT = 0x10000000,
            PAGE_ENCLAVE_SS_FIRST = 0x10000001,
            PAGE_ENCLAVE_SS_REST = 0x10000002,
            SEC_PARTITION_OWNER_HANDLE = 0x00040000,
            SEC_64K_PAGES = 0x00080000,
            SEC_FILE = 0x00800000,
            SEC_IMAGE = 0x01000000,
            SEC_PROTECTED_IMAGE = 0x02000000,
            SEC_RESERVE = 0x04000000,
            SEC_COMMIT = 0x08000000,
            SEC_NOCACHE = 0x10000000,
            SEC_WRITECOMBINE = 0x40000000,
            SEC_LARGE_PAGES = 0x80000000,
            SEC_IMAGE_NO_EXECUTE = 0x11000000,
        }

        [Flags]
        public enum THREAD_CREATION_FLAGS : uint
        {
            THREAD_CREATE_RUN_IMMEDIATELY = 0x00000000,
            THREAD_CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000,
        }

        [Flags]
        public enum VIRTUAL_ALLOCATION_TYPE : uint
        {
            MEM_COMMIT = 0x00001000,
            MEM_RESERVE = 0x00002000,
            MEM_RESET = 0x00080000,
            MEM_RESET_UNDO = 0x01000000,
            MEM_REPLACE_PLACEHOLDER = 0x00004000,
            MEM_LARGE_PAGES = 0x20000000,
            MEM_RESERVE_PLACEHOLDER = 0x00040000,
            MEM_FREE = 0x00010000,
        }

        [DllImport("kernel32.dll", EntryPoint = "#138", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", EntryPoint = "#233", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess(
            string applicationName,
            string commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            CREATION_FLAGS creationFlags,
            IntPtr environment,
            string currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("KERNEL32.dll", EntryPoint = "#235", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern unsafe HANDLE CreateRemoteThread(
            HANDLE hProcess,
            [Optional] SECURITY_ATTRIBUTES* lpThreadAttributes,
            nuint dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            [Optional] void* lpParameter,
            THREAD_CREATION_FLAGS dwCreationFlags,
            [Optional] uint* lpThreadId);

        [DllImport("KERNEL32.dll", EntryPoint = "#246", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern unsafe HANDLE CreateThread(
            [Optional] SECURITY_ATTRIBUTES* lpThreadAttributes,
            nuint dwStackSize,
            LPTHREAD_START_ROUTINE lpStartAddress,
            [Optional] void* lpParameter,
            THREAD_CREATION_FLAGS dwCreationFlags,
            [Optional] uint* lpThreadId);

        [DllImport("user32.dll")]
        public static extern bool EnumDesktops(IntPtr hwinsta, IntPtr lpEnumFunc, IntPtr lParam);

        [DllImport("KERNEL32.dll", EntryPoint = "#545", ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern HANDLE GetCurrentProcess();

        [DllImport("KERNEL32.dll", EntryPoint = "#1500", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern unsafe IntPtr VirtualAllocEx(
            HANDLE hProcess,
            [Optional] IntPtr lpAddress,
            nuint dwSize,
            VIRTUAL_ALLOCATION_TYPE flAllocationType,
            PAGE_PROTECTION_FLAGS flProtect);

        [DllImport("KERNEL32.dll", EntryPoint = "#1584", ExactSpelling = true, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        public static extern unsafe BOOL WriteProcessMemory(
            HANDLE hProcess,
            void* lpBaseAddress,
            void* lpBuffer,
            nuint nSize,
            [Optional] nuint* lpNumberOfBytesWritten);

        [DebuggerDisplay("{Value}")]
        public readonly struct BOOL(int value) : IEquatable<BOOL>
        {
            public readonly int Value = value;

            public BOOL(bool value) : this(value ? 1 : 0)
            {
            }

            public static explicit operator BOOL(int value) => new(value);

            public static implicit operator bool(BOOL value) => value.Value != 0;

            public static implicit operator BOOL(bool value) => new(value);

            public static implicit operator int(BOOL value) => value.Value;

            public static bool operator !=(BOOL left, BOOL right) => !(left == right);

            public static bool operator ==(BOOL left, BOOL right) => left.Value == right.Value;

            public bool Equals(BOOL other) => Value == other.Value;

            public override bool Equals(object obj) => obj is BOOL other && Equals(other);

            public override int GetHashCode() => Value.GetHashCode();

            public override string ToString() => $"0x{Value:x}";
        }

        [DebuggerDisplay("{Value}")]
        public readonly struct HANDLE(IntPtr value) : IEquatable<HANDLE>
        {
            public readonly IntPtr Value = value;

            public static HANDLE Null => default;

            public bool IsNull => Value == default;

            public static explicit operator HANDLE(IntPtr value) => new(value);

            public static implicit operator IntPtr(HANDLE value) => value.Value;

            public static bool operator !=(HANDLE left, HANDLE right) => !(left == right);

            public static bool operator ==(HANDLE left, HANDLE right) => left.Value == right.Value;

            public bool Equals(HANDLE other) => Value == other.Value;

            public override bool Equals(object obj) => obj is HANDLE other && Equals(other);

            public override int GetHashCode() => Value.GetHashCode();

            public override string ToString() => $"0x{Value:x}";
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        public struct SECURITY_ATTRIBUTES
        {
            public BOOL bInheritHandle;
            public unsafe void* lpSecurityDescriptor;
            public uint nLength;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
    }
}
