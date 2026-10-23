using System.Runtime.InteropServices;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// One process as reported by the kernel, without opening a handle to it.
/// </summary>
public readonly record struct KernelProcess(int ProcessId, long CreateTime, string ImageName, long CpuTime, long WorkingSetBytes, long PrivateBytes,
    long ReadBytes, long WriteBytes, long OtherBytes);

/// <summary>
/// The Windows calls behind the System page. Process figures come from one NtQuerySystemInformation call, the same
/// source Task Manager uses, so no process handles are opened and protected processes are included.
/// </summary>
public static class NativeSystem
{
    private const int SystemProcessInformation = 5;
    private const uint StatusInfoLengthMismatch = 0xC0000004;

    // Offsets into SYSTEM_PROCESS_INFORMATION on 64-bit Windows.
    private const int NextEntryOffsetField = 0;
    private const int CreateTimeField = 32;
    private const int UserTimeField = 40;
    private const int KernelTimeField = 48;
    private const int ImageNameLengthField = 56;
    private const int ImageNameBufferField = 64;
    private const int ProcessIdField = 80;
    private const int WorkingSetSizeField = 144;
    private const int PrivatePageCountField = 200;

    // IO_COUNTERS follows PrivatePageCount: the byte totals since the process started. They cover file, network and
    // device I/O together; Windows does not split them.
    private const int ReadTransferCountField = 232;
    private const int WriteTransferCountField = 240;
    private const int OtherTransferCountField = 248;

    /// <summary>
    /// The "Logon" audit subcategory; its failure flag decides whether failed sign-ins (4625) are logged at all.
    /// </summary>
    private static readonly Guid LogonAuditSubcategory = new("0CCE9215-69AE-11D9-BED3-505054503030");
    private const uint AuditFailureFlag = 0x2;

    public static List<KernelProcess> ListProcesses()
    {
        if (!OperatingSystem.IsWindows() || IntPtr.Size != 8)
            return [];

        var bufferSize = 1024 * 1024;
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var buffer = Marshal.AllocHGlobal(bufferSize);
            try
            {
                var status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, out var neededSize);
                if (status == StatusInfoLengthMismatch)
                {
                    bufferSize = Math.Max(bufferSize * 2, neededSize + 64 * 1024);
                    continue;
                }

                if (status != 0)
                    return [];

                return ParseProcesses(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return [];
    }

    private static List<KernelProcess> ParseProcesses(IntPtr buffer)
    {
        var processes = new List<KernelProcess>();
        var entry = buffer;
        while (true)
        {
            var processId = (int)Marshal.ReadInt64(entry, ProcessIdField);
            var nameLength = Marshal.ReadInt16(entry, ImageNameLengthField);
            var nameBuffer = Marshal.ReadIntPtr(entry, ImageNameBufferField);
            var imageName = processId == 0 ? "Idle" : nameBuffer == IntPtr.Zero ? "System" : Marshal.PtrToStringUni(nameBuffer, nameLength / 2);

            processes.Add(new KernelProcess(
                processId,
                Marshal.ReadInt64(entry, CreateTimeField),
                imageName,
                Marshal.ReadInt64(entry, UserTimeField) + Marshal.ReadInt64(entry, KernelTimeField),
                Marshal.ReadInt64(entry, WorkingSetSizeField),
                Marshal.ReadInt64(entry, PrivatePageCountField),
                Marshal.ReadInt64(entry, ReadTransferCountField),
                Marshal.ReadInt64(entry, WriteTransferCountField),
                Marshal.ReadInt64(entry, OtherTransferCountField)));

            var nextEntryOffset = Marshal.ReadInt32(entry, NextEntryOffsetField);
            if (nextEntryOffset == 0)
                break;

            entry += nextEntryOffset;
        }

        return processes;
    }

    /// <summary>
    /// Idle, kernel (which includes idle) and user time for all processors, in 100 ns units.
    /// </summary>
    public static (long Idle, long Kernel, long User)? SystemTimes()
    {
        if (!OperatingSystem.IsWindows() || !GetSystemTimes(out var idle, out var kernel, out var user))
            return null;

        return (idle, kernel, user);
    }

    public static (long TotalBytes, long AvailableBytes)? Memory()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var status = new MemoryStatusEx { Length = (uint)Marshal.SizeOf<MemoryStatusEx>() };
        return GlobalMemoryStatusEx(ref status) ? ((long)status.TotalPhysical, (long)status.AvailablePhysical) : null;
    }

    /// <summary>
    /// Whether Windows records failed sign-ins, or null when the policy can't be read.
    /// </summary>
    public static bool? IsFailedSignInAuditingOn()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var subcategories = new[] { LogonAuditSubcategory };
        if (!AuditQuerySystemPolicy(subcategories, 1, out var policies) || policies == IntPtr.Zero)
            return null;

        try
        {
            var policy = Marshal.PtrToStructure<AuditPolicyInformation>(policies);
            return (policy.AuditingInformation & AuditFailureFlag) != 0;
        }
        finally
        {
            AuditFree(policies);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint Length;
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out long idleTime, out long kernelTime, out long userTime);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);
}
