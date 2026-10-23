using System.Diagnostics.Eventing.Reader;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Windows records nothing about file reads unless asked. Read tracking asks it, for the owner's folders only:
/// <list type="number">
/// <item>the "File System" audit subcategory is switched on for successes,</item>
/// <item>each personal folder gets an audit entry (Everyone, read data, success) that applies to the files inside,
/// not the folders, so folder listings aren't mistaken for reads,</item>
/// <item>the Security log is made bigger, so the extra events don't push out sign-in and account events.</item>
/// </list>
/// Everything changed is recorded in <see cref="FileReadAuditState"/> and put back exactly by <see cref="Revert"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public static class FileReadAudit
{
    private static readonly Guid FileSystemSubcategory = new("0CCE921D-69AE-11D9-BED3-505054503030");
    private const uint AuditSuccess = 0x1;
    private const uint AuditFailure = 0x2;
    private const uint AuditNone = 0x4;
    private const long SecurityLogBytes = 512L * 1024 * 1024;

    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);

    public static FileSystemAuditRule ReadRule => new(Everyone, FileSystemRights.ReadData, InheritanceFlags.ObjectInherit,
        PropagationFlags.InheritOnly, AuditFlags.Success);

    public static void Apply(FileReadAuditState state, IReadOnlyCollection<string> folders)
    {
        EnablePrivilege("SeSecurityPrivilege");

        if (!state.Applied)
        {
            state.PreviousPolicyFlags = QueryPolicy() ?? 0;
            using var configuration = new EventLogConfiguration("Security");
            state.PreviousSecurityLogBytes = configuration.MaximumSizeInBytes;
            if (configuration.MaximumSizeInBytes < SecurityLogBytes)
            {
                configuration.MaximumSizeInBytes = SecurityLogBytes;
                configuration.SaveChanges();
            }

            state.SecurityLogBytes = Math.Max(SecurityLogBytes, state.PreviousSecurityLogBytes);
        }

        SetPolicy((state.PreviousPolicyFlags & AuditFailure) | AuditSuccess);

        // Folders no longer wanted lose the entry; new ones gain it.
        foreach (var folder in state.AuditedFolders.Except(folders, StringComparer.OrdinalIgnoreCase).ToList())
        {
            RemoveRule(folder);
            state.AuditedFolders.Remove(folder);
        }

        foreach (var folder in folders.Where(Directory.Exists))
        {
            if (state.AuditedFolders.Contains(folder, StringComparer.OrdinalIgnoreCase))
                continue;

            var directory = new DirectoryInfo(folder);
            var security = directory.GetAccessControl(AccessControlSections.Audit);
            security.AddAuditRule(ReadRule);
            directory.SetAccessControl(security);
            state.AuditedFolders.Add(folder);
        }

        state.Applied = true;
        state.AppliedAt ??= DateTime.UtcNow;
        state.LastError = null;
    }

    public static void Revert(FileReadAuditState state)
    {
        if (!state.Applied)
            return;

        EnablePrivilege("SeSecurityPrivilege");
        var errors = new List<string>();
        foreach (var folder in state.AuditedFolders.ToList())
        {
            try
            {
                RemoveRule(folder);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
            {
                errors.Add($"{folder}: {exception.Message}");
            }
        }

        // Back to how the File System subcategory was: no auditing, or failures only.
        SetPolicy(AuditNone);
        if ((state.PreviousPolicyFlags & (AuditSuccess | AuditFailure)) != 0)
            SetPolicy(state.PreviousPolicyFlags & (AuditSuccess | AuditFailure));

        if (state.PreviousSecurityLogBytes > 0)
        {
            using var configuration = new EventLogConfiguration("Security");
            if (configuration.MaximumSizeInBytes == state.SecurityLogBytes)
            {
                configuration.MaximumSizeInBytes = state.PreviousSecurityLogBytes;
                configuration.SaveChanges();
            }
        }

        state.Applied = false;
        state.AppliedAt = null;
        state.AuditedFolders.Clear();
        state.LastError = errors.Count == 0 ? null : string.Join("; ", errors);
    }

    /// <summary>
    /// Whether file-system success auditing is on right now. Group Policy can switch it back off.
    /// </summary>
    public static bool IsPolicyOn()
    {
        return ((QueryPolicy() ?? 0) & AuditSuccess) != 0;
    }

    private static void RemoveRule(string folder)
    {
        if (!Directory.Exists(folder))
            return;

        var directory = new DirectoryInfo(folder);
        var security = directory.GetAccessControl(AccessControlSections.Audit);
        security.RemoveAuditRuleSpecific(ReadRule);
        directory.SetAccessControl(security);
    }

    private static uint? QueryPolicy()
    {
        if (!AuditQuerySystemPolicy([FileSystemSubcategory], 1, out var policies) || policies == IntPtr.Zero)
            return null;

        try
        {
            return Marshal.PtrToStructure<AuditPolicyInformation>(policies).AuditingInformation;
        }
        finally
        {
            AuditFree(policies);
        }
    }

    private static void SetPolicy(uint flags)
    {
        var policy = new[] { new AuditPolicyInformation { AuditSubCategoryGuid = FileSystemSubcategory, AuditingInformation = flags } };
        if (!AuditSetSystemPolicy(policy, 1))
            throw new InvalidOperationException($"Windows refused to change the file auditing policy (error {Marshal.GetLastWin32Error()}).");
    }

    /// <summary>
    /// Reading or changing audit settings needs SeSecurityPrivilege switched on in the sensor's own token.
    /// </summary>
    private static void EnablePrivilege(string privilege)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
            return;

        try
        {
            if (!LookupPrivilegeValue(null, privilege, out var luid))
                return;

            var privileges = new TokenPrivileges { PrivilegeCount = 1, Luid = luid, Attributes = SePrivilegeEnabled };
            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct AuditPolicyInformation
    {
        public Guid AuditSubCategoryGuid;
        public uint AuditingInformation;
        public Guid AuditCategoryGuid;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    private const uint TokenAdjustPrivileges = 0x20;
    private const uint TokenQuery = 0x8;
    private const uint SePrivilegeEnabled = 0x2;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditQuerySystemPolicy([In] Guid[] subCategoryGuids, uint policyCount, out IntPtr auditPolicy);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AuditSetSystemPolicy([In] AuditPolicyInformation[] auditPolicy, uint policyCount);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TokenPrivileges newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
