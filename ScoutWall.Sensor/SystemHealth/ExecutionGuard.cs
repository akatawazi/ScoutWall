using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading.Channels;
using ScoutWall.Sensor.Processes;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Keeps blocked programs from running. The real block is a deny-execute permission on the file, which makes
/// Windows refuse to start it. As a backstop, a blocked program that still starts (for example from a copy the
/// permission didn't cover) is ended as soon as its start is seen. Ending happens on a worker, never on the event
/// thread that reported the start.
/// </summary>
public static class ExecutionGuard
{
    private static readonly SecurityIdentifier Everyone = new(WellKnownSidType.WorldSid, null);
    private static readonly ConcurrentDictionary<string, long> BlockedPaths = new(StringComparer.OrdinalIgnoreCase);

    public static Channel<(int ProcessId, string ImagePath)> PendingKills { get; } =
        Channel.CreateBounded<(int, string)>(new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.DropOldest });

    /// <summary>
    /// Replaces the set of blocked program paths (each with the id of the action that blocks it).
    /// </summary>
    public static void SetBlocked(IReadOnlyDictionary<string, long> blockedPaths)
    {
        foreach (var path in BlockedPaths.Keys.Where(path => !blockedPaths.ContainsKey(path)).ToList())
            BlockedPaths.TryRemove(path, out _);

        foreach (var (path, actionId) in blockedPaths)
            BlockedPaths[path] = actionId;
    }

    public static bool TryGetBlockingAction(string imagePath, out long actionId)
    {
        return BlockedPaths.TryGetValue(imagePath, out actionId);
    }

    /// <summary>
    /// Called for every process start; cheap when nothing is blocked.
    /// </summary>
    public static void OnProcessStarted(int processId, string imagePath)
    {
        if (!BlockedPaths.IsEmpty && BlockedPaths.ContainsKey(imagePath))
            PendingKills.Writer.TryWrite((processId, imagePath));
    }

    [SupportedOSPlatform("windows")]
    public static void DenyExecute(string path)
    {
        var fileInfo = new FileInfo(path);
        var security = fileInfo.GetAccessControl();
        security.AddAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
        fileInfo.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    public static void AllowExecute(string path)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            return;

        var security = fileInfo.GetAccessControl();
        security.RemoveAccessRule(new FileSystemAccessRule(Everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
        fileInfo.SetAccessControl(security);
    }

    [SupportedOSPlatform("windows")]
    public static bool HasDenyExecute(string path)
    {
        var fileInfo = new FileInfo(path);
        if (!fileInfo.Exists)
            return false;

        return fileInfo.GetAccessControl().GetAccessRules(true, false, typeof(SecurityIdentifier))
            .OfType<FileSystemAccessRule>()
            .Any(rule => rule.AccessControlType == AccessControlType.Deny
                && rule.IdentityReference.Equals(Everyone)
                && rule.FileSystemRights.HasFlag(FileSystemRights.ExecuteFile));
    }

    /// <summary>
    /// Ends every running copy of the program. Each process is checked again right before it is ended, so a
    /// reused process id never ends the wrong program. Returns how many were ended.
    /// </summary>
    public static int EndAll(string imagePath)
    {
        var endedCount = 0;
        foreach (var process in NativeSystem.ListProcesses())
        {
            if (string.Equals(Path.GetFileName(imagePath), process.ImageName, StringComparison.OrdinalIgnoreCase) && End(process.ProcessId, imagePath))
                endedCount++;
        }

        return endedCount;
    }

    public static bool End(int processId, string expectedPath)
    {
        if (!OperatingSystem.IsWindows() || processId is 0 or 4 || processId == Environment.ProcessId)
            return false;

        var processHandle = OpenProcess(ProcessTerminate | ProcessQueryLimitedInformation, false, processId);
        if (processHandle == IntPtr.Zero)
            return false;

        try
        {
            var currentPath = ProcessPathResolver.QueryCurrentPath(processHandle);
            return string.Equals(currentPath, expectedPath, StringComparison.OrdinalIgnoreCase) && TerminateProcess(processHandle, 1);
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private const uint ProcessTerminate = 0x0001;
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(IntPtr processHandle, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
