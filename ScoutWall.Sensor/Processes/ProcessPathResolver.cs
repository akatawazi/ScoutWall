using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;

namespace ScoutWall.Sensor.Processes;

/// <summary>
/// Maps process ids to executable paths. Cached briefly because ids are reused once a process exits.
/// </summary>
public static class ProcessPathResolver
{
    public const string UnknownProcess = "Unknown";
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan UnknownCacheLifetime = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ExitedProcessMemory = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<int, (string ImagePath, DateTime ResolvedAt)> Cache = new();

    /// <summary>
    /// Paths reported when processes start, so traffic from a program that has already exited (installers,
    /// downloaders, scripts) is still attributed to it instead of "Unknown".
    /// </summary>
    private static readonly ConcurrentDictionary<int, (string ImagePath, DateTime? ExitedAt)> StartedProcesses = new();
    private static Dictionary<string, string> devicePrefixes = [];
    private static DateTime lastPrune = DateTime.UtcNow;

    public static void RememberStart(int processId, string imageName)
    {
        var imagePath = ToDrivePath(imageName);
        if (imagePath != null)
        {
            StartedProcesses[processId] = (imagePath, null);
            Cache.TryRemove(processId, out _);
            SystemHealth.ExecutionGuard.OnProcessStarted(processId, imagePath);
        }
    }

    public static void RememberExit(int processId)
    {
        if (StartedProcesses.TryGetValue(processId, out var started))
            StartedProcesses[processId] = (started.ImagePath, DateTime.UtcNow);

        var now = DateTime.UtcNow;
        if (now - lastPrune < TimeSpan.FromMinutes(1))
            return;

        lastPrune = now;
        foreach (var entry in StartedProcesses.Where(entry => entry.Value.ExitedAt < now - ExitedProcessMemory).ToList())
            StartedProcesses.TryRemove(entry.Key, out _);
    }

    /// <summary>
    /// Turns \Device\HarddiskVolume3\Windowspp.exe into C:\Windowspp.exe.
    /// </summary>
    /// <remarks>
    /// High-volume callers (file events, which include pipes and network shares) pass refreshOnMiss false so a miss
    /// doesn't re-read the device table.
    /// </remarks>
    public static string? ToDrivePath(string imageName, bool refreshOnMiss = true)
    {
        if (imageName.Length > 2 && imageName[1] == ':')
            return imageName;

        if (!imageName.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) || !OperatingSystem.IsWindows())
            return null;

        for (var attempt = 0; attempt < 2; attempt++)
        {
            foreach (var (devicePrefix, drive) in devicePrefixes)
            {
                if (imageName.StartsWith(devicePrefix + @"\", StringComparison.OrdinalIgnoreCase))
                    return drive + imageName[devicePrefix.Length..];
            }

            if (!refreshOnMiss && devicePrefixes.Count > 0)
                return null;

            devicePrefixes = ReadDevicePrefixes();
        }

        return null;
    }

    private static Dictionary<string, string> ReadDevicePrefixes()
    {
        var prefixes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in Environment.GetLogicalDrives())
        {
            var driveName = drive.TrimEnd('\\');
            var target = new StringBuilder(1024);
            if (QueryDosDevice(driveName, target, target.Capacity) > 0)
                prefixes[target.ToString()] = driveName;
        }

        return prefixes;
    }

    public static string Resolve(int processId)
    {
        if (processId == 0)
            return "Idle";

        if (processId == 4)
            return "System";

        var now = DateTime.UtcNow;
        if (Cache.TryGetValue(processId, out var cached) && now - cached.ResolvedAt < CacheLifetime)
            return cached.ImagePath;

        var imagePath = QueryImagePath(processId)
            ?? (StartedProcesses.TryGetValue(processId, out var started) ? started.ImagePath : null);

        // A failed lookup is retried soon, in case the start event for the process arrives a moment later.
        Cache[processId] = (imagePath ?? UnknownProcess, imagePath == null ? now - CacheLifetime + UnknownCacheLifetime : now);
        return imagePath ?? UnknownProcess;
    }

    private static string? QueryImagePath(int processId)
    {
        if (!OperatingSystem.IsWindows())
            return null;

        var processHandle = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (processHandle == IntPtr.Zero)
            return null;

        try
        {
            return QueryCurrentPath(processHandle);
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    /// <summary>
    /// The executable of an already opened process handle, read fresh rather than from the cache.
    /// </summary>
    public static string? QueryCurrentPath(IntPtr processHandle)
    {
        var pathBuilder = new StringBuilder(1024);
        var length = pathBuilder.Capacity;
        return QueryFullProcessImageName(processHandle, 0, pathBuilder, ref length) ? pathBuilder.ToString() : null;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr processHandle, int flags, StringBuilder exeName, ref int size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint QueryDosDevice(string deviceName, StringBuilder targetPath, int maximumLength);
}
