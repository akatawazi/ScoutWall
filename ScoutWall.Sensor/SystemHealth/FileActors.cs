using System.Collections.Concurrent;
using ScoutWall.Sensor.Processes;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Which program created, deleted or renamed a file, from the low-volume Kernel-File events. The change journal
/// says what changed but not who; this fills in "who" for those three kinds. Writes to existing files are not
/// attributed here (per-write events would bury the sensor); per-program write totals come from the I/O counters.
/// </summary>
public static class FileActors
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private const int MaximumEntries = 200_000;

    private static readonly ConcurrentDictionary<string, (string ImagePath, DateTime SeenAt)> Actors = new(StringComparer.OrdinalIgnoreCase);

    public static void Remember(int processId, string? devicePath)
    {
        if (string.IsNullOrEmpty(devicePath) || processId <= 4)
            return;

        var path = ProcessPathResolver.ToDrivePath(devicePath, refreshOnMiss: false);
        if (path == null)
            return;

        if (Actors.Count >= MaximumEntries)
            Prune(DateTime.UtcNow, aggressive: true);

        // A program that couldn't be identified is left out rather than recorded as a program named "Unknown".
        var imagePath = ProcessPathResolver.Resolve(processId);
        if (imagePath == ProcessPathResolver.UnknownProcess)
            return;

        Actors[path] = (imagePath, DateTime.UtcNow);
    }

    public static string? Find(string path)
    {
        return Actors.TryGetValue(path, out var actor) ? actor.ImagePath : null;
    }

    public static void Prune(DateTime now, bool aggressive = false)
    {
        var cutoff = now - (aggressive ? Lifetime / 4 : Lifetime);
        foreach (var entry in Actors.Where(entry => entry.Value.SeenAt < cutoff).ToList())
            Actors.TryRemove(entry.Key, out _);
    }
}
