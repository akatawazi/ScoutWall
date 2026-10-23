using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Cumulative counters for one physical disk, straight from the disk driver (IOCTL_DISK_PERFORMANCE). Unlike
/// performance counters these have no localized names and no counter registry to go wrong.
/// </summary>
public readonly record struct DiskCounters(int DiskNumber, long BytesRead, long BytesWritten, long ReadCount, long WriteCount, long IdleTime, long QueryTime, int QueueDepth);

/// <summary>
/// The activity of one disk between two readings.
/// </summary>
public record DiskActivity(int DiskNumber, string Drives, long ReadBytes, long WriteBytes, long ReadCount, long WriteCount, double BusyPercent, int QueueDepth);

/// <summary>
/// A fixed drive's size and free space.
/// </summary>
public record DriveSpace(string Name, string Label, string Format, long TotalBytes, long FreeBytes)
{
    public double FreeShare => TotalBytes == 0 ? 0 : (double)FreeBytes / TotalBytes;
}

public class DiskPerformance
{
    private const int MaximumDisks = 32;
    private const uint IoctlDiskPerformance = 0x00070020;
    private const uint IoctlStorageGetDeviceNumber = 0x002D1080;
    private const int DiskPerformanceSize = 88;

    private readonly Dictionary<int, DiskCounters> previous = [];

    /// <summary>
    /// Reads every disk and returns the change since the last call. The first call only sets the baseline.
    /// </summary>
    public List<DiskActivity> Sample()
    {
        if (!OperatingSystem.IsWindows())
            return [];

        var drivesByDisk = DriveLettersByDisk();
        var activity = new List<DiskActivity>();
        foreach (var counters in ReadAll())
        {
            if (previous.TryGetValue(counters.DiskNumber, out var before) && counters.QueryTime > before.QueryTime)
            {
                var elapsed = counters.QueryTime - before.QueryTime;
                var idle = Math.Clamp(counters.IdleTime - before.IdleTime, 0, elapsed);
                activity.Add(new DiskActivity(
                    counters.DiskNumber,
                    drivesByDisk.TryGetValue(counters.DiskNumber, out var letters) ? string.Join(", ", letters) : string.Empty,
                    Math.Max(0, counters.BytesRead - before.BytesRead),
                    Math.Max(0, counters.BytesWritten - before.BytesWritten),
                    Math.Max(0, counters.ReadCount - before.ReadCount),
                    Math.Max(0, counters.WriteCount - before.WriteCount),
                    Math.Round(100.0 * (elapsed - idle) / elapsed, 1),
                    counters.QueueDepth));
            }

            previous[counters.DiskNumber] = counters;
        }

        return activity;
    }

    public static List<DriveSpace> ReadDriveSpace()
    {
        var drives = new List<DriveSpace>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady)
                    continue;

                drives.Add(new DriveSpace(drive.Name.TrimEnd('\\'), drive.VolumeLabel, drive.DriveFormat, drive.TotalSize, drive.AvailableFreeSpace));
            }
            catch (IOException)
            {
                // A drive that disappears mid-read is skipped.
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return drives;
    }

    private static List<DiskCounters> ReadAll()
    {
        var disks = new List<DiskCounters>();
        var buffer = Marshal.AllocHGlobal(DiskPerformanceSize);
        try
        {
            for (var diskNumber = 0; diskNumber < MaximumDisks; diskNumber++)
            {
                using var handle = CreateFile($@"\\.\PhysicalDrive{diskNumber}", 0, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
                if (handle.IsInvalid)
                    continue;

                if (!DeviceIoControl(handle, IoctlDiskPerformance, IntPtr.Zero, 0, buffer, DiskPerformanceSize, out _, IntPtr.Zero))
                    continue;

                // DISK_PERFORMANCE: BytesRead 0, BytesWritten 8, ReadTime 16, WriteTime 24, IdleTime 32, ReadCount 40,
                // WriteCount 44, QueueDepth 48, SplitCount 52, QueryTime 56.
                disks.Add(new DiskCounters(
                    diskNumber,
                    Marshal.ReadInt64(buffer, 0),
                    Marshal.ReadInt64(buffer, 8),
                    (uint)Marshal.ReadInt32(buffer, 40),
                    (uint)Marshal.ReadInt32(buffer, 44),
                    Marshal.ReadInt64(buffer, 32),
                    Marshal.ReadInt64(buffer, 56),
                    Marshal.ReadInt32(buffer, 48)));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return disks;
    }

    /// <summary>
    /// Which drive letters live on which physical disk. A volume spanning disks is listed under the first.
    /// </summary>
    private static Dictionary<int, List<string>> DriveLettersByDisk()
    {
        var result = new Dictionary<int, List<string>>();
        var buffer = Marshal.AllocHGlobal(12);
        try
        {
            foreach (var drive in DriveInfo.GetDrives().Where(drive => drive.DriveType == DriveType.Fixed))
            {
                var letter = drive.Name.TrimEnd('\\');
                using var handle = CreateFile($@"\\.\{letter}", 0, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
                if (handle.IsInvalid || !DeviceIoControl(handle, IoctlStorageGetDeviceNumber, IntPtr.Zero, 0, buffer, 12, out _, IntPtr.Zero))
                    continue;

                // STORAGE_DEVICE_NUMBER: DeviceType 0, DeviceNumber 4, PartitionNumber 8.
                var diskNumber = Marshal.ReadInt32(buffer, 4);
                if (!result.TryGetValue(diskNumber, out var letters))
                    result[diskNumber] = letters = [];
                letters.Add(letter);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }

        return result;
    }

    private const uint FileShareReadWrite = 0x1 | 0x2;
    private const uint OpenExisting = 3;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint controlCode, IntPtr inBuffer, int inBufferSize, IntPtr outBuffer, int outBufferSize, out int bytesReturned, IntPtr overlapped);
}
