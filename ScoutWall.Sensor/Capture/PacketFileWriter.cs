using PacketDotNet;

namespace ScoutWall.Sensor.Capture;

/// <summary>
/// Writes frames to a rotating set of classic pcap files (a ring buffer) for forensics and offline decryption.
/// Files open in Wireshark. The oldest files are deleted once the configured count is exceeded.
/// </summary>
public class PacketFileWriter : IDisposable
{
    public const string FileExtension = ".pcap";
    public const string ProcessedMarkerExtension = ".done";

    private readonly string directoryPath;
    private readonly string filePrefix;
    private readonly long maximumFileBytes;
    private readonly int maximumFileCount;
    private FileStream? currentStream;
    private LinkLayers currentLinkType;

    public PacketFileWriter(string directoryPath, string filePrefix, int maximumFileMegabytes, int maximumFileCount)
    {
        this.directoryPath = directoryPath;
        this.filePrefix = filePrefix;
        this.maximumFileBytes = maximumFileMegabytes * 1024L * 1024L;
        this.maximumFileCount = maximumFileCount;
        Directory.CreateDirectory(directoryPath);
    }

    public string? CurrentFilePath => currentStream?.Name;

    public void Write(CapturedFrame capturedFrame)
    {
        if (currentStream == null || currentStream.Length >= maximumFileBytes || currentLinkType != capturedFrame.LinkType)
            StartNewFile(capturedFrame.LinkType);

        var unixTime = capturedFrame.Timestamp - DateTime.UnixEpoch;
        var seconds = (uint)unixTime.TotalSeconds;
        var microseconds = (uint)(unixTime.Ticks % TimeSpan.TicksPerSecond / 10);

        Span<byte> recordHeader = stackalloc byte[16];
        BitConverter.TryWriteBytes(recordHeader, seconds);
        BitConverter.TryWriteBytes(recordHeader[4..], microseconds);
        BitConverter.TryWriteBytes(recordHeader[8..], capturedFrame.Data.Length);
        BitConverter.TryWriteBytes(recordHeader[12..], capturedFrame.OriginalLength);

        currentStream!.Write(recordHeader);
        currentStream.Write(capturedFrame.Data);
    }

    public void Flush()
    {
        currentStream?.Flush();
    }

    public void Dispose()
    {
        currentStream?.Dispose();
        currentStream = null;
        GC.SuppressFinalize(this);
    }

    private void StartNewFile(LinkLayers linkType)
    {
        currentStream?.Dispose();

        var fileName = $"{filePrefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}{FileExtension}";
        currentStream = new FileStream(Path.Combine(directoryPath, fileName), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        currentLinkType = linkType;

        Span<byte> fileHeader = stackalloc byte[24];
        BitConverter.TryWriteBytes(fileHeader, 0xA1B2C3D4u);
        BitConverter.TryWriteBytes(fileHeader[4..], (ushort)2);
        BitConverter.TryWriteBytes(fileHeader[6..], (ushort)4);
        BitConverter.TryWriteBytes(fileHeader[16..], 65535u);
        BitConverter.TryWriteBytes(fileHeader[20..], (uint)linkType);
        currentStream.Write(fileHeader);

        DeleteOldFiles();
    }

    private void DeleteOldFiles()
    {
        var oldFiles = new DirectoryInfo(directoryPath)
            .GetFiles($"{filePrefix}-*{FileExtension}")
            .OrderByDescending(fileInfo => fileInfo.Name)
            .Skip(maximumFileCount);

        foreach (var oldFile in oldFiles)
        {
            TryDelete(oldFile.FullName);
            TryDelete(oldFile.FullName + ProcessedMarkerExtension);
        }
    }

    private static void TryDelete(string filePath)
    {
        try
        {
            File.Delete(filePath);
        }
        catch (IOException)
        {
            // In use by the decryption worker; removed on the next rotation.
        }
    }
}
