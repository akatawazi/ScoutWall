using System.Threading.Channels;
using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ScoutWall.Sensor.Capture;

public record CapturedFrame(DateTime Timestamp, LinkLayers LinkType, byte[] Data, int OriginalLength, string InterfaceName);

/// <summary>
/// Anything that produces raw frames: a live interface, a capture file or the synthetic generator.
/// Keeping this seam lets the whole pipeline run and be tested without Npcap installed.
/// </summary>
public interface IPacketSource
{
    string Name { get; }
    Task Run(ChannelWriter<CapturedFrame> frameWriter, CaptureStatistics captureStatistics, CancellationToken cancellationToken);
}

/// <summary>
/// Live capture through Npcap (Windows) or libpcap. Requires Npcap to be installed.
/// </summary>
public class LivePacketSource : IPacketSource
{
    private readonly string deviceName;
    private readonly bool promiscuous;
    private readonly string? captureFilter;

    public LivePacketSource(string deviceName, bool promiscuous, string? captureFilter)
    {
        this.deviceName = deviceName;
        this.promiscuous = promiscuous;
        this.captureFilter = captureFilter;
    }

    public string Name => deviceName;

    public async Task Run(ChannelWriter<CapturedFrame> frameWriter, CaptureStatistics captureStatistics, CancellationToken cancellationToken)
    {
        var device = LibPcapLiveDeviceList.Instance.FirstOrDefault(item => item.Name == deviceName)
            ?? throw new InvalidOperationException($"Capture device {deviceName} was not found.");

        device.OnPacketArrival += (sender, packetCapture) =>
        {
            var rawCapture = packetCapture.GetPacket();
            var capturedFrame = new CapturedFrame(
                rawCapture.Timeval.Date.ToUniversalTime(),
                rawCapture.LinkLayerType,
                rawCapture.Data,
                rawCapture.PacketLength,
                deviceName);

            if (!frameWriter.TryWrite(capturedFrame))
                captureStatistics.RecordDropped();
        };

        device.Open(new DeviceConfiguration
        {
            Mode = promiscuous ? DeviceModes.Promiscuous : DeviceModes.None,
            ReadTimeout = 500,
            Snaplen = 65535
        });

        try
        {
            if (!string.IsNullOrWhiteSpace(captureFilter))
                device.Filter = captureFilter;

            device.StartCapture();
            await WaitForCancellation(cancellationToken);
        }
        finally
        {
            RecordKernelDrops(device, captureStatistics);
            device.StopCapture();
            device.Close();
        }
    }

    private static void RecordKernelDrops(LibPcapLiveDevice device, CaptureStatistics captureStatistics)
    {
        try
        {
            captureStatistics.RecordDropped(device.Statistics?.DroppedPackets ?? 0);
        }
        catch (PcapException)
        {
            // Statistics are unavailable on some adapters.
        }
    }

    private static async Task WaitForCancellation(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(Timeout.Infinite, cancellationToken);
        }
        catch (OperationCanceledException)
        {
        }
    }
}

/// <summary>
/// Reads a .pcap or .pcapng file without Npcap. Frames keep their original timestamps.
/// </summary>
public class FilePacketSource : IPacketSource
{
    private readonly string filePath;

    public FilePacketSource(string filePath)
    {
        this.filePath = filePath;
    }

    public string Name => Path.GetFileName(filePath);

    public async Task Run(ChannelWriter<CapturedFrame> frameWriter, CaptureStatistics captureStatistics, CancellationToken cancellationToken)
    {
        await using var fileStream = File.OpenRead(filePath);
        foreach (var capturedFrame in PacketFileReader.Read(fileStream, Name))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await frameWriter.WriteAsync(capturedFrame, cancellationToken);
        }
    }
}
