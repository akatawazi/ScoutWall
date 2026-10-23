using System.Net.NetworkInformation;
using System.Threading.Channels;
using ScoutWall.Sensor.Capture;
using ScoutWall.Sensor.Processing;
using SharpPcap;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Runs the packet sources, feeds frames through the packet processor on a single consumer, and flushes
/// aggregates to SQLite every ten seconds in one transaction. Restarts when capture settings change.
/// </summary>
public class CaptureWorker : BackgroundService
{
    private const string LibpcapMissingMessage =
        "libpcap is not installed, so live capture is unavailable. Install it with your package manager (for example: apt install libpcap0.8) and restart ScoutWall.";
    private const int MaximumUnsavedBatches = 30;
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(10);

    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<CaptureWorker> logger;
    private readonly Queue<FlushBatch> unsavedBatches = new();

    public CaptureWorker(SensorRuntime sensorRuntime, ILogger<CaptureWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await sensorRuntime.WaitUntilReady(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            using var captureCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, sensorRuntime.CaptureRestartToken);
            try
            {
                await RunCapture(captureCancellation.Token);
            }
            catch (OperationCanceledException) when (captureCancellation.IsCancellationRequested)
            {
                logger.LogInformation("Capture stopped");
            }
            catch (Exception exception)
            {
                if (exception.Message != sensorRuntime.LastError)
                    logger.LogError("Capture failed: {Message}", exception.Message);

                sensorRuntime.LastError = exception.Message;
                await SensorWorker.DelayQuietly(TimeSpan.FromMinutes(1), captureCancellation.Token);
            }
        }
    }

    private async Task RunCapture(CancellationToken cancellationToken)
    {
        var packetSources = CreateSources();
        sensorRuntime.CapturingInterfaces = packetSources
            .SelectMany(packetSource => packetSource is EtwPacketSource etwPacketSource ? etwPacketSource.InterfaceNames : [packetSource.Name])
            .ToList();
        logger.LogInformation("Capturing on {Interfaces}", string.Join(", ", sensorRuntime.CapturingInterfaces));

        var frameChannel = Channel.CreateBounded<CapturedFrame>(new BoundedChannelOptions(100_000)
        {
            FullMode = BoundedChannelFullMode.Wait
        });

        using var packetProcessor = new PacketProcessor(sensorRuntime);
        var sourceTasks = packetSources.Select(packetSource => RunSource(packetSource, frameChannel.Writer, cancellationToken)).ToList();

        try
        {
            await ConsumeFrames(frameChannel.Reader, packetProcessor, cancellationToken);
        }
        finally
        {
            await Task.WhenAll(sourceTasks);
            await Flush(packetProcessor.Drain());
        }
    }

    private List<IPacketSource> CreateSources()
    {
        var startupOptions = sensorRuntime.StartupOptions;
        var captureSettings = sensorRuntime.Configuration.Capture;

        if (startupOptions.CaptureMode == CaptureMode.Synthetic)
            return [new SyntheticPacketSource()];

        if (startupOptions.CaptureMode == CaptureMode.File)
            return [new FilePacketSource(startupOptions.CaptureFilePath ?? throw new InvalidOperationException("Sensor:CaptureFilePath is not set."))];

        var deviceNames = captureSettings.InterfaceNames.Count > 0 ? captureSettings.InterfaceNames : DefaultDeviceNames();

        // Windows: Npcap when it is installed (faster, promiscuous mode, loopback), otherwise Windows' own capture.
        if (OperatingSystem.IsWindows() && !IsPcapAvailable())
        {
            if (!loggedCaptureChoice)
                logger.LogInformation("Npcap is not installed; capturing with Windows' built-in packet capture");
            loggedCaptureChoice = true;
            sensorRuntime.CaptureEngine = "Windows built-in capture";
            return [new EtwPacketSource(deviceNames)];
        }

        if (!IsPcapAvailable())
            throw new InvalidOperationException(LibpcapMissingMessage);

        sensorRuntime.CaptureEngine = OperatingSystem.IsWindows() ? "Npcap" : "libpcap";
        return deviceNames
            .Select(deviceName => (IPacketSource)new LivePacketSource(deviceName, captureSettings.Promiscuous, captureSettings.CaptureFilter))
            .ToList();
    }

    /// <summary>
    /// With nothing selected, capture on the adapters that actually reach a network (they have a default
    /// gateway), which skips the many virtual adapters Hyper-V, WSL and VPN clients create.
    /// </summary>
    private static List<string> DefaultDeviceNames()
    {
        var activeInterfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback
                && networkInterface.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .ToList();

        var gatewayInterfaces = activeInterfaces
            .Where(networkInterface => networkInterface.GetIPProperties().GatewayAddresses
                .Any(gateway => !gateway.Address.Equals(System.Net.IPAddress.Any) && !gateway.Address.Equals(System.Net.IPAddress.IPv6Any)))
            .ToList();

        return (gatewayInterfaces.Count > 0 ? gatewayInterfaces : activeInterfaces)
            .Select(ConfigurationWorker.CaptureDeviceName)
            .ToList();
    }

    /// <summary>
    /// Fails once with a clear message instead of once per interface when Npcap is missing.
    /// </summary>
    private bool loggedCaptureChoice;

    /// <summary>
    /// Whether Npcap (Windows) or libpcap (Linux) can be loaded.
    /// </summary>
    private static bool IsPcapAvailable()
    {
        try
        {
            _ = SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance.Count;
            return true;
        }
        catch (Exception exception) when (exception is DllNotFoundException or TypeInitializationException or PcapException or BadImageFormatException)
        {
            return false;
        }
    }

    private async Task RunSource(IPacketSource packetSource, ChannelWriter<CapturedFrame> frameWriter, CancellationToken cancellationToken)
    {
        try
        {
            await packetSource.Run(frameWriter, sensorRuntime.Statistics, cancellationToken);
            logger.LogInformation("Packet source {Source} finished", packetSource.Name);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is DllNotFoundException or TypeInitializationException or PcapException)
        {
            var message = OperatingSystem.IsWindows() ? "Npcap stopped working; restart ScoutWall to fall back to Windows' built-in capture." : LibpcapMissingMessage;
            logger.LogError("{Message} ({Detail})", message, exception.Message);
            sensorRuntime.LastError = message;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Packet source {Source} failed", packetSource.Name);
            sensorRuntime.LastError = $"{packetSource.Name}: {exception.Message}";
        }
    }

    private async Task ConsumeFrames(ChannelReader<CapturedFrame> frameReader, PacketProcessor packetProcessor, CancellationToken cancellationToken)
    {
        var nextFlush = DateTime.UtcNow.Add(FlushInterval);

        while (!cancellationToken.IsCancellationRequested)
        {
            while (DateTime.UtcNow < nextFlush && frameReader.TryRead(out var capturedFrame))
                packetProcessor.Process(capturedFrame);

            if (DateTime.UtcNow >= nextFlush)
            {
                await Flush(packetProcessor.Drain());
                nextFlush = DateTime.UtcNow.Add(FlushInterval);
                continue;
            }

            var waitTime = nextFlush - DateTime.UtcNow;
            await Task.WhenAny(frameReader.WaitToReadAsync(cancellationToken).AsTask(), Task.Delay(waitTime, cancellationToken));
        }
    }

    /// <summary>
    /// Writes the batch, after first retrying any batches that failed earlier (for example while the database
    /// was locked). Upserts add counts, and a failed transaction wrote nothing, so a retry never double-counts.
    /// </summary>
    private async Task Flush(FlushBatch flushBatch)
    {
        unsavedBatches.Enqueue(flushBatch);

        while (unsavedBatches.Count > 0)
        {
            if (!await TryWrite(unsavedBatches.Peek()))
                break;

            unsavedBatches.Dequeue();
        }

        while (unsavedBatches.Count > MaximumUnsavedBatches)
        {
            var droppedBatch = unsavedBatches.Dequeue();
            logger.LogError("Discarded {Count} unsaved traffic rows after repeated database failures", droppedBatch.TrafficCounts.Count);
        }
    }

    private async Task<bool> TryWrite(FlushBatch flushBatch)
    {
        try
        {
            await using var dataContext = sensorRuntime.CreateDataContext();
            await using var transaction = await dataContext.Database.BeginTransactionAsync();
            await TrafficMinute.Record(dataContext, flushBatch.TrafficCounts);
            await TrafficHour.Record(dataContext, flushBatch.TrafficCounts);
            await IpAddressProfile.RecordSeen(dataContext, flushBatch.SeenAddresses);
            await DnsRecord.RecordObservations(dataContext, flushBatch.DnsObservations);
            await TlsSession.RecordObservations(dataContext, flushBatch.TlsObservations);
            await transaction.CommitAsync();
            return true;
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Writing {Count} traffic rows failed; will retry", flushBatch.TrafficCounts.Count);
            sensorRuntime.LastError = $"Database write failed: {exception.Message}";
            return false;
        }
    }
}
