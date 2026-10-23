using System.Net.NetworkInformation;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Waits for the web application to create the database, loads the configuration, publishes the capture
/// interfaces, then keeps the configuration current and writes the sensor heartbeat.
/// </summary>
public class ConfigurationWorker : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan InterfacePublishInterval = TimeSpan.FromMinutes(5);

    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<ConfigurationWorker> logger;
    private DateTime lastHeartbeat = DateTime.MinValue;
    private DateTime lastInterfacePublish = DateTime.MinValue;
    private long lastPacketsCaptured;
    private long lastBytesCaptured;

    public ConfigurationWorker(SensorRuntime sensorRuntime, ILogger<ConfigurationWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await WaitForSchema(stoppingToken);
        await LoadConfiguration();
        sensorRuntime.MarkReady();
        logger.LogInformation("Sensor {SensorName} ready. Database {DatabasePath}, capture mode {CaptureMode}",
            sensorRuntime.StartupOptions.SensorName, sensorRuntime.DatabasePath, sensorRuntime.StartupOptions.CaptureMode);

        while (await SensorWorker.DelayQuietly(PollInterval, stoppingToken))
        {
            try
            {
                await RunOnce();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Configuration pass failed");
                sensorRuntime.LastError = exception.Message;
            }
        }
    }

    private async Task WaitForSchema(CancellationToken stoppingToken)
    {
        var loggedWaiting = false;
        while (!await DataContext.IsSchemaCurrent(sensorRuntime.DatabasePath))
        {
            if (!loggedWaiting)
                logger.LogWarning("Waiting for the ScoutWall web application to create or upgrade the database at {DatabasePath}", sensorRuntime.DatabasePath);

            loggedWaiting = true;
            await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
        }
    }

    private async Task RunOnce()
    {
        await using var dataContext = sensorRuntime.CreateDataContext();

        var latestRevision = await Setting.GetLatestRevision(dataContext);
        if (latestRevision != sensorRuntime.Configuration.Revision)
        {
            await LoadConfiguration();
            logger.LogInformation("Configuration reloaded at revision {Revision}", latestRevision);
        }

        if (DateTime.UtcNow - lastInterfacePublish >= InterfacePublishInterval)
            await PublishInterfaces(dataContext);

        if (DateTime.UtcNow - lastHeartbeat >= HeartbeatInterval)
            await WriteHeartbeat(dataContext);
    }

    private async Task LoadConfiguration()
    {
        await using var dataContext = sensorRuntime.CreateDataContext();
        sensorRuntime.ApplyConfiguration(await SensorConfiguration.Load(dataContext));
        await PublishInterfaces(dataContext);

        var learningPeriod = await LearningPeriod.Load(dataContext);
        sensorRuntime.LearningPeriod = learningPeriod;
        var reclassifiedCount = await FlowVerdict.ReclassifyLearningPeriod(dataContext, learningPeriod);
        if (reclassifiedCount > 0)
            logger.LogInformation("Re-marked {Count} learning-period verdicts as normal", reclassifiedCount);
    }

    private async Task PublishInterfaces(DataContext dataContext)
    {
        var selectedNames = sensorRuntime.Configuration.Capture.InterfaceNames;
        var captureInterfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up
                || selectedNames.Contains(CaptureDeviceName(networkInterface)))
            .Select(networkInterface => ToCaptureInterface(networkInterface, sensorRuntime.CapturingInterfaces))
            .ToList();

        foreach (var selectedName in selectedNames.Where(name => captureInterfaces.All(item => item.Name != name)))
            captureInterfaces.Add(new CaptureInterface { Name = selectedName, FriendlyName = "(not present)", LastSeenAt = DateTime.UtcNow });

        await CaptureInterface.Publish(dataContext, captureInterfaces);
        lastInterfacePublish = DateTime.UtcNow;
    }

    /// <summary>
    /// On Windows, Npcap names devices \Device\NPF_{adapter id} (Windows' own capture uses the same names), so the
    /// list can be built without Npcap installed. On Linux, libpcap uses the interface name, such as eth0.
    /// </summary>
    public static string CaptureDeviceName(NetworkInterface networkInterface)
    {
        if (!OperatingSystem.IsWindows())
            return networkInterface.Name;

        return networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback
            ? @"\Device\NPF_Loopback"
            : $@"\Device\NPF_{networkInterface.Id}";
    }

    private static CaptureInterface ToCaptureInterface(NetworkInterface networkInterface, List<string> capturingInterfaces)
    {
        var name = CaptureDeviceName(networkInterface);
        var addresses = networkInterface.GetIPProperties().UnicastAddresses.Select(address => address.Address.ToString());
        var macAddress = networkInterface.GetPhysicalAddress().ToString();

        return new CaptureInterface
        {
            Name = name,
            FriendlyName = networkInterface.Name,
            Description = $"{networkInterface.Description} ({networkInterface.OperationalStatus})",
            Addresses = string.Join(", ", addresses),
            MacAddress = string.IsNullOrEmpty(macAddress) ? null : macAddress,
            IsLoopback = networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback,
            IsRecommended = networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType is not (NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)
                && networkInterface.GetIPProperties().GatewayAddresses.Any(gateway => !gateway.Address.Equals(System.Net.IPAddress.Any) && !gateway.Address.Equals(System.Net.IPAddress.IPv6Any)),
            IsCapturing = capturingInterfaces.Contains(name),
            LastSeenAt = DateTime.UtcNow
        };
    }

    private async Task WriteHeartbeat(DataContext dataContext)
    {
        var now = DateTime.UtcNow;
        var elapsedSeconds = lastHeartbeat == DateTime.MinValue ? HeartbeatInterval.TotalSeconds : (now - lastHeartbeat).TotalSeconds;
        var statistics = sensorRuntime.Statistics;
        var packetsCaptured = statistics.PacketsCaptured;
        var bytesCaptured = statistics.BytesCaptured;

        var sensorStatus = new SensorStatus
        {
            SensorName = sensorRuntime.StartupOptions.SensorName,
            CaptureMode = sensorRuntime.CaptureEngine == null ? sensorRuntime.StartupOptions.CaptureMode.ToString() : $"{sensorRuntime.StartupOptions.CaptureMode} ({sensorRuntime.CaptureEngine})",
            Interfaces = string.Join(", ", sensorRuntime.CapturingInterfaces),
            StartedAt = sensorRuntime.StartedAt,
            LastHeartbeatAt = now,
            PacketsCaptured = packetsCaptured,
            PacketsDropped = statistics.PacketsDropped,
            BytesCaptured = bytesCaptured,
            PacketsPerSecond = (packetsCaptured - lastPacketsCaptured) / elapsedSeconds,
            BitsPerSecond = (bytesCaptured - lastBytesCaptured) * 8 / elapsedSeconds,
            IsUserIdle = sensorRuntime.Idle.IsIdle,
            ActiveResponseMode = sensorRuntime.Configuration.Response.Mode.ToString(),
            ConfigurationVersion = sensorRuntime.Configuration.Revision,
            LastError = sensorRuntime.LastError is { Length: > 1000 } error ? error[..1000] : sensorRuntime.LastError
        };

        await SensorStatus.Heartbeat(dataContext, sensorStatus);
        lastHeartbeat = now;
        lastPacketsCaptured = packetsCaptured;
        lastBytesCaptured = bytesCaptured;
    }
}
