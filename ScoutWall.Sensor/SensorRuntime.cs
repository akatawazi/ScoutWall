using System.Net;
using System.Text.Json;
using System.Threading.Channels;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Network;
using ScoutWall.Sensor.Presence;
using ScoutWall.Sensor.Processes;

namespace ScoutWall.Sensor;

public enum CaptureMode
{
    Live = 1,
    File = 2,
    Synthetic = 3
}

/// <summary>
/// Bootstrap options from appsettings.json. Everything else is configured from the web application.
/// </summary>
public class SensorStartupOptions
{
    public string? DatabasePath { get; set; }
    public string SensorName { get; set; } = Environment.MachineName;
    public CaptureMode CaptureMode { get; set; } = CaptureMode.Live;
    public string? CaptureFilePath { get; set; }
    public string PacketFileDirectory { get; set; } = @"%ProgramData%\ScoutWall\packets";
}

/// <summary>
/// State shared by the sensor's background workers: the current configuration, the network view,
/// queues between workers and live counters.
/// </summary>
public class SensorRuntime
{
    private readonly TaskCompletionSource readySource = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private CancellationTokenSource captureRestartSource = new();
    private string captureSettingsJson = string.Empty;

    public SensorRuntime(SensorStartupOptions startupOptions)
    {
        StartupOptions = startupOptions;
        DatabasePath = DataContext.ResolveDatabasePath(startupOptions.DatabasePath);
        PacketFileDirectory = ScoutWall.Data.ScoutWallPaths.Resolve(startupOptions.PacketFileDirectory);
    }

    public SensorStartupOptions StartupOptions { get; }
    public string DatabasePath { get; }
    public string PacketFileDirectory { get; }
    public DateTime StartedAt { get; } = DateTime.UtcNow;
    public SensorConfiguration Configuration { get; private set; } = new();
    public NetworkClassifier NetworkClassifier { get; private set; } = NetworkClassifier.Build([]);
    public HostContext HostContext { get; private set; } = HostContext.Gather();
    public Blocklist Blocklist { get; set; } = Blocklist.Empty;
    public ConnectionOwnerMap ConnectionOwners { get; } = new();
    public IdleState Idle { get; set; } = IdleState.Unknown;
    public LearningPeriod? LearningPeriod { get; set; }
    public CaptureStatistics Statistics { get; } = new();
    public List<string> CapturingInterfaces { get; set; } = [];

    /// <summary>
    /// What live capture runs on: Npcap, libpcap or Windows built-in capture.
    /// </summary>
    public string? CaptureEngine { get; set; }
    public string? LastError { get; set; }

    public Channel<Alert> AlertQueue { get; } = Channel.CreateBounded<Alert>(new BoundedChannelOptions(10_000)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true
    });

    /// <summary>
    /// Cancelled whenever capture settings change, so the capture worker restarts on the new interfaces.
    /// </summary>
    public CancellationToken CaptureRestartToken => captureRestartSource.Token;

    public DataContext CreateDataContext()
    {
        return DataContext.Create(DatabasePath);
    }

    public Task WaitUntilReady(CancellationToken cancellationToken)
    {
        return readySource.Task.WaitAsync(cancellationToken);
    }

    public void MarkReady()
    {
        readySource.TrySetResult();
    }

    public void ApplyConfiguration(SensorConfiguration sensorConfiguration)
    {
        Configuration = sensorConfiguration;
        NetworkClassifier = NetworkClassifier.Build(sensorConfiguration.Capture.LocalNetworks);
        HostContext = HostContext.Gather();

        var newCaptureSettingsJson = JsonSerializer.Serialize(sensorConfiguration.Capture);
        if (captureSettingsJson.Length > 0 && newCaptureSettingsJson != captureSettingsJson)
        {
            var previousSource = captureRestartSource;
            captureRestartSource = new CancellationTokenSource();
            previousSource.Cancel();
            previousSource.Dispose();
        }

        captureSettingsJson = newCaptureSettingsJson;
    }

    public bool IsRuleEnabled(string ruleName)
    {
        return !Configuration.Detection.DisabledRules.Contains(ruleName, StringComparer.OrdinalIgnoreCase);
    }

    public bool IsAllowlistedAddress(IPAddress address)
    {
        return Configuration.Response.AllowlistedAddresses
            .Select(text => IpNetwork.TryParse(text, out var ipNetwork) ? ipNetwork : null)
            .Any(ipNetwork => ipNetwork != null && ipNetwork.Contains(address));
    }

    /// <summary>
    /// Full-path entries match exactly. Bare file names only match programs under Windows or Program Files,
    /// so malware cannot earn an exemption just by calling itself svchost.exe.
    /// </summary>
    public bool IsAllowlistedProgram(string imagePath)
    {
        return Configuration.Response.IsAllowlistedProgram(imagePath);
    }
}

public class CaptureStatistics
{
    private long packetsCaptured;
    private long bytesCaptured;
    private long packetsDropped;

    public long PacketsCaptured => Interlocked.Read(ref packetsCaptured);
    public long BytesCaptured => Interlocked.Read(ref bytesCaptured);
    public long PacketsDropped => Interlocked.Read(ref packetsDropped);

    public void RecordPacket(int length)
    {
        Interlocked.Increment(ref packetsCaptured);
        Interlocked.Add(ref bytesCaptured, length);
    }

    public void RecordDropped(long count = 1)
    {
        Interlocked.Add(ref packetsDropped, count);
    }
}
