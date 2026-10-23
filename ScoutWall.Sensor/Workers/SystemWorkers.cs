using System.Diagnostics.Eventing.Reader;
using System.Text.Json;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.SystemHealth;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Samples processor and memory use every 30 seconds. Writes one machine row a minute, the heaviest programs every
/// five minutes, a snapshot of everything running once a minute, and the list of services every five minutes.
/// </summary>
public class SystemResourceWorker : SensorWorker
{
    private const int HeaviestProgramsPerMeasure = 25;
    private const double SampleSeconds = 30;
    private static readonly TimeSpan ServiceInterval = TimeSpan.FromMinutes(5);
    private readonly ResourceSampler resourceSampler = new();
    private readonly ResourceAccumulator resourceAccumulator = new();
    private DateTime lastServiceCheck;

    public SystemResourceWorker(SensorRuntime sensorRuntime, ILogger<SystemResourceWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(SampleSeconds);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var sample = resourceSampler.Sample();
        if (!sample.HasProcessorFigures)
            return;

        var nowUnixSeconds = new DateTimeOffset(sample.TakenAt).ToUnixTimeSeconds();
        var minuteBucket = nowUnixSeconds - nowUnixSeconds % 60;
        var programBucket = nowUnixSeconds - nowUnixSeconds % ProcessResourceSample.BucketSeconds;

        await using var dataContext = SensorRuntime.CreateDataContext();

        if (resourceAccumulator.MinuteBucket is long pendingMinute && pendingMinute != minuteBucket)
        {
            var minute = resourceAccumulator.TakeMinute();
            if (minute != null)
                await SystemResourceMinute.Insert(dataContext, minute);

            await SaveSnapshot(dataContext, sample);
        }

        if (resourceAccumulator.ProgramBucket is long pendingBucket && pendingBucket != programBucket)
            await SaveHeaviestPrograms(dataContext);

        resourceAccumulator.Add(sample, minuteBucket, programBucket);

        if (sample.TakenAt - lastServiceCheck >= ServiceInterval)
        {
            lastServiceCheck = sample.TakenAt;
            await CheckServices(dataContext, sample.TakenAt);
        }
    }

    private static async Task SaveSnapshot(DataContext dataContext, ResourceSampler.MachineSample sample)
    {
        var paths = sample.Programs.Select(program => program.ImagePath).ToList();
        var knownIds = (await ProcessImage.GetAll(dataContext, image => paths.Contains(image.ImagePath)))
            .ToDictionary(image => image.ImagePath, image => image.Id, StringComparer.OrdinalIgnoreCase);

        var snapshot = new RunningProgramSnapshot
        {
            TakenAt = sample.TakenAt,
            Programs = sample.Programs
                .Select(program => new RunningProgram
                {
                    ImagePath = program.ImagePath,
                    Name = ProcessImage.NameFromPath(program.ImagePath),
                    ProcessImageId = knownIds.TryGetValue(program.ImagePath, out var id) ? id : null,
                    InstanceCount = program.InstanceCount,
                    CpuPercent = Math.Round(program.CpuPercent, 1),
                    MemoryBytes = program.MemoryBytes,
                    PrivateBytes = program.PrivateBytes,
                    ReadBytesPerSecond = program.ReadBytes / (long)SampleSeconds,
                    WriteBytesPerSecond = program.WriteBytes / (long)SampleSeconds,
                    ProcessIds = program.ProcessIds.Take(20).ToList()
                })
                .OrderByDescending(program => program.MemoryBytes)
                .ToList()
        };

        await snapshot.Save(dataContext);
    }

    private async Task SaveHeaviestPrograms(DataContext dataContext)
    {
        var heaviest = resourceAccumulator.TakePrograms(HeaviestProgramsPerMeasure);
        if (heaviest.Count == 0)
            return;

        var ids = await ProcessImage.GetOrCreateIds(dataContext, heaviest.Select(row => row.ImagePath).ToList(), DateTime.UtcNow);
        foreach (var (imagePath, resourceSample) in heaviest)
        {
            if (ids.TryGetValue(imagePath, out var processImageId))
            {
                resourceSample.ProcessImageId = processImageId;
                dataContext.ProcessResourceSamples.Add(resourceSample);
            }
        }

        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }

    private async Task CheckServices(DataContext dataContext, DateTime seenAt)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var appeared = await SystemService.Synchronize(dataContext, ServiceReader.Read(), seenAt);
        foreach (var service in appeared)
        {
            var programPath = service.BinaryPath == null ? null : EventLogCollector.ExecutablePath(service.BinaryPath);
            if (ProtectedPrograms.IsScoutWall(programPath) || SensorRuntime.Configuration.Detection.DisabledRules.Contains("NewService"))
                continue;

            var summary = $"New service \"{service.ServiceName}\" ({service.DisplayName}) appeared. It runs {service.BinaryPath} as {service.Account}.";
            await SensorRuntime.AlertQueue.Writer.WriteAsync(HostAlerts.Create("NewService", AlertSeverity.Medium,
                $"New service installed: {service.ServiceName}", summary, service.ServiceName, programPath, seenAt, new { service.ServiceName, service.DisplayName, service.BinaryPath, service.Account, service.StartMode }));
        }
    }
}

/// <summary>
/// Reads the notable Windows events every minute, stores them, and raises alerts for the ones that matter. Events
/// from before ScoutWall started monitoring are stored for context but never alerted on.
/// </summary>
public class EventLogWorker : SensorWorker
{
    private const int FailedSignInThreshold = 10;
    private const int ServiceCrashThreshold = 3;

    public EventLogWorker(SensorRuntime sensorRuntime, ILogger<EventLogWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);

    /// <summary>
    /// The console runs without administrator rights, so turning on a Windows log is asked of the sensor.
    /// </summary>
    public const string EnableTaskLogRequestKey = "request:enable_task_log";

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private async Task EnableRequestedLogs(DataContext dataContext)
    {
        if (string.IsNullOrEmpty(await SystemState.GetValue(dataContext, EnableTaskLogRequestKey)))
            return;

        try
        {
            using var configuration = new EventLogConfiguration("Microsoft-Windows-TaskScheduler/Operational");
            if (!configuration.IsEnabled)
            {
                configuration.IsEnabled = true;
                configuration.SaveChanges();
            }

            Logger.LogInformation("Scheduled task logging turned on, as asked from the console");
        }
        catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException)
        {
            Logger.LogWarning("Could not turn on scheduled task logging: {Message}", exception.Message);
        }

        await SystemState.SetValue(dataContext, EnableTaskLogRequestKey, string.Empty);
    }

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        await EnableRequestedLogs(dataContext);
        var monitoringStartedAt = await SystemState.GetMonitoringStartedAt(dataContext);
        var unreadableChannels = new List<string>();

        foreach (var source in EventLogCollector.Sources)
        {
            var bookmarkKey = $"event_log_position:{source.Name}";
            var bookmark = long.TryParse(await SystemState.GetValue(dataContext, bookmarkKey), out var recordId) ? recordId : (long?)null;

            List<CollectedEvent> collected;
            try
            {
                collected = EventLogCollector.Read(source, bookmark);
            }
            catch (Exception exception) when (exception is EventLogException or UnauthorizedAccessException)
            {
                unreadableChannels.Add(source.Channel);
                continue;
            }

            foreach (var collectedEvent in collected)
            {
                await Store(dataContext, collectedEvent.SystemEvent);
                if (collectedEvent.SystemEvent.OccurredAt >= monitoringStartedAt)
                    await RaiseAlerts(dataContext, collectedEvent.SystemEvent);
            }

            if (collected.Count > 0)
                await SystemState.SetValue(dataContext, bookmarkKey, collected.Max(item => item.RecordId).ToString());
        }

        await new EventLogHealth
        {
            CheckedAt = DateTime.UtcNow,
            FailedSignInAuditingOn = NativeSystem.IsFailedSignInAuditingOn() ?? true,
            ScheduledTaskLogOn = EventLogCollector.IsChannelEnabled(EventLogCollector.TaskSchedulerChannel),
            UnreadableChannels = unreadableChannels.Distinct().ToList()
        }.Save(dataContext);
    }

    private static async Task Store(DataContext dataContext, SystemEvent systemEvent)
    {
        if (systemEvent.Channel == "Security" && systemEvent.EventId == 4625)
        {
            await SystemEvent.AddFailedSignIns(dataContext, systemEvent);
            return;
        }

        await SystemEvent.Insert(dataContext, systemEvent);
    }

    private async Task RaiseAlerts(DataContext dataContext, SystemEvent systemEvent)
    {
        var disabledRules = SensorRuntime.Configuration.Detection.DisabledRules;
        var programPath = systemEvent.ProgramPath;

        // ScoutWall installing or updating its own services is not news.
        if (ProtectedPrograms.IsScoutWall(programPath))
            return;

        var alertFor = EventLogCollector.AlertFor(systemEvent);
        if (alertFor is { } single && !disabledRules.Contains(single.Rule))
        {
            // Windows features create tasks in bursts (one per tip or update); one alert per task folder is enough.
            if (single.Rule == "NewScheduledTask")
            {
                var folder = EventLogCollector.TaskFolder(systemEvent.Subject);
                await Queue(single.Rule, single.Severity, $"New scheduled task in {folder}", systemEvent.Summary, folder, programPath, systemEvent);
                return;
            }

            await Queue(single.Rule, single.Severity, single.Title, systemEvent.Summary, systemEvent.Subject, programPath, systemEvent);
            return;
        }

        // Rules that only fire on repetition.
        if (systemEvent is { Channel: "Security", EventId: 4625 } && !disabledRules.Contains("FailedSignIns"))
        {
            var recentFailures = await SystemEvent.CountSince(dataContext, 4625, DateTime.UtcNow.AddMinutes(-10),
                systemEvent.RemoteAddress == null ? systemEvent.Subject : null, systemEvent.RemoteAddress);
            if (recentFailures >= FailedSignInThreshold)
            {
                var from = systemEvent.RemoteAddress ?? systemEvent.Subject ?? "unknown";
                await Queue("FailedSignIns", AlertSeverity.Medium, $"{recentFailures} failed sign-ins in 10 minutes ({from})",
                    $"There were {recentFailures} failed sign-in attempts in the last 10 minutes, the latest for {systemEvent.Subject} from {systemEvent.RemoteAddress ?? "this computer"}.",
                    from, programPath, systemEvent);
            }
        }

        if (systemEvent is { Channel: "System", EventId: 7031 or 7034 } && systemEvent.Subject != null && !disabledRules.Contains("ServiceCrashLoop"))
        {
            var crashes = await SystemEvent.CountSince(dataContext, 7031, DateTime.UtcNow.AddHours(-1), systemEvent.Subject)
                + await SystemEvent.CountSince(dataContext, 7034, DateTime.UtcNow.AddHours(-1), systemEvent.Subject);
            if (crashes >= ServiceCrashThreshold)
            {
                await Queue("ServiceCrashLoop", AlertSeverity.Low, $"The {systemEvent.Subject} service keeps crashing",
                    $"The {systemEvent.Subject} service stopped unexpectedly {crashes} times in the last hour.", systemEvent.Subject, programPath, systemEvent);
            }
        }
    }

    private async Task Queue(string rule, AlertSeverity severity, string title, string description, string? subject, string? programPath, SystemEvent systemEvent)
    {
        var details = new { systemEvent.Channel, systemEvent.EventId, systemEvent.Provider, systemEvent.Subject, systemEvent.RemoteAddress, systemEvent.ProgramPath };
        await SensorRuntime.AlertQueue.Writer.WriteAsync(HostAlerts.Create(rule, severity, title, description, subject, programPath, systemEvent.OccurredAt, details));
    }
}

/// <summary>
/// Alerts about this computer itself, from its event logs and service list.
/// </summary>
public static class HostAlerts
{
    public static Alert Create(string rule, AlertSeverity severity, string title, string description, string? subject, string? programPath, DateTime occurredAt, object details)
    {
        return new Alert
        {
            RuleName = rule,
            Severity = severity,
            Status = AlertStatus.Open,
            Scope = AlertScope.Host,
            Title = Truncate(title, 256),
            Description = Truncate(description, 2000),
            SourceIp = string.Empty,
            Subject = subject == null ? null : Truncate(subject, 512),
            ProcessPath = programPath != null && Path.IsPathRooted(programPath) ? Truncate(programPath, 1024) : null,
            Details = JsonSerializer.Serialize(details),
            CreatedAt = occurredAt,
            LastSeenAt = occurredAt
        };
    }

    private static string Truncate(string text, int maximumLength)
    {
        return text.Length <= maximumLength ? text : text[..(maximumLength - 1)] + "…";
    }
}

/// <summary>
/// Ends programs that were blocked from running but started anyway, as soon as their start is reported.
/// </summary>
public class ExecutionGuardWorker : BackgroundService
{
    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<ExecutionGuardWorker> logger;

    public ExecutionGuardWorker(SensorRuntime sensorRuntime, ILogger<ExecutionGuardWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await sensorRuntime.WaitUntilReady(stoppingToken);
        try
        {
            await foreach (var (processId, imagePath) in ExecutionGuard.PendingKills.Reader.ReadAllAsync(stoppingToken))
            {
                if (ExecutionGuard.End(processId, imagePath))
                    logger.LogWarning("Stopped blocked program {Path} on launch (process {ProcessId})", imagePath, processId);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }
}
