using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// The whole computer's processor and memory use for one minute.
/// </summary>
[Table("system_resource_minutes")]
[Index(nameof(BucketStart), IsUnique = true)]
public class SystemResourceMinute : Repository<SystemResourceMinute>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("cpu_percent")]
    public double CpuPercent { get; set; }

    [Column("memory_used_bytes")]
    public long MemoryUsedBytes { get; set; }

    [Column("memory_total_bytes")]
    public long MemoryTotalBytes { get; set; }

    [Column("process_count")]
    public int ProcessCount { get; set; }

    public static async Task<List<SystemResourcePoint>> GetTimeline(DataContext dataContext, long sinceUnixSeconds, int stepSeconds)
    {
        return await Query(dataContext)
            .Where(minute => minute.BucketStart >= sinceUnixSeconds)
            .GroupBy(minute => minute.BucketStart / stepSeconds)
            .Select(group => new SystemResourcePoint
            {
                BucketStart = group.Key * stepSeconds,
                CpuPercent = group.Average(minute => minute.CpuPercent),
                MemoryUsedBytes = (long)group.Average(minute => minute.MemoryUsedBytes)
            })
            .OrderBy(point => point.BucketStart)
            .ToListAsync();
    }

    public static async Task<SystemResourceMinute?> GetLatest(DataContext dataContext)
    {
        return await Query(dataContext).OrderByDescending(minute => minute.BucketStart).FirstOrDefaultAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, minute => minute.BucketStart < cutoffUnixSeconds);
    }
}

public class SystemResourcePoint
{
    public long BucketStart { get; set; }
    public double CpuPercent { get; set; }
    public long MemoryUsedBytes { get; set; }
}

/// <summary>
/// One program's processor and memory use over five minutes. Only the heaviest programs are kept for each
/// bucket, so the table stays small enough for SQLite on a busy machine.
/// </summary>
[Table("process_resource_samples")]
[Index(nameof(BucketStart), nameof(ProcessImageId), IsUnique = true)]
[Index(nameof(ProcessImageId), nameof(BucketStart))]
public class ProcessResourceSample : Repository<ProcessResourceSample>
{
    public const int BucketSeconds = 300;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("process_image_id")]
    public long ProcessImageId { get; set; }

    [Column("cpu_percent_average")]
    public double CpuPercentAverage { get; set; }

    [Column("cpu_percent_peak")]
    public double CpuPercentPeak { get; set; }

    [Column("memory_bytes_peak")]
    public long MemoryBytesPeak { get; set; }

    [Column("private_bytes_peak")]
    public long PrivateBytesPeak { get; set; }

    [Column("instance_count")]
    public int InstanceCount { get; set; }

    /// <summary>
    /// Bytes the program read and wrote in the bucket, summed over its processes. Windows counts file, network and
    /// device I/O together here; "other" is I/O that is neither a read nor a write (device control, for example).
    /// </summary>
    [Column("read_bytes")]
    public long ReadBytes { get; set; }

    [Column("write_bytes")]
    public long WriteBytes { get; set; }

    [Column("other_bytes")]
    public long OtherBytes { get; set; }

    public static async Task<Dictionary<long, ProcessResourceUsage>> GetUsage(DataContext dataContext, long sinceUnixSeconds)
    {
        return await Query(dataContext)
            .Where(sample => sample.BucketStart >= sinceUnixSeconds)
            .GroupBy(sample => sample.ProcessImageId)
            .Select(group => new ProcessResourceUsage
            {
                ProcessImageId = group.Key,
                CpuPercentAverage = group.Average(sample => sample.CpuPercentAverage),
                CpuPercentPeak = group.Max(sample => sample.CpuPercentPeak),
                MemoryBytesPeak = group.Max(sample => sample.MemoryBytesPeak)
            })
            .ToDictionaryAsync(usage => usage.ProcessImageId);
    }

    public static async Task<List<ProcessResourceSample>> GetForProgram(DataContext dataContext, long processImageId, long sinceUnixSeconds)
    {
        return await Query(dataContext)
            .Where(sample => sample.ProcessImageId == processImageId && sample.BucketStart >= sinceUnixSeconds)
            .OrderBy(sample => sample.BucketStart)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, sample => sample.BucketStart < cutoffUnixSeconds);
    }
}

public class ProcessResourceUsage
{
    public long ProcessImageId { get; set; }
    public double CpuPercentAverage { get; set; }
    public double CpuPercentPeak { get; set; }
    public long MemoryBytesPeak { get; set; }
}

/// <summary>
/// What is running right now, written by the sensor once a minute as a single document so the console can show
/// every process without storing hundreds of rows a minute.
/// </summary>
public class RunningProgramSnapshot
{
    public const string StateKey = "running_programs";

    public DateTime TakenAt { get; set; }
    public List<RunningProgram> Programs { get; set; } = [];

    public static async Task<RunningProgramSnapshot> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new RunningProgramSnapshot();

        try
        {
            return JsonSerializer.Deserialize<RunningProgramSnapshot>(json) ?? new RunningProgramSnapshot();
        }
        catch (JsonException)
        {
            return new RunningProgramSnapshot();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }
}

public class RunningProgram
{
    public string ImagePath { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public long? ProcessImageId { get; set; }
    public int InstanceCount { get; set; }
    public double CpuPercent { get; set; }
    public long MemoryBytes { get; set; }
    public long PrivateBytes { get; set; }
    public long ReadBytesPerSecond { get; set; }
    public long WriteBytesPerSecond { get; set; }
    public List<int> ProcessIds { get; set; } = [];
}

/// <summary>
/// A Windows service as last seen by the sensor. Services first seen after the baseline are flagged as new.
/// </summary>
[Table("system_services")]
[Index(nameof(ServiceName), IsUnique = true)]
public class SystemService : Repository<SystemService>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("service_name")]
    [MaxLength(256)]
    public string ServiceName { get; set; } = string.Empty;

    [Column("display_name")]
    [MaxLength(512)]
    public string DisplayName { get; set; } = string.Empty;

    [Column("state")]
    [MaxLength(32)]
    public string State { get; set; } = string.Empty;

    [Column("start_mode")]
    [MaxLength(32)]
    public string StartMode { get; set; } = string.Empty;

    [Column("binary_path")]
    [MaxLength(2048)]
    public string? BinaryPath { get; set; }

    [Column("account")]
    [MaxLength(256)]
    public string? Account { get; set; }

    [Column("is_baseline")]
    public bool IsBaseline { get; set; }

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [Column("last_changed_at")]
    public DateTime LastChangedAt { get; set; }

    [Column("removed_at")]
    public DateTime? RemovedAt { get; set; }

    [NotMapped]
    public bool IsRunning => State == "Running";

    [NotMapped]
    public bool IsNew => !IsBaseline && FirstSeenAt >= DateTime.UtcNow.AddDays(-7);

    /// <summary>
    /// Brings the table in line with the services that exist now. The first snapshot ever taken is the baseline.
    /// Returns the services that appeared since the last snapshot (none on the baseline).
    /// </summary>
    public static async Task<List<SystemService>> Synchronize(DataContext dataContext, List<SystemService> currentServices, DateTime seenAt)
    {
        var knownServices = await dataContext.SystemServices.ToListAsync();
        var isBaseline = knownServices.Count == 0;
        var knownByName = knownServices.ToDictionary(service => service.ServiceName, StringComparer.OrdinalIgnoreCase);
        var appeared = new List<SystemService>();

        foreach (var currentService in currentServices)
        {
            if (!knownByName.TryGetValue(currentService.ServiceName, out var knownService))
            {
                currentService.IsBaseline = isBaseline;
                currentService.FirstSeenAt = seenAt;
                currentService.LastSeenAt = seenAt;
                currentService.LastChangedAt = seenAt;
                dataContext.SystemServices.Add(currentService);
                if (!isBaseline)
                    appeared.Add(currentService);
                continue;
            }

            var changed = knownService.State != currentService.State
                || knownService.StartMode != currentService.StartMode
                || knownService.BinaryPath != currentService.BinaryPath
                || knownService.Account != currentService.Account
                || knownService.RemovedAt != null;
            knownService.DisplayName = currentService.DisplayName;
            knownService.State = currentService.State;
            knownService.StartMode = currentService.StartMode;
            knownService.BinaryPath = currentService.BinaryPath;
            knownService.Account = currentService.Account;
            knownService.LastSeenAt = seenAt;
            knownService.RemovedAt = null;
            if (changed)
                knownService.LastChangedAt = seenAt;
        }

        var currentNames = currentServices.Select(service => service.ServiceName).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var removedService in knownServices.Where(service => service.RemovedAt == null && !currentNames.Contains(service.ServiceName)))
        {
            removedService.RemovedAt = seenAt;
            removedService.LastChangedAt = seenAt;
        }

        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
        return appeared;
    }

    public static async Task<List<SystemService>> GetCurrent(DataContext dataContext)
    {
        return await Query(dataContext)
            .Where(service => service.RemovedAt == null)
            .OrderBy(service => service.DisplayName)
            .ToListAsync();
    }
}

public enum SystemEventCategory
{
    Security = 1,
    Defender = 2,
    Service = 3,
    Account = 4,
    ScheduledTask = 5,
    Stability = 6,
    Disk = 7,
    AppCrash = 8
}

/// <summary>
/// A notable entry from a Windows event log. Failed sign-ins are stored as one row per account, address and minute
/// with a count, never one row per event, so an attack cannot flood the table.
/// </summary>
[Table("system_events")]
[Index(nameof(OccurredAt))]
[Index(nameof(Channel), nameof(EventId), nameof(OccurredAt))]
public class SystemEvent : Repository<SystemEvent>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("occurred_at")]
    public DateTime OccurredAt { get; set; }

    [Column("channel")]
    [MaxLength(128)]
    public string Channel { get; set; } = string.Empty;

    [Column("event_id")]
    public int EventId { get; set; }

    [Column("level")]
    public int Level { get; set; }

    [Column("provider")]
    [MaxLength(256)]
    public string Provider { get; set; } = string.Empty;

    [Column("category")]
    public SystemEventCategory Category { get; set; }

    /// <summary>
    /// What the event is about: a service, task, account or file name. Attacker-controlled text.
    /// </summary>
    [Column("subject")]
    [MaxLength(512)]
    public string? Subject { get; set; }

    [Column("program_path")]
    [MaxLength(2048)]
    public string? ProgramPath { get; set; }

    [Column("remote_address")]
    [MaxLength(64)]
    public string? RemoteAddress { get; set; }

    [Column("summary")]
    [MaxLength(2048)]
    public string Summary { get; set; } = string.Empty;

    [Column("occurrence_count")]
    public int OccurrenceCount { get; set; } = 1;

    public static async Task<List<SystemEvent>> GetRecent(DataContext dataContext, DateTime since, int count, bool includeAppCrashes = true)
    {
        var query = Query(dataContext).Where(systemEvent => systemEvent.OccurredAt >= since);
        if (!includeAppCrashes)
            query = query.Where(systemEvent => systemEvent.Category != SystemEventCategory.AppCrash);

        return await query.OrderByDescending(systemEvent => systemEvent.OccurredAt).Take(count).ToListAsync();
    }

    public static async Task<List<SystemEvent>> GetAround(DataContext dataContext, DateTime center, TimeSpan window, int count)
    {
        var from = center - window;
        var to = center + window;
        return await Query(dataContext)
            .Where(systemEvent => systemEvent.OccurredAt >= from && systemEvent.OccurredAt <= to)
            .OrderByDescending(systemEvent => systemEvent.OccurredAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> CountSince(DataContext dataContext, int eventId, DateTime since, string? subject = null, string? remoteAddress = null)
    {
        var query = Query(dataContext).Where(systemEvent => systemEvent.EventId == eventId && systemEvent.OccurredAt >= since);
        if (subject != null)
            query = query.Where(systemEvent => systemEvent.Subject == subject);
        if (remoteAddress != null)
            query = query.Where(systemEvent => systemEvent.RemoteAddress == remoteAddress);

        return await query.SumAsync(systemEvent => systemEvent.OccurrenceCount);
    }

    /// <summary>
    /// Adds failed sign-ins to the counter row for the same account, address and minute.
    /// </summary>
    public static async Task AddFailedSignIns(DataContext dataContext, SystemEvent failedSignIn)
    {
        var minuteStart = new DateTime(failedSignIn.OccurredAt.Ticks - failedSignIn.OccurredAt.Ticks % TimeSpan.TicksPerMinute, DateTimeKind.Utc);
        var minuteEnd = minuteStart.AddMinutes(1);
        var existing = await dataContext.SystemEvents.FirstOrDefaultAsync(systemEvent => systemEvent.EventId == failedSignIn.EventId
            && systemEvent.Channel == failedSignIn.Channel
            && systemEvent.Subject == failedSignIn.Subject
            && systemEvent.RemoteAddress == failedSignIn.RemoteAddress
            && systemEvent.OccurredAt >= minuteStart && systemEvent.OccurredAt < minuteEnd);

        if (existing == null)
        {
            failedSignIn.OccurredAt = minuteStart;
            dataContext.SystemEvents.Add(failedSignIn);
        }
        else
        {
            existing.OccurrenceCount += failedSignIn.OccurrenceCount;
        }

        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, systemEvent => systemEvent.OccurredAt < cutoff);
    }
}

/// <summary>
/// Whether the logs ScoutWall relies on are switched on, written by the sensor so the console can explain gaps.
/// </summary>
public class EventLogHealth
{
    public const string StateKey = "event_log_health";

    public DateTime CheckedAt { get; set; }
    public bool FailedSignInAuditingOn { get; set; } = true;
    public bool ScheduledTaskLogOn { get; set; } = true;
    public List<string> UnreadableChannels { get; set; } = [];

    public static async Task<EventLogHealth> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new EventLogHealth();

        try
        {
            return JsonSerializer.Deserialize<EventLogHealth>(json) ?? new EventLogHealth();
        }
        catch (JsonException)
        {
            return new EventLogHealth();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }
}

/// <summary>
/// Everything the System page shows.
/// </summary>
public class SystemReport
{
    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public SystemResourceMinute? Latest { get; set; }
    public List<SystemResourcePoint> Timeline { get; set; } = [];
    public RunningProgramSnapshot Snapshot { get; set; } = new();
    public Dictionary<long, ProcessResourceUsage> UsageByProgram { get; set; } = [];
    public List<SystemService> Services { get; set; } = [];
    public bool ShowAllServices { get; set; }
    public List<SystemEvent> Events { get; set; } = [];
    public EventLogHealth LogHealth { get; set; } = new();
    public Dictionary<long, string> FriendlyNames { get; set; } = [];
    public ResponseSettings Response { get; set; } = new();

    /// <summary>
    /// Everything ScoutWall currently blocks, disables or slows down, for the "Blocked" list.
    /// </summary>
    public List<ResponseAction> InForce { get; set; } = [];

    /// <summary>
    /// Why a running program can't be ended or blocked, or null when it can.
    /// </summary>
    public string? RefusalFor(RunningProgram program)
    {
        if (!Path.IsPathRooted(program.ImagePath))
            return "ScoutWall can't see where this program is installed.";

        return ProtectedPrograms.ReasonNotBlockable(program.ImagePath)
            ?? (Response.IsAllowlistedProgram(program.ImagePath) ? "On the never-block allowlist." : null);
    }

    public ScanStatus Scan { get; set; } = new();
    public List<ScanResult> ScanResults { get; set; } = [];

    /// <summary>
    /// Which actions a scan result can offer, each with whether it is the recommended one. Protected items offer none.
    /// </summary>
    public List<(ResponseActionType ActionType, string Label, bool Recommended)> ActionsFor(ScanResult scanResult)
    {
        var actions = new List<(ResponseActionType, string, bool)>();
        switch (scanResult.Kind)
        {
            case ScanItemKind.ScheduledTask:
                if (HostTargets.ReasonTaskNotActionable(scanResult.Target, deleting: false) == null)
                    actions.Add((ResponseActionType.DisableScheduledTask, "Disable", scanResult.Recommendation == ScanRecommendation.DisableTask));
                if (HostTargets.ReasonTaskNotActionable(scanResult.Target, deleting: true) == null)
                    actions.Add((ResponseActionType.DeleteScheduledTask, "Remove", scanResult.Recommendation == ScanRecommendation.RemoveTask));
                break;

            case ScanItemKind.Service:
                if (HostTargets.ReasonServiceNotActionable(scanResult.Target, scanResult.Command) == null)
                    actions.Add((ResponseActionType.StopService, "Stop and disable", scanResult.Recommendation == ScanRecommendation.StopService));
                break;

            default:
                var path = scanResult.ProgramPath;
                if (path != null && Path.IsPathRooted(path) && ProtectedPrograms.ReasonNotBlockable(path) == null && !Response.IsAllowlistedProgram(path))
                {
                    if (ProtectedPrograms.ReasonNotBlockableFromRunning(path) == null)
                        actions.Add((ResponseActionType.BlockExecution, "Block from running", scanResult.Recommendation == ScanRecommendation.BlockFromRunning));

                    actions.Add((ResponseActionType.BlockProgram, "Block internet", scanResult.Recommendation == ScanRecommendation.BlockInternet));
                }
                break;
        }

        return actions;
    }

    /// <summary>
    /// What an action on a scan result targets: the program path for program actions, otherwise the task or service.
    /// </summary>
    public static string TargetFor(ScanResult scanResult, ResponseActionType actionType)
    {
        return actionType is ResponseActionType.BlockExecution or ResponseActionType.BlockProgram ? scanResult.ProgramPath ?? scanResult.Target : scanResult.Target;
    }

    public static bool CanBlockFromRunning(RunningProgram program)
    {
        return ProtectedPrograms.ReasonNotBlockableFromRunning(program.ImagePath) == null;
    }

    public ResponseAction? BlockFor(RunningProgram program)
    {
        return InForce.FirstOrDefault(action => action.ActionType == ResponseActionType.BlockExecution
            && string.Equals(action.Target, program.ImagePath, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Blocks and disables a person would want to find again, newest first. Automatic network blocks from alerts
    /// are listed on the Blocks page instead.
    /// </summary>
    public IEnumerable<ResponseAction> BlockedItems => InForce.Where(action => action.IsHostAction
        || (action.ActionType is ResponseActionType.BlockProgram or ResponseActionType.ThrottleProgram or ResponseActionType.BlockAddress
            && action.CreatedBy != "sensor"));

    public string NameOf(RunningProgram program)
    {
        return program.ProcessImageId is long id && FriendlyNames.TryGetValue(id, out var friendlyName) ? friendlyName : program.Name;
    }

    public int RunningServiceCount => Services.Count(service => service.IsRunning);
    public int NewServiceCount => Services.Count(service => service.IsNew);
    public long MemoryTotalBytes => Latest?.MemoryTotalBytes ?? 0;

    public IEnumerable<SystemService> VisibleServices => ShowAllServices
        ? Services
        : Services.Where(service => service.IsRunning || service.IsNew);

    public static async Task<SystemReport> Build(DataContext dataContext, TimeRange range, bool showAllServices)
    {
        var snapshot = await RunningProgramSnapshot.Load(dataContext);
        var knownIds = snapshot.Programs.Where(program => program.ProcessImageId.HasValue).Select(program => program.ProcessImageId!.Value).ToList();
        var friendlyNames = (await ProcessImage.GetAll(dataContext, image => knownIds.Contains(image.Id)))
            .ToDictionary(image => image.Id, image => image.DisplayName);

        return new SystemReport
        {
            FriendlyNames = friendlyNames,
            Scan = await ScanStatus.Load(dataContext),
            ScanResults = await ScanResult.GetLatest(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            InForce = await ResponseAction.GetInForce(dataContext),
            Range = range,
            Latest = await SystemResourceMinute.GetLatest(dataContext),
            Timeline = await SystemResourceMinute.GetTimeline(dataContext, range.SinceUnixSeconds, range.StepSeconds),
            Snapshot = snapshot,
            UsageByProgram = await ProcessResourceSample.GetUsage(dataContext, range.SinceUnixSeconds),
            Services = await SystemService.GetCurrent(dataContext),
            ShowAllServices = showAllServices,
            Events = await SystemEvent.GetRecent(dataContext, DateTime.UtcNow.Subtract(range.Duration), 100),
            LogHealth = await EventLogHealth.Load(dataContext)
        };
    }
}
