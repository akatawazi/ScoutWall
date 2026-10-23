using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Decryption;
using ScoutWall.Sensor.Enrichment;
using ScoutWall.Sensor.Network;
using ScoutWall.Sensor.Notifications;
using ScoutWall.Sensor.Presence;
using ScoutWall.Sensor.Response;
using ScoutWall.Sensor.Capture;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Keeps the idle state current and records presence history. Runs often so idle-only blocks lift within seconds
/// of the user returning.
/// </summary>
public class PresenceWorker : SensorWorker
{
    // A longer silence means the sensor stopped or the computer slept; the open period ends where it was last seen.
    private static readonly TimeSpan ResumeGap = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan ConfirmInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan RelabelRepeatDelay = TimeSpan.FromSeconds(90);

    private DateTime? lastTickAt;
    private (long SinceUnixSeconds, DateTime RunAt)? pendingRelabel;

    public PresenceWorker(SensorRuntime sensorRuntime, ILogger<PresenceWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(2);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        await using var dataContext = SensorRuntime.CreateDataContext();
        var idleThreshold = TimeSpan.FromMinutes(SensorRuntime.Configuration.Response.IdleMinutes);
        var idleState = await IdleDetector.Detect(dataContext, idleThreshold);

        if (idleState.IsIdle != SensorRuntime.Idle.IsIdle)
            Logger.LogInformation("User presence changed: idle={IsIdle} ({Source})", idleState.IsIdle, idleState.Source);

        SensorRuntime.Idle = idleState;
        await RecordHistory(dataContext, idleState);
    }

    private async Task RecordHistory(DataContext dataContext, IdleState idleState)
    {
        var now = DateTime.UtcNow;
        var state = idleState.IsIdle switch { true => PresenceState.Away, false => PresenceState.Here, null => PresenceState.Unknown };
        var resumed = lastTickAt == null || now - lastTickAt > ResumeGap;
        lastTickAt = now;

        var openPeriod = await PresencePeriod.GetOpen(dataContext);
        if (openPeriod != null && resumed)
        {
            await PresencePeriod.Close(dataContext, openPeriod.Id, openPeriod.ConfirmedAt);
            openPeriod = null;
        }

        if (openPeriod == null || openPeriod.State != state)
        {
            // Away really began at the last input, a whole idle threshold before it was noticed. Only backdate
            // within a period the sensor watched, never into time it was stopped or the computer slept.
            var startedAt = now;
            if (state == PresenceState.Away && openPeriod != null && idleState.IdleFor is { } idleFor)
                startedAt = now - idleFor < openPeriod.StartedAt ? openPeriod.StartedAt : now - idleFor;

            if (openPeriod != null)
                await PresencePeriod.Close(dataContext, openPeriod.Id, startedAt);

            await PresencePeriod.Open(dataContext, state, idleState.Source, startedAt, now);
            Logger.LogInformation("Presence period started: {State} from {StartedAt:u} ({Source})", state, startedAt, idleState.Source);

            if (state == PresenceState.Away && startedAt < now)
            {
                var sinceUnixSeconds = new DateTimeOffset(startedAt).ToUnixTimeSeconds();
                await Relabel(dataContext, sinceUnixSeconds);
                // Traffic still buffered for the current minute is written as "here" a little later; catch it too.
                pendingRelabel = (sinceUnixSeconds, now + RelabelRepeatDelay);
            }
            else
            {
                pendingRelabel = null;
            }
        }
        else if (now - openPeriod.ConfirmedAt >= ConfirmInterval)
        {
            await PresencePeriod.Confirm(dataContext, openPeriod.Id, now, idleState.Source);
        }

        if (pendingRelabel is { } relabel && now >= relabel.RunAt)
        {
            pendingRelabel = null;
            if (state == PresenceState.Away)
                await Relabel(dataContext, relabel.SinceUnixSeconds);
        }
    }

    private async Task Relabel(DataContext dataContext, long sinceUnixSeconds)
    {
        var moved = await ProcessTrafficMinute.RelabelAsAway(dataContext, sinceUnixSeconds);
        if (moved > 0)
            Logger.LogInformation("Moved {Count} traffic minutes from before away was noticed into away", moved);
    }
}

/// <summary>
/// Expires actions, applies the idle lockdown and reconciles the firewall with the desired state.
/// </summary>
public class ResponseWorker : SensorWorker
{
    private readonly ResponseReconciler responseReconciler;
    private readonly HostActionReconciler hostActionReconciler;

    public ResponseWorker(SensorRuntime sensorRuntime, ILogger<ResponseWorker> logger) : base(sensorRuntime, logger)
    {
        responseReconciler = new ResponseReconciler(sensorRuntime, logger);
        hostActionReconciler = new HostActionReconciler(logger);
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(3);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        await using var dataContext = SensorRuntime.CreateDataContext();
        await ResponseAction.ExpireDue(dataContext, DateTime.UtcNow);
        var deferredCount = await ResponsePlanner.PlanDeferred(dataContext, SensorRuntime);
        if (deferredCount > 0)
            Logger.LogWarning("Planned {Count} responses for alerts the analyst did not clear", deferredCount);
        await ApplyIdlePolicy(dataContext);
        await responseReconciler.Reconcile(dataContext);

        // Task and service actions act on this computer, so they apply whichever firewall is chosen.
        await hostActionReconciler.Reconcile(dataContext);
    }

    private async Task ApplyIdlePolicy(ScoutWall.Data.DataContext dataContext)
    {
        var responseSettings = SensorRuntime.Configuration.Response;
        var shouldLockDown = responseSettings.Mode == ResponseMode.BlockWhenIdle && SensorRuntime.Idle.IsIdle == true;

        if (!shouldLockDown)
        {
            var endedCount = await ResponseAction.EndIdleActions(dataContext, DateTime.UtcNow);
            if (endedCount > 0)
                Logger.LogInformation("User is back; lifted {Count} idle-only actions", endedCount);
            return;
        }

        if (responseSettings.IdleScope != IdleBlockScope.AllInternet)
            return;

        var idleLockdown = new ResponseAction
        {
            ActionType = ResponseActionType.IdleLockdown,
            Target = "Public internet",
            BlockOutbound = true,
            Reason = $"Nobody has used the computer for {SensorRuntime.Idle.IdleFor?.TotalMinutes:0} minutes ({SensorRuntime.Idle.Source})",
            EndsWhenUserReturns = true,
            CreatedBy = ResponsePlanner.SensorUser,
            ExpiresAt = DateTime.UtcNow.AddHours(24)
        };
        await ResponseAction.Request(dataContext, idleLockdown, responseSettings.DryRun);
    }
}

/// <summary>
/// Sends queued email and webhook notifications with retry and backoff.
/// </summary>
public class NotificationWorker : SensorWorker
{
    public NotificationWorker(SensorRuntime sensorRuntime, ILogger<NotificationWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(10);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        var notificationSettings = SensorRuntime.Configuration.Notification;
        await Deliver(NotificationChannel.Email, delivery => NotificationSender.SendEmail(notificationSettings, delivery, cancellationToken));
        await Deliver(NotificationChannel.Webhook, delivery => NotificationSender.SendWebhook(notificationSettings, delivery, cancellationToken));
    }

    private async Task Deliver(NotificationChannel notificationChannel, Func<NotificationDelivery, Task> send)
    {
        await using var dataContext = SensorRuntime.CreateDataContext();
        var dueDeliveries = await NotificationDelivery.GetDue(dataContext, notificationChannel, 20);

        foreach (var notificationDelivery in dueDeliveries)
        {
            try
            {
                await send(notificationDelivery);
                await NotificationDelivery.MarkSent(dataContext, notificationDelivery.Id);
            }
            catch (Exception exception)
            {
                Logger.LogWarning("{Channel} notification {Id} failed: {Message}", notificationChannel, notificationDelivery.Id, exception.Message);
                await notificationDelivery.MarkFailed(dataContext, exception.Message);
            }
        }
    }
}

/// <summary>
/// Geolocates newly seen addresses and refreshes threat blocklists.
/// </summary>
public class EnrichmentWorker : SensorWorker
{
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly TimeSpan LookupLifetime = TimeSpan.FromDays(30);

    private readonly GeoIpResolver geoIpResolver = new();
    private readonly Dictionary<string, string> feedContents = [];
    private DateTime lastBlocklistRefresh = DateTime.MinValue;
    private string lastBlocklistSettings = string.Empty;

    public EnrichmentWorker(SensorRuntime sensorRuntime, ILogger<EnrichmentWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(15);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        await RefreshBlocklist(cancellationToken);
        await LookUpAddresses(cancellationToken);
    }

    private async Task LookUpAddresses(CancellationToken cancellationToken)
    {
        var integrationSettings = SensorRuntime.Configuration.Integration;
        if (!geoIpResolver.HasSource(integrationSettings))
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        var pendingProfiles = await IpAddressProfile.GetPendingLookups(dataContext, 100, DateTime.UtcNow.Subtract(LookupLifetime));
        if (pendingProfiles.Count == 0)
            return;

        var ipAddresses = pendingProfiles.Select(profile => profile.IpAddress).ToList();
        var lookedUpProfiles = await geoIpResolver.Lookup(integrationSettings, ipAddresses, cancellationToken);
        foreach (var lookedUpProfile in lookedUpProfiles)
            await IpAddressProfile.SaveLookup(dataContext, lookedUpProfile);

        Logger.LogDebug("Geolocated {Count} addresses", lookedUpProfiles.Count);
    }

    private async Task RefreshBlocklist(CancellationToken cancellationToken)
    {
        var integrationSettings = SensorRuntime.Configuration.Integration;
        var blocklistSettings = string.Join("|", integrationSettings.BlocklistUrls.Concat(integrationSettings.StaticBlocklist));
        var refreshDue = DateTime.UtcNow - lastBlocklistRefresh >= TimeSpan.FromHours(integrationSettings.BlocklistRefreshHours);
        if (!refreshDue && blocklistSettings == lastBlocklistSettings)
            return;

        foreach (var feedUrl in integrationSettings.BlocklistUrls)
            await DownloadFeed(feedUrl, cancellationToken);

        var feeds = integrationSettings.BlocklistUrls
            .Where(feedContents.ContainsKey)
            .Select(feedUrl => (new Uri(feedUrl).Host, feedContents[feedUrl]))
            .Append(("Static list", string.Join('\n', integrationSettings.StaticBlocklist)));

        SensorRuntime.Blocklist = Blocklist.Build(feeds);
        lastBlocklistRefresh = DateTime.UtcNow;
        lastBlocklistSettings = blocklistSettings;
        Logger.LogInformation("Blocklist loaded with {Count} entries", SensorRuntime.Blocklist.Count);
    }

    private async Task DownloadFeed(string feedUrl, CancellationToken cancellationToken)
    {
        try
        {
            feedContents[feedUrl] = await HttpClient.GetStringAsync(feedUrl, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or UriFormatException)
        {
            Logger.LogWarning("Could not download blocklist {Url}: {Message}", feedUrl, exception.Message);
        }
    }
}

/// <summary>
/// Runs finished packet files through tshark with the TLS key log to recover HTTP request metadata.
/// </summary>
public class DecryptionWorker : SensorWorker
{
    private const int FilesPerPass = 3;
    private string? lastWarning;

    public DecryptionWorker(SensorRuntime sensorRuntime, ILogger<DecryptionWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromMinutes(1);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        var integrationSettings = SensorRuntime.Configuration.Integration;
        if (!integrationSettings.DecryptionEnabled || !Prerequisites(integrationSettings))
            return;

        foreach (var packetFilePath in FindFinishedFiles().Take(FilesPerPass))
        {
            var decryptedRequests = await TsharkDecryptor.Decrypt(integrationSettings.TsharkPath!, integrationSettings.KeyLogFilePath!, packetFilePath, cancellationToken);
            await using var dataContext = SensorRuntime.CreateDataContext();
            await DecryptedRequest.InsertBatch(dataContext, decryptedRequests);
            await File.WriteAllTextAsync(packetFilePath + PacketFileWriter.ProcessedMarkerExtension, DateTime.UtcNow.ToString("O"), cancellationToken);
            Logger.LogInformation("Decrypted {Count} requests from {File}", decryptedRequests.Count, Path.GetFileName(packetFilePath));
        }
    }

    private bool Prerequisites(IntegrationSettings integrationSettings)
    {
        string? warning = null;
        if (string.IsNullOrWhiteSpace(integrationSettings.TsharkPath) || !TrustedPaths.IsTrustedTshark(integrationSettings.TsharkPath))
            warning = "Decryption is enabled but the tshark path is not tshark.exe under Program Files; refusing to run it.";
        else if (!File.Exists(integrationSettings.TsharkPath))
            warning = "Decryption is enabled but tshark was not found. Install Wireshark or fix the tshark path in Settings.";
        else if (string.IsNullOrWhiteSpace(integrationSettings.KeyLogFilePath) || !File.Exists(integrationSettings.KeyLogFilePath))
            warning = "Decryption is enabled but the TLS key log file does not exist yet. Set SSLKEYLOGFILE for the programs to inspect.";

        if (warning != null && warning != lastWarning)
            Logger.LogWarning("{Warning}", warning);

        lastWarning = warning;
        return warning == null;
    }

    /// <summary>
    /// Every packet file except the newest of each capture, which is still being written.
    /// </summary>
    private IEnumerable<string> FindFinishedFiles()
    {
        if (!Directory.Exists(SensorRuntime.PacketFileDirectory))
            return [];

        return new DirectoryInfo(SensorRuntime.PacketFileDirectory)
            .GetFiles("*" + PacketFileWriter.FileExtension)
            .GroupBy(fileInfo => fileInfo.Name.Split('-')[0] + "-" + fileInfo.Name.Split('-')[1])
            .SelectMany(group => group.OrderByDescending(fileInfo => fileInfo.Name).Skip(1))
            .Where(fileInfo => !File.Exists(fileInfo.FullName + PacketFileWriter.ProcessedMarkerExtension))
            .OrderBy(fileInfo => fileInfo.Name)
            .Select(fileInfo => fileInfo.FullName);
    }
}

/// <summary>
/// Deletes data past its retention period.
/// </summary>
public class MaintenanceWorker : SensorWorker
{
    public MaintenanceWorker(SensorRuntime sensorRuntime, ILogger<MaintenanceWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromHours(1);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        var retentionSettings = SensorRuntime.Configuration.Retention;
        var now = DateTime.UtcNow;
        var nowUnixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const long secondsPerDay = 86_400;

        await using var dataContext = SensorRuntime.CreateDataContext();
        var deletedCount = 0;
        deletedCount += await TrafficMinute.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.MinuteTrafficDays * secondsPerDay);
        deletedCount += await TrafficHour.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.HourTrafficDays * secondsPerDay);
        deletedCount += await ProcessTrafficMinute.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.ProcessTrafficDays * secondsPerDay);
        deletedCount += await PresencePeriod.DeleteBefore(dataContext, now.AddDays(-retentionSettings.ProcessTrafficDays));
        deletedCount += await Alert.DeleteResolvedBefore(dataContext, now.AddDays(-retentionSettings.ResolvedAlertDays));
        deletedCount += await DnsRecord.DeleteBefore(dataContext, now.AddDays(-retentionSettings.DnsRecordDays));
        deletedCount += await TlsSession.DeleteBefore(dataContext, now.AddDays(-retentionSettings.TlsSessionDays));
        deletedCount += await DecryptedRequest.DeleteBefore(dataContext, now.AddDays(-retentionSettings.DecryptedRequestDays));
        deletedCount += await AnalystAssessment.DeleteBefore(dataContext, now.AddDays(-retentionSettings.ResolvedAlertDays));
        deletedCount += await FlowVerdict.DeleteBefore(dataContext, now.AddDays(-retentionSettings.FlowVerdictDays));
        deletedCount += await AuditEntry.DeleteBefore(dataContext, now.AddDays(-retentionSettings.AuditDays));
        deletedCount += await NotificationDelivery.DeleteBefore(dataContext, now.AddDays(-30));
        deletedCount += await SystemResourceMinute.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.SystemResourceDays * secondsPerDay);
        deletedCount += await ProcessResourceSample.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.SystemResourceDays * secondsPerDay);
        deletedCount += await SystemEvent.DeleteBefore(dataContext, now.AddDays(-retentionSettings.SystemEventDays));
        deletedCount += await FileChange.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.FileChangeDays * secondsPerDay);
        deletedCount += await DiskIoMinute.DeleteBefore(dataContext, nowUnixSeconds - retentionSettings.DiskActivityDays * secondsPerDay);
        deletedCount += await ScannerBlock.DeleteExpired(dataContext);

        if (deletedCount > 0)
            Logger.LogInformation("Retention removed {Count} rows", deletedCount);
    }
}
