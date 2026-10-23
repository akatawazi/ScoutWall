using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum HomeStatus
{
    NotWatching = 0,
    AllGood = 1,
    NeedsAttention = 2,
    Danger = 3
}

public record AppUsage(long ProcessImageId, string Name, string? Publisher, long BytesSent, long BytesReceived, bool IsNew)
{
    public long TotalBytes => BytesSent + BytesReceived;
}

/// <summary>
/// The home page for people who are not network experts: one status, what needs them, what happened today in
/// plain sentences, and which apps used the internet. The status and sentences are computed by fixed rules from
/// the database rather than written by a model, so they are instant, free and cannot be manipulated by traffic.
/// </summary>
public class HomeReport
{
    public HomeStatus Status { get; set; }
    public string Headline { get; set; } = string.Empty;
    public string Detail { get; set; } = string.Empty;
    public List<AnalystAssessment> Findings { get; set; } = [];
    public List<Alert> UnreviewedAlerts { get; set; } = [];
    public List<string> TodaySentences { get; set; } = [];
    public List<AppUsage> TopApps { get; set; } = [];
    public string HealthLine { get; set; } = string.Empty;
    public bool AssistantReady { get; set; }
    public LearningPeriod LearningPeriod { get; set; } = new(DateTime.UtcNow, 24);

    public static async Task<HomeReport> Build(DataContext dataContext)
    {
        var sensors = await SensorStatus.GetAll(dataContext);
        var analystSettings = await Setting.Load<AnalystSettings>(dataContext);
        var findings = await AnalystAssessment.GetOpenFindings(dataContext, 10);
        var since = DateTime.UtcNow.Date;
        var openAlerts = await Alert.GetAll(dataContext, alert => alert.Status == AlertStatus.Open && alert.LastSeenAt >= since.AddDays(-1));

        var homeReport = new HomeReport
        {
            Findings = findings,
            UnreviewedAlerts = analystSettings.IsReady ? [] : openAlerts.OrderByDescending(alert => alert.Severity).Take(5).ToList(),
            AssistantReady = analystSettings.IsReady,
            LearningPeriod = await LearningPeriod.Load(dataContext),
            TopApps = await GetTopApps(dataContext, since, 5),
            HealthLine = DescribeHealth(sensors)
        };

        homeReport.ApplyStatus(sensors, findings, openAlerts);
        homeReport.TodaySentences = await DescribeToday(dataContext, since, homeReport.TopApps, analystSettings);
        return homeReport;
    }

    /// <summary>
    /// Grey when ScoutWall cannot see traffic, red for anything judged malicious or a serious hard-rule alert,
    /// amber for findings that need a look or a degraded monitor, green otherwise.
    /// </summary>
    private void ApplyStatus(List<SensorStatus> sensors, List<AnalystAssessment> findings, List<Alert> openAlerts)
    {
        var sensor = sensors.OrderByDescending(item => item.LastHeartbeatAt).FirstOrDefault();
        var notWatchingReason = NotWatchingReason(sensor);
        if (notWatchingReason != null)
        {
            Set(HomeStatus.NotWatching, "ScoutWall isn't watching right now", notWatchingReason);
            return;
        }

        var maliciousCount = findings.Count(finding => finding.Verdict == AnalystVerdict.Malicious);
        var seriousAlerts = openAlerts.Count(alert => alert.IsHardRule && alert.Severity >= AlertSeverity.High && alert.AnalystAssessmentId == null);
        if (maliciousCount > 0 || seriousAlerts > 0)
        {
            Set(HomeStatus.Danger, "Something needs your attention now",
                maliciousCount > 0 ? $"The assistant found {Plural(maliciousCount, "likely threat")}. See below for what to do." : $"{Plural(seriousAlerts, "serious alert")} came in. See below.");
            return;
        }

        var attentionCount = findings.Count + (AssistantReady ? 0 : openAlerts.Count(alert => alert.Severity >= AlertSeverity.Medium));
        var isDegraded = sensor!.LastError != null && (sensor.LastError.Contains("administrator", StringComparison.OrdinalIgnoreCase) || sensor.LastError.Contains("Per-program", StringComparison.OrdinalIgnoreCase));
        if (attentionCount > 0)
        {
            Set(HomeStatus.NeedsAttention, $"{Plural(attentionCount, "thing")} to look at when you have a moment", "Nothing looks urgent.");
            return;
        }

        if (isDegraded)
        {
            Set(HomeStatus.NeedsAttention, "Your computer looks fine, but ScoutWall can only see part of the picture", "Run the ScoutWall monitor as administrator so it can tell which apps are using the internet.");
            return;
        }

        Set(HomeStatus.AllGood, "Your computer looks safe", "Nothing unusual has been found.");
    }

    private static string? NotWatchingReason(SensorStatus? sensor)
    {
        if (sensor == null)
            return "The ScoutWall monitor has never run on this computer. Install it with \"scoutwall install\" as administrator.";

        if (!sensor.IsOnline)
            return OperatingSystem.IsWindows()
                ? $"The ScoutWall monitor stopped reporting {Ago(sensor.LastHeartbeatAt)}. Restart the \"ScoutWall Sensor\" service."
                : $"The ScoutWall monitor stopped reporting {Ago(sensor.LastHeartbeatAt)}. Restart it: sudo systemctl restart scoutwall-sensor";

        if (sensor.LastError != null && sensor.LastError.Contains("libpcap", StringComparison.OrdinalIgnoreCase))
            return "ScoutWall needs libpcap to see network traffic. Install it with your package manager (for example: sudo apt install libpcap0.8).";

        return null;
    }

    private void Set(HomeStatus status, string headline, string detail)
    {
        Status = status;
        Headline = headline;
        Detail = detail;
    }

    private static string DescribeHealth(List<SensorStatus> sensors)
    {
        var sensor = sensors.OrderByDescending(item => item.LastHeartbeatAt).FirstOrDefault();
        if (sensor == null)
            return "Monitor not installed.";

        var interfaceCount = sensor.Interfaces.Split(',', StringSplitOptions.RemoveEmptyEntries).Length;
        var presence = sensor.IsUserIdle switch { true => "you're away", false => "you're here", _ => "can't tell if you're here" };
        return $"{(sensor.IsOnline ? "Watching" : "Not watching")} {Plural(Math.Max(interfaceCount, 1), "connection")} · last check {Ago(sensor.LastHeartbeatAt)} · {presence}";
    }

    private static async Task<List<AppUsage>> GetTopApps(DataContext dataContext, DateTime since, int count)
    {
        var sinceUnixSeconds = new DateTimeOffset(since).ToUnixTimeSeconds();
        var summaries = await ProcessTrafficMinute.GetSummaries(dataContext, sinceUnixSeconds, 50);
        return summaries
            .Where(summary => summary.ProcessImage != null && summary.ProcessImage.Name is not ("System" or "Idle" or "Unknown"))
            .OrderByDescending(summary => summary.BytesSent + summary.BytesReceived)
            .Take(count)
            .Select(summary => new AppUsage(summary.ProcessImageId, summary.Name, summary.ProcessImage!.Publisher ?? summary.ProcessImage.Company,
                summary.BytesSent, summary.BytesReceived, summary.ProcessImage.IsNew))
            .ToList();
    }

    private static async Task<List<string>> DescribeToday(DataContext dataContext, DateTime since, List<AppUsage> topApps, AnalystSettings analystSettings)
    {
        var sentences = new List<string>();
        var sinceUnixSeconds = new DateTimeOffset(since).ToUnixTimeSeconds();
        var totals = await TrafficRecord<TrafficMinute>.GetTotals(dataContext, sinceUnixSeconds);
        sentences.Add($"Today this computer downloaded {Bytes(totals.BytesIn)} and uploaded {Bytes(totals.BytesOut)}.");

        if (topApps.Count > 0)
            sentences.Add($"{topApps[0].Name} used the internet the most ({Bytes(topApps[0].TotalBytes)}).");

        var newApps = await dataContext.ProcessImages.AsNoTracking().Where(image => image.FirstSeenAt >= since).ToListAsync();
        var learningPeriod = await LearningPeriod.Load(dataContext);
        if (!learningPeriod.IsActive && newApps.Count > 0)
            sentences.Add($"New today: {string.Join(", ", newApps.Take(3).Select(image => image.DisplayName))}{(newApps.Count > 3 ? $" and {newApps.Count - 3} more" : string.Empty)} started using the internet.");

        var awayRecords = dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && record.Presence == PresenceState.Away);
        var awaySent = await awayRecords.SumAsync(record => record.BytesSent);
        var awayReceived = await awayRecords.SumAsync(record => record.BytesReceived);
        sentences.Add(awaySent > 1024 * 1024
            ? $"While you were away, {Bytes(awaySent)} was uploaded and {Bytes(awayReceived)} downloaded. The Data Flow page shows which programs did it."
            : "Nothing meaningful was uploaded while you were away.");

        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        var actionsToday = await ResponseAction.Count(dataContext, action => action.CreatedAt >= since);
        if (actionsToday > 0)
            sentences.Add(responseSettings.DryRun
                ? $"Practice mode: ScoutWall would have blocked {Plural(actionsToday, "thing")} today."
                : $"ScoutWall blocked {Plural(actionsToday, "thing")} today.");

        if (analystSettings.IsReady)
        {
            var usage = await AnalystAssessment.GetUsageSince(dataContext, since);
            var reviewed = usage.Investigations + usage.Reused;
            if (reviewed > 0)
            {
                var findingsToday = await AnalystAssessment.Count(dataContext, assessment => assessment.CreatedAt >= since
                    && (assessment.Verdict == AnalystVerdict.NeedsAttention || assessment.Verdict == AnalystVerdict.Malicious));
                sentences.Add(findingsToday == 0
                    ? $"The assistant reviewed {Plural(reviewed, "flagged item")} and found nothing you need to worry about."
                    : $"The assistant reviewed {Plural(reviewed, "flagged item")}; {Plural(findingsToday, "is", "are")} listed above for you.");
            }
        }

        return sentences;
    }

    public static string Bytes(long bytes)
    {
        string[] units = ["bytes", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < units.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        return unitIndex == 0 ? $"{bytes} bytes" : $"{value:0.#} {units[unitIndex]}";
    }

    private static string Plural(int count, string noun)
    {
        return $"{count} {noun}{(count == 1 ? string.Empty : "s")}";
    }

    private static string Plural(int count, string singularVerb, string pluralVerb)
    {
        return $"{count} {(count == 1 ? singularVerb : pluralVerb)}";
    }

    private static string Ago(DateTime time)
    {
        var elapsed = DateTime.UtcNow - time;
        if (elapsed < TimeSpan.FromMinutes(1))
            return $"{Math.Max(1, (int)elapsed.TotalSeconds)} seconds ago";
        if (elapsed < TimeSpan.FromHours(1))
            return $"{(int)elapsed.TotalMinutes} minutes ago";
        if (elapsed < TimeSpan.FromDays(1))
            return $"{(int)elapsed.TotalHours} hours ago";
        return $"{(int)elapsed.TotalDays} days ago";
    }
}
