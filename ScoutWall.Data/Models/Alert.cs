using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

[Table("alerts")]
[Index(nameof(Status), nameof(LastSeenAt))]
[Index(nameof(RuleName), nameof(SourceIp), nameof(Status))]
[Index(nameof(SourceIp))]
[Index(nameof(DestinationIp))]
public class Alert : Repository<Alert>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [Column("rule_name")]
    [MaxLength(64)]
    public string RuleName { get; set; } = string.Empty;

    [Column("severity")]
    public AlertSeverity Severity { get; set; }

    [Column("status")]
    public AlertStatus Status { get; set; } = AlertStatus.Open;

    [Column("title")]
    [MaxLength(256)]
    public string Title { get; set; } = string.Empty;

    [Column("description")]
    public string Description { get; set; } = string.Empty;

    [Column("source_ip")]
    [MaxLength(45)]
    public string SourceIp { get; set; } = string.Empty;

    [Column("destination_ip")]
    [MaxLength(45)]
    public string? DestinationIp { get; set; }

    [Column("destination_port")]
    public int? DestinationPort { get; set; }

    [Column("protocol")]
    [MaxLength(16)]
    public string? Protocol { get; set; }

    /// <summary>
    /// The program responsible, for alerts raised from per-process traffic such as data bleed.
    /// </summary>
    [Column("process_path")]
    [MaxLength(1024)]
    public string? ProcessPath { get; set; }

    [Column("occurrence_count")]
    public int OccurrenceCount { get; set; } = 1;

    /// <summary>
    /// Network alerts are about traffic; host alerts come from this computer's own event logs and have no source address.
    /// </summary>
    [Column("scope")]
    public AlertScope Scope { get; set; } = AlertScope.Network;

    /// <summary>
    /// For host alerts, what the event is about: a service, scheduled task, account or file. Attacker-controlled text.
    /// </summary>
    [Column("subject")]
    [MaxLength(512)]
    public string? Subject { get; set; }

    [NotMapped]
    public bool IsHostEvent => Scope == AlertScope.Host;

    /// <summary>
    /// Rules about data leaving the computer, shown under "Data" on the Alerts tab.
    /// </summary>
    public static readonly string[] DataRules = ["DataBleed", "IdleDataBleed"];

    /// <summary>
    /// The alert came from an internet address that can be blocked from the alert.
    /// </summary>
    [NotMapped]
    public bool SourceCanBeBlocked => !IsHostEvent
        && RuleName != "InternalNameLeak"
        && System.Net.IPAddress.TryParse(SourceIp, out _)
        && !ResponseAction.IsPrivateAddress(SourceIp);

    /// <summary>
    /// A device on the local network touched a decoy port; it can be blocked from reaching this computer.
    /// </summary>
    [NotMapped]
    public bool SourceIsProbingLocalDevice => RuleName is "DecoyPortTouched" or "PortScan"
        && System.Net.IPAddress.TryParse(SourceIp, out _) && ResponseAction.IsPrivateAddress(SourceIp);

    [NotMapped]
    public AlertGroup Group => IsHostEvent ? AlertGroup.System : DataRules.Contains(RuleName) ? AlertGroup.Data : AlertGroup.Network;

    /// <summary>
    /// The tasks or services this alert is about, with what can be done to them. Filled in for display.
    /// </summary>
    [NotMapped]
    public List<HostActionTarget> HostActionTargets { get; set; } = [];

    /// <summary>
    /// JSON evidence captured by the detection rule (counts, ports, thresholds).
    /// </summary>
    [Column("details")]
    public string? Details { get; set; }

    [Column("analyst_assessment_id")]
    public long? AnalystAssessmentId { get; set; }

    [Column("analyst_note")]
    [MaxLength(2048)]
    public string? AnalystNote { get; set; }

    /// <summary>
    /// Soft alerts wait for the analyst before the response mode acts; this marks that the wait is over.
    /// </summary>
    [Column("response_considered")]
    public bool ResponseConsidered { get; set; }

    [Column("acknowledged_by")]
    [MaxLength(256)]
    public string? AcknowledgedBy { get; set; }

    [Column("acknowledged_at")]
    public DateTime? AcknowledgedAt { get; set; }

    [Column("resolved_at")]
    public DateTime? ResolvedAt { get; set; }

    [NotMapped]
    public string SeverityBadgeClass => Severity switch
    {
        AlertSeverity.Critical => "bg-danger",
        AlertSeverity.High => "bg-warning text-dark",
        AlertSeverity.Medium => "bg-info text-dark",
        _ => "bg-secondary"
    };

    [NotMapped]
    public string StatusBadgeClass => Status switch
    {
        AlertStatus.Open => "bg-danger-subtle text-danger-emphasis",
        AlertStatus.Acknowledged => "bg-warning-subtle text-warning-emphasis",
        _ => "bg-success-subtle text-success-emphasis"
    };

    /// <summary>
    /// Stores a new alert, or folds it into an existing open alert for the same rule and source
    /// that was seen within the aggregation window.
    /// </summary>
    public static async Task<Alert> Raise(DataContext dataContext, Alert candidate, TimeSpan aggregationWindow)
    {
        var windowStart = candidate.LastSeenAt.Subtract(aggregationWindow);
        var existingAlert = await Get(
            dataContext,
            alert => alert.RuleName == candidate.RuleName
                && alert.SourceIp == candidate.SourceIp
                && alert.ProcessPath == candidate.ProcessPath
                && alert.Subject == candidate.Subject
                && alert.Status != AlertStatus.Resolved
                && alert.LastSeenAt >= windowStart);

        if (existingAlert == null)
            return await Insert(dataContext, candidate);

        existingAlert.OccurrenceCount++;
        existingAlert.LastSeenAt = candidate.LastSeenAt;
        existingAlert.Description = candidate.Description;
        existingAlert.Details = candidate.Details;
        existingAlert.Severity = candidate.Severity > existingAlert.Severity ? candidate.Severity : existingAlert.Severity;
        return await Update(dataContext, existingAlert);
    }

    public static async Task<List<Alert>> GetRecent(DataContext dataContext, int count)
    {
        return await Query(dataContext)
            .OrderByDescending(alert => alert.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<Alert>> GetForAddress(DataContext dataContext, string ipAddress, int count)
    {
        return await Query(dataContext)
            .Where(alert => alert.SourceIp == ipAddress || alert.DestinationIp == ipAddress)
            .OrderByDescending(alert => alert.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<Alert>> GetFiltered(DataContext dataContext, AlertFilter alertFilter)
    {
        var since = DateTime.UtcNow.Subtract(alertFilter.TimeRange.Duration);
        var query = Query(dataContext).Where(alert => alert.LastSeenAt >= since);
        query = alertFilter.Group switch
        {
            AlertGroup.System => query.Where(alert => alert.Scope == AlertScope.Host),
            AlertGroup.Data => query.Where(alert => alert.Scope == AlertScope.Network && DataRules.Contains(alert.RuleName)),
            AlertGroup.Network => query.Where(alert => alert.Scope == AlertScope.Network && !DataRules.Contains(alert.RuleName)),
            _ => query
        };

        if (alertFilter.Severity.HasValue)
            query = query.Where(alert => alert.Severity >= alertFilter.Severity.Value);

        if (alertFilter.Status.HasValue)
            query = query.Where(alert => alert.Status == alertFilter.Status.Value);

        if (!string.IsNullOrWhiteSpace(alertFilter.Search))
            query = query.Where(alert => alert.SourceIp.Contains(alertFilter.Search)
                || alert.Title.Contains(alertFilter.Search)
                || alert.RuleName.Contains(alertFilter.Search));

        return await query
            .OrderByDescending(alert => alert.LastSeenAt)
            .Take(AlertFilter.MaximumResults)
            .ToListAsync();
    }

    public static async Task<int> CountOpen(DataContext dataContext)
    {
        return await Count(dataContext, alert => alert.Status == AlertStatus.Open);
    }

    public static async Task<Dictionary<AlertSeverity, int>> GetSeverityCounts(DataContext dataContext, DateTime since)
    {
        var severityCounts = await Query(dataContext)
            .Where(alert => alert.LastSeenAt >= since)
            .GroupBy(alert => alert.Severity)
            .Select(group => new { Severity = group.Key, Count = group.Count() })
            .ToListAsync();

        return Enum.GetValues<AlertSeverity>()
            .ToDictionary(
                severity => severity,
                severity => severityCounts.FirstOrDefault(item => item.Severity == severity)?.Count ?? 0);
    }

    public static async Task<bool> Acknowledge(DataContext dataContext, long id, string userEmail)
    {
        var alert = await Get(dataContext, item => item.Id == id);
        if (alert == null || alert.Status != AlertStatus.Open)
            return false;

        alert.Status = AlertStatus.Acknowledged;
        alert.AcknowledgedBy = userEmail;
        alert.AcknowledgedAt = DateTime.UtcNow;
        await Update(dataContext, alert);
        return true;
    }

    public static async Task<bool> Resolve(DataContext dataContext, long id, string userEmail)
    {
        var alert = await Get(dataContext, item => item.Id == id);
        if (alert == null || alert.Status == AlertStatus.Resolved)
            return false;

        alert.Status = AlertStatus.Resolved;
        alert.AcknowledgedBy ??= userEmail;
        alert.AcknowledgedAt ??= DateTime.UtcNow;
        alert.ResolvedAt = DateTime.UtcNow;
        await Update(dataContext, alert);
        return true;
    }

    /// <summary>
    /// Rules whose alerts the analyst may only annotate, never dismiss.
    /// </summary>
    public static readonly IReadOnlySet<string> HardRules = new HashSet<string>
    {
        "Blocklisted", "PortScan", "SynFlood", "SensitivePortAccess", "InternalNameLeak",
        "LogCleared", "DefenderActionFailed", "DecoyPortTouched"
    };

    [NotMapped]
    public bool IsHardRule => HardRules.Contains(RuleName);

    public static async Task<List<Alert>> GetAwaitingAnalyst(DataContext dataContext, DateTime since, int count)
    {
        return await Query(dataContext)
            .Where(alert => alert.AnalystAssessmentId == null && alert.Status == AlertStatus.Open && alert.LastSeenAt >= since)
            .OrderByDescending(alert => alert.Severity)
            .ThenBy(alert => alert.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// Soft alerts whose analyst grace period has passed and that the response mode has not yet considered.
    /// </summary>
    public static async Task<List<Alert>> GetDueForResponse(DataContext dataContext, DateTime createdBefore)
    {
        var hardRules = HardRules.ToList();
        return await Query(dataContext)
            .Where(alert => !alert.ResponseConsidered
                && alert.CreatedAt <= createdBefore
                && !hardRules.Contains(alert.RuleName))
            .OrderBy(alert => alert.CreatedAt)
            .Take(100)
            .ToListAsync();
    }

    public static async Task MarkResponseConsidered(DataContext dataContext, long id)
    {
        await dataContext.Alerts.Where(alert => alert.Id == id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(alert => alert.ResponseConsidered, true));
    }

    /// <summary>
    /// Records the analyst's conclusion on the alert. A benign conclusion resolves soft alerts; hard-rule
    /// alerts only receive the note and stay open for a person to decide.
    /// </summary>
    public static async Task ApplyAssessment(DataContext dataContext, long id, AnalystAssessment assessment, bool mayClose = true)
    {
        var alert = await Get(dataContext, item => item.Id == id);
        if (alert == null)
            return;

        alert.AnalystAssessmentId = assessment.Id;
        alert.AnalystNote = $"{assessment.VerdictLabel}: {assessment.Title}. {assessment.Explanation}";
        if (alert.AnalystNote.Length > 2000)
            alert.AnalystNote = alert.AnalystNote[..2000];

        if (mayClose && assessment.Verdict == AnalystVerdict.Benign && !alert.IsHardRule && alert.Status != AlertStatus.Resolved)
        {
            alert.Status = AlertStatus.Resolved;
            alert.ResolvedAt = DateTime.UtcNow;
            alert.AcknowledgedBy ??= "analyst agent";
            alert.AcknowledgedAt ??= DateTime.UtcNow;
        }

        if (assessment.Verdict == AnalystVerdict.Malicious && alert.Severity < AlertSeverity.High)
            alert.Severity = AlertSeverity.High;

        await Update(dataContext, alert);
        dataContext.ChangeTracker.Clear();
    }

    /// <summary>
    /// How many open alerts of at least the given severity each group has, for the Alerts tab headings.
    /// </summary>
    public static async Task<Dictionary<AlertGroup, int>> CountOpenByGroup(DataContext dataContext, AlertSeverity minimumSeverity, DateTime since)
    {
        var rows = await Query(dataContext)
            .Where(alert => alert.Status == AlertStatus.Open && alert.Severity >= minimumSeverity && alert.LastSeenAt >= since)
            .Select(alert => new { alert.Scope, alert.RuleName })
            .ToListAsync();

        return rows
            .GroupBy(row => row.Scope == AlertScope.Host ? AlertGroup.System : DataRules.Contains(row.RuleName) ? AlertGroup.Data : AlertGroup.Network)
            .ToDictionary(group => group.Key, group => group.Count());
    }

    /// <summary>
    /// Fills in the task and service choices for the host alerts in a list.
    /// </summary>
    public static async Task AttachHostActions(DataContext dataContext, IEnumerable<Alert> alerts)
    {
        foreach (var hostAlert in alerts.Where(alert => alert.IsHostEvent))
            hostAlert.HostActionTargets = await HostActionOptions.Build(dataContext, hostAlert);
    }

    public static async Task<int> DeleteResolvedBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, alert => alert.Status == AlertStatus.Resolved && alert.LastSeenAt < cutoff);
    }
}

/// <summary>
/// Query options from the alerts page. Not persisted.
/// </summary>
public enum AlertGroup
{
    System = 1,
    Data = 2,
    Network = 3
}

public class AlertFilter
{
    public const int MaximumResults = 500;

    public AlertGroup? Group { get; set; }

    public AlertSeverity? Severity { get; set; }
    public AlertStatus? Status { get; set; }
    public string? Search { get; set; }
    public string? Range { get; set; }

    public TimeRange TimeRange => TimeRange.Parse(Range, TimeRange.SevenDays);
}
