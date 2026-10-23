using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum AnalystVerdict
{
    Benign = 1,
    NeedsAttention = 2,
    Malicious = 3,
    Failed = 4
}

/// <summary>
/// The analyst agent's conclusion about one case: what it is, whether the user needs to care, and why.
/// Benign conclusions are remembered for a scope (program + destination) and a volume envelope, so the same
/// activity is not re-investigated until it changes.
/// </summary>
[Table("analyst_assessments")]
[Index(nameof(CaseKey), nameof(CreatedAt))]
[Index(nameof(Verdict), nameof(Acknowledged))]
[Index(nameof(CreatedAt))]
public class AnalystAssessment : Repository<AnalystAssessment>
{
    public const int MaximumRememberDays = 30;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("case_key")]
    [MaxLength(1024)]
    public string CaseKey { get; set; } = string.Empty;

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("verdict")]
    public AnalystVerdict Verdict { get; set; }

    [Column("confidence")]
    public double Confidence { get; set; }

    [Column("title")]
    [MaxLength(256)]
    public string Title { get; set; } = string.Empty;

    [Column("explanation")]
    public string Explanation { get; set; } = string.Empty;

    [Column("recommended_action")]
    [MaxLength(1024)]
    public string? RecommendedAction { get; set; }

    /// <summary>
    /// The agent believes this hard-rule alert is a false positive (for example an internal vulnerability
    /// scanner) and suggests suppressing it. Only applied when a person confirms.
    /// </summary>
    [Column("proposes_suppression")]
    public bool ProposesSuppression { get; set; }

    [Column("floor_note")]
    [MaxLength(512)]
    public string? FloorNote { get; set; }

    [Column("remember_until")]
    public DateTime? RememberUntil { get; set; }

    /// <summary>
    /// The bytes per hour sent out that the agent judged normal. Much more than this reopens the case.
    /// </summary>
    [Column("envelope_bytes_out_per_hour")]
    public long EnvelopeBytesOutPerHour { get; set; }

    [Column("envelope_idle_share")]
    public double EnvelopeIdleShare { get; set; }

    [Column("process_fingerprint")]
    [MaxLength(128)]
    public string? ProcessFingerprint { get; set; }

    [Column("process_path")]
    [MaxLength(1024)]
    public string? ProcessPath { get; set; }

    [Column("remote_ip")]
    [MaxLength(45)]
    public string? RemoteIp { get; set; }

    [Column("destination")]
    [MaxLength(256)]
    public string? Destination { get; set; }

    [Column("rule_name")]
    [MaxLength(64)]
    public string? RuleName { get; set; }

    [Column("alert_id")]
    public long? AlertId { get; set; }

    [Column("evidence_json")]
    public string EvidenceJson { get; set; } = "{}";

    /// <summary>
    /// True when the conclusion was reused from an earlier assessment without calling the model.
    /// </summary>
    [Column("reused_from_id")]
    public long? ReusedFromId { get; set; }

    [Column("model")]
    [MaxLength(64)]
    public string? Model { get; set; }

    [Column("input_tokens")]
    public long InputTokens { get; set; }

    [Column("output_tokens")]
    public long OutputTokens { get; set; }

    [Column("cache_read_tokens")]
    public long CacheReadTokens { get; set; }

    [Column("tool_calls")]
    public int ToolCalls { get; set; }

    [Column("acknowledged")]
    public bool Acknowledged { get; set; }

    [Column("acknowledged_by")]
    [MaxLength(256)]
    public string? AcknowledgedBy { get; set; }

    [Column("acknowledged_at")]
    public DateTime? AcknowledgedAt { get; set; }

    /// <summary>
    /// The tasks or services behind this finding, when it came from the event logs. Filled in for display.
    /// </summary>
    [NotMapped]
    public List<HostActionTarget> HostActionTargets { get; set; } = [];

    [NotMapped]
    public bool IsFinding => Verdict is AnalystVerdict.NeedsAttention or AnalystVerdict.Malicious;

    [NotMapped]
    public string VerdictBadgeClass => Verdict switch
    {
        AnalystVerdict.Malicious => "bg-danger",
        AnalystVerdict.NeedsAttention => "bg-warning text-dark",
        AnalystVerdict.Benign => "bg-success",
        _ => "bg-secondary"
    };

    [NotMapped]
    public string VerdictLabel => Verdict switch
    {
        AnalystVerdict.NeedsAttention => "Needs attention",
        AnalystVerdict.Failed => "Not assessed",
        _ => Verdict.ToString()
    };

    /// <summary>
    /// The most recent still-valid benign conclusion for a case, if the activity is still inside the
    /// envelope that was judged normal and the program has not changed.
    /// </summary>
    public static async Task<AnalystAssessment?> FindReusableBenign(
        DataContext dataContext,
        string caseKey,
        string? processFingerprint,
        long bytesOutPerHour,
        double reopenMultiplier)
    {
        var now = DateTime.UtcNow;
        var priorAssessment = await Query(dataContext)
            .Where(assessment => assessment.CaseKey == caseKey
                && assessment.Verdict == AnalystVerdict.Benign
                && assessment.ReusedFromId == null
                && assessment.RememberUntil != null
                && assessment.RememberUntil > now)
            .OrderByDescending(assessment => assessment.CreatedAt)
            .FirstOrDefaultAsync();

        if (priorAssessment == null || priorAssessment.ProcessFingerprint != processFingerprint)
            return null;

        var allowedBytes = Math.Max(priorAssessment.EnvelopeBytesOutPerHour, 64 * 1024) * reopenMultiplier;
        return bytesOutPerHour <= allowedBytes ? priorAssessment : null;
    }

    /// <summary>
    /// A recent conclusion about the same recurring situation (for example "internet hosts are probing SSH").
    /// New alerts of that kind are attached to it instead of raising a fresh finding each time.
    /// </summary>
    public static async Task<AnalystAssessment?> FindRecentForSituation(DataContext dataContext, string caseKey, TimeSpan window)
    {
        var since = DateTime.UtcNow.Subtract(window);
        return await Query(dataContext)
            .Where(assessment => assessment.CaseKey == caseKey
                && assessment.ReusedFromId == null
                && assessment.Verdict != AnalystVerdict.Failed
                && assessment.CreatedAt >= since)
            .OrderByDescending(assessment => assessment.CreatedAt)
            .FirstOrDefaultAsync();
    }

    public static async Task<List<AnalystAssessment>> GetOpenFindings(DataContext dataContext, int count)
    {
        var findings = await Query(dataContext)
            .Where(assessment => (assessment.Verdict == AnalystVerdict.NeedsAttention || assessment.Verdict == AnalystVerdict.Malicious)
                && !assessment.Acknowledged)
            .OrderByDescending(assessment => assessment.Verdict)
            .ThenByDescending(assessment => assessment.CreatedAt)
            .Take(count)
            .ToListAsync();

        // Findings about scheduled tasks and services offer to deal with them right there.
        var alertIds = findings.Where(finding => finding.AlertId.HasValue).Select(finding => finding.AlertId!.Value).ToList();
        var hostAlerts = await Alert.GetAll(dataContext, alert => alertIds.Contains(alert.Id) && alert.Scope == AlertScope.Host);
        foreach (var hostAlert in hostAlerts)
        {
            var targets = await HostActionOptions.Build(dataContext, hostAlert);
            foreach (var finding in findings.Where(finding => finding.AlertId == hostAlert.Id))
                finding.HostActionTargets = targets;
        }

        return findings;
    }

    public static async Task<List<AnalystAssessment>> GetRecent(DataContext dataContext, AnalystVerdict? verdict, int count)
    {
        var query = Query(dataContext);
        if (verdict.HasValue)
            query = query.Where(assessment => assessment.Verdict == verdict.Value);

        return await query.OrderByDescending(assessment => assessment.CreatedAt).Take(count).ToListAsync();
    }

    public static async Task<List<AnalystAssessment>> GetPrior(DataContext dataContext, string? processPath, string? destination, int count)
    {
        var query = Query(dataContext).Where(assessment => assessment.ReusedFromId == null && assessment.Verdict != AnalystVerdict.Failed);
        if (!string.IsNullOrEmpty(processPath))
            query = query.Where(assessment => assessment.ProcessPath == processPath);

        if (!string.IsNullOrEmpty(destination))
            query = query.Where(assessment => assessment.Destination == destination || assessment.RemoteIp == destination);

        return await query.OrderByDescending(assessment => assessment.CreatedAt).Take(count).ToListAsync();
    }

    public static async Task<AnalystUsage> GetUsageSince(DataContext dataContext, DateTime since)
    {
        var assessments = Query(dataContext).Where(assessment => assessment.CreatedAt >= since);
        return new AnalystUsage
        {
            Investigations = await assessments.CountAsync(assessment => assessment.ReusedFromId == null && assessment.Model != null),
            Reused = await assessments.CountAsync(assessment => assessment.ReusedFromId != null),
            InputTokens = await assessments.SumAsync(assessment => assessment.InputTokens),
            OutputTokens = await assessments.SumAsync(assessment => assessment.OutputTokens),
            CacheReadTokens = await assessments.SumAsync(assessment => assessment.CacheReadTokens)
        };
    }

    public static async Task<bool> Acknowledge(DataContext dataContext, long id, string userEmail)
    {
        var assessment = await Get(dataContext, item => item.Id == id);
        if (assessment == null)
            return false;

        assessment.Acknowledged = true;
        assessment.AcknowledgedBy = userEmail;
        assessment.AcknowledgedAt = DateTime.UtcNow;
        await Update(dataContext, assessment);
        await AuditEntry.Record(dataContext, userEmail, "Analyst finding acknowledged", assessment.Title);
        return true;
    }

    /// <summary>
    /// A person confirms the agent's proposal that a scan alert source is legitimate (for example a
    /// vulnerability scanner). Adds the rule and source to the detection suppression list.
    /// </summary>
    public static async Task<string?> ConfirmSuppression(DataContext dataContext, long id, string userEmail)
    {
        var assessment = await Get(dataContext, item => item.Id == id);
        if (assessment == null || !assessment.ProposesSuppression || assessment.RuleName == null || assessment.RemoteIp == null)
            return "This finding does not propose a suppression.";

        var detectionSettings = await Setting.Load<DetectionSettings>(dataContext);
        var suppressionEntry = DetectionSettings.SuppressionEntry(assessment.RuleName, assessment.RemoteIp);
        if (!detectionSettings.SuppressedDetections.Contains(suppressionEntry))
            detectionSettings.SuppressedDetections.Add(suppressionEntry);

        var revision = await Setting.GetRevision<DetectionSettings>(dataContext);
        var errors = await Setting.Save(dataContext, detectionSettings, revision, userEmail);
        if (errors.Count > 0)
            return string.Join(" ", errors);

        await Acknowledge(dataContext, id, userEmail);
        return null;
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, assessment => assessment.CreatedAt < cutoff && (assessment.Acknowledged || assessment.Verdict == AnalystVerdict.Benign));
    }
}

public class AnalystUsage
{
    public int Investigations { get; set; }
    public int Reused { get; set; }
    public long InputTokens { get; set; }
    public long OutputTokens { get; set; }
    public long CacheReadTokens { get; set; }

    public long TotalTokens => InputTokens + OutputTokens;
}

public class AnalystOverview
{
    public AnalystSettings Settings { get; set; } = new();
    public LearningPeriod LearningPeriod { get; set; } = new(DateTime.UtcNow, 24);
    public string? BaselineProfile { get; set; }
    public string? BaselineProfileWrittenAt { get; set; }
    public AnalystUsage UsageToday { get; set; } = new();
    public List<AnalystAssessment> OpenFindings { get; set; } = [];
    public List<AnalystAssessment> RecentAssessments { get; set; } = [];
    public AnalystVerdict? Filter { get; set; }

    public static async Task<AnalystOverview> Build(DataContext dataContext, AnalystVerdict? filter)
    {
        return new AnalystOverview
        {
            Settings = await Setting.Load<AnalystSettings>(dataContext),
            LearningPeriod = await LearningPeriod.Load(dataContext),
            BaselineProfile = await SystemState.GetValue(dataContext, SystemState.BaselineProfileKey),
            BaselineProfileWrittenAt = await SystemState.GetValue(dataContext, SystemState.BaselineProfileWrittenAtKey),
            UsageToday = await AnalystAssessment.GetUsageSince(dataContext, DateTime.UtcNow.Date),
            OpenFindings = await AnalystAssessment.GetOpenFindings(dataContext, 50),
            RecentAssessments = await AnalystAssessment.GetRecent(dataContext, filter, 200),
            Filter = filter
        };
    }
}
