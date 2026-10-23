using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum Verdict
{
    Ok = 1,
    Suspicious = 2,
    Problematic = 3,
    Abstain = 4
}

public enum ExternalVerdictMode
{
    /// <summary>Verdicts are stored for comparison only.</summary>
    Shadow = 1,

    /// <summary>Verdicts are stored and a confident "malicious" raises a low-severity alert. Never blocks.</summary>
    Annotate = 2
}

/// <summary>
/// The opinion of one verdict provider (the deterministic ScoreCard, or an external engine such as zev)
/// about one flow. Several providers judge the same flow state, so their agreement can be measured.
/// </summary>
[Table("flow_verdicts")]
[Index(nameof(EvaluatedAt))]
[Index(nameof(StateHash), nameof(Provider))]
[Index(nameof(RemoteIp))]
public class FlowVerdict : Repository<FlowVerdict>
{
    public const string ScoreCardProvider = "ScoreCard";
    public const string ZevProvider = "Zev";

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("evaluated_at")]
    public DateTime EvaluatedAt { get; set; }

    [Column("provider")]
    [MaxLength(32)]
    public string Provider { get; set; } = string.Empty;

    [Column("verdict")]
    public Verdict Verdict { get; set; }

    [Column("confidence")]
    public double Confidence { get; set; }

    [Column("score")]
    public int? Score { get; set; }

    /// <summary>
    /// What the verdict was before any reclassification, kept so the ScoreCard can still be evaluated.
    /// </summary>
    [Column("original_verdict")]
    public Verdict? OriginalVerdict { get; set; }

    [Column("reasons")]
    [MaxLength(2048)]
    public string Reasons { get; set; } = string.Empty;

    [Column("is_shadow")]
    public bool IsShadow { get; set; }

    [Column("local_ip")]
    [MaxLength(45)]
    public string LocalIp { get; set; } = string.Empty;

    [Column("remote_ip")]
    [MaxLength(45)]
    public string RemoteIp { get; set; } = string.Empty;

    [Column("service_port")]
    public int ServicePort { get; set; }

    [Column("protocol")]
    [MaxLength(16)]
    public string Protocol { get; set; } = string.Empty;

    [Column("direction")]
    public TrafficDirection Direction { get; set; }

    [Column("process_path")]
    [MaxLength(1024)]
    public string? ProcessPath { get; set; }

    [Column("hostname")]
    [MaxLength(256)]
    public string? Hostname { get; set; }

    /// <summary>
    /// The structured feature record that was judged, as JSON, so every verdict can be explained later.
    /// </summary>
    [Column("features_json")]
    public string FeaturesJson { get; set; } = "{}";

    [Column("state_hash")]
    [MaxLength(64)]
    public string StateHash { get; set; } = string.Empty;

    [Column("template_version")]
    [MaxLength(16)]
    public string? TemplateVersion { get; set; }

    [NotMapped]
    public string VerdictBadgeClass => Verdict switch
    {
        Verdict.Problematic => "bg-danger",
        Verdict.Suspicious => "bg-warning text-dark",
        Verdict.Ok => "bg-success",
        _ => "bg-secondary"
    };

    public static async Task InsertBatch(DataContext dataContext, IReadOnlyCollection<FlowVerdict> flowVerdicts)
    {
        if (flowVerdicts.Count == 0)
            return;

        dataContext.FlowVerdicts.AddRange(flowVerdicts);
        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<FlowVerdict>> GetRecent(DataContext dataContext, string? provider, Verdict? verdict, int count)
    {
        var query = Query(dataContext);
        if (!string.IsNullOrEmpty(provider))
            query = query.Where(flowVerdict => flowVerdict.Provider == provider);

        if (verdict.HasValue)
            query = query.Where(flowVerdict => flowVerdict.Verdict == verdict.Value);

        return await query
            .OrderByDescending(flowVerdict => flowVerdict.EvaluatedAt)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// Suspicious and problematic ScoreCard verdicts newer than the given id, for the analyst to review.
    /// </summary>
    public static async Task<List<FlowVerdict>> GetCandidatesAfter(DataContext dataContext, long afterId, int count)
    {
        return await Query(dataContext)
            .Where(flowVerdict => flowVerdict.Id > afterId
                && flowVerdict.Provider == ScoreCardProvider
                && (flowVerdict.Verdict == Verdict.Suspicious || flowVerdict.Verdict == Verdict.Problematic))
            .OrderBy(flowVerdict => flowVerdict.Id)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<FlowVerdict>> GetForAddress(DataContext dataContext, string ipAddress, int count)
    {
        return await Query(dataContext)
            .Where(flowVerdict => flowVerdict.RemoteIp == ipAddress || flowVerdict.LocalIp == ipAddress)
            .OrderByDescending(flowVerdict => flowVerdict.EvaluatedAt)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// How often the external provider agreed with the ScoreCard on the same flow state: a confusion matrix
    /// keyed by (ScoreCard verdict, external verdict). This is the evidence needed before trusting zev.
    /// </summary>
    public static async Task<List<VerdictAgreement>> GetAgreement(DataContext dataContext, string externalProvider, DateTime since)
    {
        var scoreCardVerdicts = Query(dataContext)
            .Where(flowVerdict => flowVerdict.Provider == ScoreCardProvider && flowVerdict.EvaluatedAt >= since);
        var externalVerdicts = Query(dataContext)
            .Where(flowVerdict => flowVerdict.Provider == externalProvider && flowVerdict.EvaluatedAt >= since);

        return await scoreCardVerdicts
            .Join(externalVerdicts,
                scoreCard => new { scoreCard.StateHash, scoreCard.EvaluatedAt },
                external => new { external.StateHash, external.EvaluatedAt },
                (scoreCard, external) => new { ScoreCardVerdict = scoreCard.Verdict, ExternalVerdict = external.Verdict })
            .GroupBy(pair => new { pair.ScoreCardVerdict, pair.ExternalVerdict })
            .Select(group => new VerdictAgreement
            {
                ScoreCardVerdict = group.Key.ScoreCardVerdict,
                ExternalVerdict = group.Key.ExternalVerdict,
                Count = group.Count()
            })
            .ToListAsync();
    }

    public const string LearningReclassificationNote = "Reclassified as normal: seen during the initial learning period, when everything is new. Original reasons: ";

    /// <summary>
    /// Re-marks ScoreCard "suspicious" verdicts made during the learning period as normal. They were driven by
    /// novelty, which means nothing while ScoutWall is still learning the machine. Safe to run repeatedly.
    /// </summary>
    public static async Task<int> ReclassifyLearningPeriod(DataContext dataContext, LearningPeriod learningPeriod)
    {
        var learningEndsAt = learningPeriod.EndsAt;
        return await dataContext.FlowVerdicts
            .Where(flowVerdict => flowVerdict.Provider == ScoreCardProvider
                && flowVerdict.Verdict == Verdict.Suspicious
                && flowVerdict.EvaluatedAt < learningEndsAt)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(flowVerdict => flowVerdict.OriginalVerdict, flowVerdict => flowVerdict.Verdict)
                .SetProperty(flowVerdict => flowVerdict.Verdict, Verdict.Ok)
                .SetProperty(flowVerdict => flowVerdict.Reasons, flowVerdict => LearningReclassificationNote + flowVerdict.Reasons));
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, flowVerdict => flowVerdict.EvaluatedAt < cutoff);
    }
}

public class VerdictAgreement
{
    public Verdict ScoreCardVerdict { get; set; }
    public Verdict ExternalVerdict { get; set; }
    public int Count { get; set; }
}

public class VerdictReport
{
    public string? Provider { get; set; }
    public Verdict? Verdict { get; set; }
    public VerdictSettings Settings { get; set; } = new();
    public List<FlowVerdict> Verdicts { get; set; } = [];
    public List<VerdictAgreement> Agreement { get; set; } = [];

    public int AgreementTotal => Agreement.Sum(item => item.Count);
    public int AgreementMatches => Agreement
        .Where(item => item.ScoreCardVerdict == item.ExternalVerdict)
        .Sum(item => item.Count);

    public int CountFor(Verdict scoreCardVerdict, Verdict externalVerdict)
    {
        return Agreement.FirstOrDefault(item => item.ScoreCardVerdict == scoreCardVerdict && item.ExternalVerdict == externalVerdict)?.Count ?? 0;
    }

    public static async Task<VerdictReport> Build(DataContext dataContext, string? provider, Verdict? verdict)
    {
        return new VerdictReport
        {
            Provider = provider,
            Verdict = verdict,
            Settings = await Setting.Load<VerdictSettings>(dataContext),
            Verdicts = await FlowVerdict.GetRecent(dataContext, provider, verdict, 300),
            Agreement = await FlowVerdict.GetAgreement(dataContext, FlowVerdict.ZevProvider, DateTime.UtcNow.AddDays(-7))
        };
    }
}
