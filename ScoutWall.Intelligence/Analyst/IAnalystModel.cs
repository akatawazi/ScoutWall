using ScoutWall.Data.Models;

namespace ScoutWall.Intelligence.Analyst;

public record AnalystConclusion(
    AnalystVerdict Verdict,
    double Confidence,
    string Title,
    string Explanation,
    string RecommendedAction,
    int RememberDays,
    long EnvelopeBytesOutPerHour,
    bool ProposesSuppression);

public record AnalystRunResult(AnalystConclusion? Conclusion, string? Error, long InputTokens, long OutputTokens, long CacheReadTokens, int ToolCalls, string Model);

/// <summary>
/// A language model that can assess a case. Every provider gets the same evidence pack and must answer in the
/// same JSON shape; only Claude also offers a deeper investigation in which it calls lookups itself.
/// </summary>
public interface IAnalystModel
{
    string ModelName { get; }

    bool SupportsDeepInvestigation { get; }

    Task<AnalystRunResult> Assess(AnalystCase analystCase, string evidencePack, string hostContext, string? baselineProfile, CancellationToken cancellationToken);

    Task<AnalystRunResult> Investigate(AnalystCase analystCase, string hostContext, string? baselineProfile, AnalystTools analystTools, CancellationToken cancellationToken);

    Task<(string? Profile, long Tokens)> WriteBaselineProfile(string hostContext, string observedActivity, CancellationToken cancellationToken);

    /// <summary>
    /// A plain reply to a conversation, used by the read-only chat for providers without tool use.
    /// </summary>
    Task<(string Reply, long Tokens)> Reply(string systemPrompt, IReadOnlyList<(bool FromUser, string Text)> conversation, CancellationToken cancellationToken);
}
