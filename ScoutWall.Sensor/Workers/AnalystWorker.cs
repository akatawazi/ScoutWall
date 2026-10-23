using Anthropic.Exceptions;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Intelligence.Analyst;
using ScoutWall.Sensor.Analyst;
using ScoutWall.Sensor.Detection;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Runs the analyst agent over what the detectors nominate. Remembered conclusions are reused without calling
/// the model while the activity stays inside the judged envelope; investigations are capped per hour and per day.
/// </summary>
public class AnalystWorker : SensorWorker
{
    private const string VerdictCursorKey = "analyst_last_verdict_id";
    private const string EscalationRule = "AnalystEscalation";
    private const string BaselineCaseKey = "baseline-profile";

    public AnalystWorker(SensorRuntime sensorRuntime, ILogger<AnalystWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(30);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        var analystSettings = SensorRuntime.Configuration.Analyst;
        if (!analystSettings.IsReady)
            return;

        var agent = AnalystModelFactory.Create(analystSettings);
        if (agent == null)
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        var learningPeriod = await LearningPeriod.Load(dataContext);

        await RefreshBaseline(dataContext, agent, analystSettings, learningPeriod, cancellationToken);

        var verdictCursor = await ReadVerdictCursor(dataContext);
        var alerts = await Alert.GetAwaitingAnalyst(dataContext, DateTime.UtcNow.AddHours(-24), 50);
        var flowVerdicts = await FlowVerdict.GetCandidatesAfter(dataContext, verdictCursor, 100);
        var cases = await AnalystCaseBuilder.Build(dataContext, alerts, flowVerdicts);
        if (cases.Count == 0)
        {
            await SaveVerdictCursor(dataContext, verdictCursor, flowVerdicts);
            return;
        }

        var hostContext = SensorRuntime.HostContext.Describe() + $"\nLearning period: {(learningPeriod.IsActive ? $"active until {learningPeriod.EndsAt:u}" : $"ended {learningPeriod.EndsAt:u}")}";
        var baselineProfile = await SystemState.GetValue(dataContext, SystemState.BaselineProfileKey);
        var handledVerdictIds = new List<long>();

        foreach (var analystCase in cases.OrderByDescending(item => item.HardRuleInvolved || item.ProblematicInvolved))
        {
            if (await TryReuse(dataContext, analystCase, analystSettings))
            {
                RecordHandled(handledVerdictIds, analystCase);
                continue;
            }

            if (!await WithinBudget(dataContext, analystSettings))
                break;

            await Investigate(dataContext, agent, analystCase, hostContext, baselineProfile, analystSettings, cancellationToken);
            RecordHandled(handledVerdictIds, analystCase);
        }

        await SaveVerdictCursor(dataContext, verdictCursor, flowVerdicts.Where(verdict => handledVerdictIds.Contains(verdict.Id)).ToList(), flowVerdicts);
    }

    private static void RecordHandled(List<long> handledVerdictIds, AnalystCase analystCase)
    {
        if (analystCase.FlowVerdictId.HasValue)
            handledVerdictIds.Add(analystCase.FlowVerdictId.Value);
    }

    private async Task<bool> TryReuse(DataContext dataContext, AnalystCase analystCase, AnalystSettings analystSettings)
    {
        if (analystCase.BlocklistedInvolved || analystCase.ProblematicInvolved || analystCase.RuleNames.Contains("SynFlood"))
            return false;

        var isRecurringProbe = analystCase.Key.StartsWith("probe|", StringComparison.Ordinal);
        var priorAssessment = isRecurringProbe
            ? await AnalystAssessment.FindRecentForSituation(dataContext, analystCase.Key, TimeSpan.FromHours(24))
            : await AnalystAssessment.FindReusableBenign(
                dataContext, analystCase.Key, analystCase.ProcessFingerprint, analystCase.BytesOutLastHour, analystSettings.ReopenVolumeMultiplier);
        if (priorAssessment == null)
            return false;

        var reusedAssessment = new AnalystAssessment
        {
            CaseKey = analystCase.Key,
            CreatedAt = DateTime.UtcNow,
            Verdict = priorAssessment.Verdict,
            Confidence = priorAssessment.Confidence,
            Title = priorAssessment.Title,
            Explanation = priorAssessment.Explanation,
            RecommendedAction = priorAssessment.RecommendedAction,
            ProcessPath = analystCase.ProcessPath,
            ProcessFingerprint = analystCase.ProcessFingerprint,
            RemoteIp = analystCase.RemoteIp,
            Destination = analystCase.Destination ?? analystCase.NetworkOwner,
            RuleName = analystCase.RuleName,
            AlertId = analystCase.AlertIds.FirstOrDefault() is var alertId and > 0 ? alertId : null,
            ReusedFromId = priorAssessment.Id,
            Acknowledged = true
        };
        await AnalystAssessment.Insert(dataContext, reusedAssessment);
        dataContext.ChangeTracker.Clear();

        foreach (var linkedAlertId in analystCase.AlertIds)
            await Alert.ApplyAssessment(dataContext, linkedAlertId, reusedAssessment, analystSettings.MayCloseAlerts);

        return true;
    }

    private async Task<bool> WithinBudget(DataContext dataContext, AnalystSettings analystSettings)
    {
        var lastHour = await AnalystAssessment.GetUsageSince(dataContext, DateTime.UtcNow.AddHours(-1));
        if (lastHour.Investigations >= analystSettings.MaximumInvestigationsPerHour)
            return false;

        var today = await AnalystAssessment.GetUsageSince(dataContext, DateTime.UtcNow.Date);
        if (today.TotalTokens < analystSettings.DailyTokenBudget)
            return true;

        if (SensorRuntime.LastError?.StartsWith("Analyst") != true)
            Logger.LogWarning("Analyst daily token budget of {Budget} reached; remaining cases wait until tomorrow", analystSettings.DailyTokenBudget);

        SensorRuntime.LastError = "Analyst: daily token budget reached; new cases wait until tomorrow (UTC).";
        return false;
    }

    private async Task Investigate(
        DataContext dataContext,
        IAnalystModel agent,
        AnalystCase analystCase,
        string hostContext,
        string? baselineProfile,
        AnalystSettings analystSettings,
        CancellationToken cancellationToken)
    {
        AnalystRunResult runResult;
        try
        {
            runResult = await AssessWithEscalation(agent, analystCase, hostContext, baselineProfile, new AnalystTools(dataContext), cancellationToken);
        }
        catch (Exception exception) when (exception is AnthropicApiException or HttpRequestException or InvalidOperationException or TaskCanceledException)
        {
            Logger.LogError("Analyst request failed: {Message}", exception.Message);
            SensorRuntime.LastError = $"Analyst: {exception.Message}";
            runResult = new AnalystRunResult(null, exception.Message, 0, 0, 0, 0, agent.ModelName);
        }

        var assessment = BuildAssessment(analystCase, runResult, analystSettings);
        await AnalystAssessment.Insert(dataContext, assessment);
        dataContext.ChangeTracker.Clear();
        Logger.LogInformation("Analyst: {Verdict} ({Confidence:P0}) {Title} [{Tokens} tokens, {ToolCalls} lookups]",
            assessment.VerdictLabel, assessment.Confidence, assessment.Title, assessment.InputTokens + assessment.OutputTokens, assessment.ToolCalls);

        foreach (var linkedAlertId in analystCase.AlertIds)
            await Alert.ApplyAssessment(dataContext, linkedAlertId, assessment, analystSettings.MayCloseAlerts);

        await Announce(dataContext, analystCase, assessment, analystSettings);
    }

    /// <summary>
    /// Assesses from the evidence pack first. When Claude is unsure (or sees something malicious), it gets a second,
    /// deeper pass in which it chooses its own lookups; token use from both passes is counted.
    /// </summary>
    private static async Task<AnalystRunResult> AssessWithEscalation(
        IAnalystModel agent,
        AnalystCase analystCase,
        string hostContext,
        string? baselineProfile,
        AnalystTools analystTools,
        CancellationToken cancellationToken)
    {
        var evidencePack = await EvidencePack.Gather(analystTools, analystCase);
        var firstPass = await agent.Assess(analystCase, evidencePack, hostContext, baselineProfile, cancellationToken);
        var needsDeeperLook = firstPass.Conclusion == null
            || firstPass.Conclusion.Confidence < 0.6
            || firstPass.Conclusion.Verdict == AnalystVerdict.Malicious;
        if (!agent.SupportsDeepInvestigation || !needsDeeperLook)
            return firstPass;

        var deepPass = await agent.Investigate(analystCase, hostContext, baselineProfile, analystTools, cancellationToken);
        var conclusion = deepPass.Conclusion ?? firstPass.Conclusion;
        return new AnalystRunResult(
            conclusion,
            conclusion == null ? deepPass.Error ?? firstPass.Error : null,
            firstPass.InputTokens + deepPass.InputTokens,
            firstPass.OutputTokens + deepPass.OutputTokens,
            firstPass.CacheReadTokens + deepPass.CacheReadTokens,
            deepPass.ToolCalls,
            agent.ModelName);
    }

    /// <summary>
    /// Applies the floors the agent cannot argue its way past: a blocklisted destination or a problematic
    /// ScoreCard verdict is never closed as benign without a person looking.
    /// </summary>
    private static AnalystAssessment BuildAssessment(AnalystCase analystCase, AnalystRunResult runResult, AnalystSettings analystSettings)
    {
        var conclusion = runResult.Conclusion;
        var assessment = new AnalystAssessment
        {
            CaseKey = analystCase.Key,
            CreatedAt = DateTime.UtcNow,
            Verdict = conclusion?.Verdict ?? AnalystVerdict.Failed,
            Confidence = conclusion?.Confidence ?? 0,
            Title = conclusion?.Title ?? "The analyst could not assess this case",
            Explanation = conclusion?.Explanation ?? runResult.Error ?? "Unknown error.",
            RecommendedAction = conclusion?.RecommendedAction,
            ProposesSuppression = conclusion?.ProposesSuppression == true && analystCase.RuleNames.Any(rule => rule is RuleNames.PortScan or RuleNames.SynFlood),
            ProcessPath = analystCase.ProcessPath,
            ProcessFingerprint = analystCase.ProcessFingerprint,
            RemoteIp = analystCase.RemoteIp,
            Destination = analystCase.Destination ?? analystCase.NetworkOwner,
            RuleName = analystCase.RuleName,
            AlertId = analystCase.AlertIds.Count > 0 ? analystCase.AlertIds[0] : null,
            EvidenceJson = System.Text.Json.JsonSerializer.Serialize(new { analystCase.Key, case_description = analystCase.Describe() }),
            Model = runResult.Model,
            InputTokens = runResult.InputTokens,
            OutputTokens = runResult.OutputTokens,
            CacheReadTokens = runResult.CacheReadTokens,
            ToolCalls = runResult.ToolCalls,
            EnvelopeBytesOutPerHour = conclusion?.EnvelopeBytesOutPerHour ?? 0,
            EnvelopeIdleShare = analystCase.IdleShare
        };

        if (assessment.Verdict == AnalystVerdict.Benign && (analystCase.BlocklistedInvolved || analystCase.ProblematicInvolved))
        {
            assessment.Verdict = AnalystVerdict.NeedsAttention;
            assessment.FloorNote = analystCase.BlocklistedInvolved
                ? "Raised to needs attention: the destination is on a threat blocklist, so a person should confirm."
                : "Raised to needs attention: the ScoreCard rated this problematic, so a person should confirm.";
        }

        if (assessment.Verdict == AnalystVerdict.Benign)
        {
            var rememberDays = Math.Min(conclusion!.RememberDays, analystSettings.RememberDays);
            assessment.RememberUntil = DateTime.UtcNow.AddDays(rememberDays);
            assessment.Acknowledged = !assessment.ProposesSuppression;
        }

        if (assessment.Verdict == AnalystVerdict.Failed)
            assessment.Acknowledged = true;

        return assessment;
    }

    private async Task Announce(DataContext dataContext, AnalystCase analystCase, AnalystAssessment assessment, AnalystSettings analystSettings)
    {
        if (!assessment.IsFinding)
            return;

        var severity = assessment.Verdict == AnalystVerdict.Malicious ? AlertSeverity.High : AlertSeverity.Medium;

        if (assessment.Verdict == AnalystVerdict.Malicious && analystCase.AlertIds.Count == 0)
        {
            var escalation = AlertBuilder.Build(EscalationRule, AlertSeverity.High, assessment.Title, assessment.Explanation,
                analystCase.RemoteIp ?? "unknown", null, analystCase.ServicePort, analystCase.Protocol,
                new { assessmentId = assessment.Id, assessment.Confidence }, DateTime.UtcNow, analystCase.ProcessPath);
            escalation.AnalystAssessmentId = assessment.Id;
            escalation.AnalystNote = $"{assessment.VerdictLabel}: {assessment.Title}";
            SensorRuntime.AlertQueue.Writer.TryWrite(escalation);
        }

        if (!analystSettings.NotifyFindings)
            return;

        var notificationSettings = SensorRuntime.Configuration.Notification;
        var message = $"{assessment.Explanation}\n\nRecommended: {assessment.RecommendedAction}\n\nProgram: {assessment.ProcessPath ?? "n/a"}\nDestination: {assessment.Destination ?? assessment.RemoteIp}";
        var title = $"Analyst: {assessment.Title}";

        if (notificationSettings.EmailEnabled && severity >= notificationSettings.EmailMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Email, severity, title, message, assessment.AlertId);

        if (notificationSettings.WebhookEnabled && severity >= notificationSettings.WebhookMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Webhook, severity, title, message, assessment.AlertId);

        if (notificationSettings.DesktopEnabled && severity >= notificationSettings.DesktopMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Desktop, severity, title, assessment.Explanation, assessment.AlertId);
    }

    /// <summary>
    /// Once learning has finished, and then every few days, the agent writes down what normal looks like here.
    /// </summary>
    private async Task RefreshBaseline(DataContext dataContext, IAnalystModel agent, AnalystSettings analystSettings, LearningPeriod learningPeriod, CancellationToken cancellationToken)
    {
        if (learningPeriod.IsActive)
            return;

        var writtenAtText = await SystemState.GetValue(dataContext, SystemState.BaselineProfileWrittenAtKey);
        var isCurrent = DateTime.TryParse(writtenAtText, null, System.Globalization.DateTimeStyles.RoundtripKind, out var writtenAt)
            && DateTime.UtcNow - writtenAt < TimeSpan.FromDays(analystSettings.BaselineRefreshDays);
        if (isCurrent || !await WithinBudget(dataContext, analystSettings))
            return;

        var observedActivity = await AnalystCaseBuilder.DescribeObservedActivity(dataContext);
        var (profile, tokens) = await agent.WriteBaselineProfile(SensorRuntime.HostContext.Describe(), observedActivity, cancellationToken);
        if (profile == null)
            return;

        await SystemState.SetValue(dataContext, SystemState.BaselineProfileKey, profile);
        await SystemState.SetValue(dataContext, SystemState.BaselineProfileWrittenAtKey, DateTime.UtcNow.ToString("O"));
        await AnalystAssessment.Insert(dataContext, new AnalystAssessment
        {
            CaseKey = BaselineCaseKey,
            CreatedAt = DateTime.UtcNow,
            Verdict = AnalystVerdict.Benign,
            Confidence = 1,
            Title = "Baseline profile written",
            Explanation = profile,
            Model = agent.ModelName,
            OutputTokens = tokens,
            Acknowledged = true
        });
        dataContext.ChangeTracker.Clear();
        Logger.LogInformation("Analyst wrote the baseline profile for this computer");
    }

    /// <summary>
    /// The analyst starts from the newest verdict when first enabled, rather than working through history.
    /// </summary>
    private static async Task<long> ReadVerdictCursor(DataContext dataContext)
    {
        var storedValue = await SystemState.GetValue(dataContext, VerdictCursorKey);
        if (long.TryParse(storedValue, out var cursor))
            return cursor;

        var latestId = dataContext.FlowVerdicts.Select(verdict => (long?)verdict.Id).Max() ?? 0;
        await SystemState.SetValue(dataContext, VerdictCursorKey, latestId.ToString());
        return latestId;
    }

    /// <summary>
    /// Moves past verdicts that were handled, or up to the first one that had to wait for budget.
    /// </summary>
    private static async Task SaveVerdictCursor(DataContext dataContext, long currentCursor, List<FlowVerdict> handledVerdicts, List<FlowVerdict>? allVerdicts = null)
    {
        var candidates = allVerdicts ?? handledVerdicts;
        var handledIds = handledVerdicts.Select(verdict => verdict.Id).ToHashSet();
        var newCursor = currentCursor;

        foreach (var flowVerdict in candidates.OrderBy(verdict => verdict.Id))
        {
            if (allVerdicts != null && !handledIds.Contains(flowVerdict.Id))
                break;

            newCursor = flowVerdict.Id;
        }

        if (newCursor != currentCursor)
            await SystemState.SetValue(dataContext, VerdictCursorKey, newCursor.ToString());
    }
}
