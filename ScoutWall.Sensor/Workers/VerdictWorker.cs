using System.Text.Json;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Detection;
using ScoutWall.Sensor.Verdicts;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Judges recent flows with every enabled verdict provider and stores each opinion.
/// Merge policy: the ScoreCard is authoritative and may raise alerts. External providers (zev) are stored
/// for comparison and, in Annotate mode, may only raise a low-severity alert; they never downgrade the
/// ScoreCard and are never used for blocking.
/// </summary>
public class VerdictWorker : SensorWorker
{
    public const string ScoreCardRule = "ScoreCard";
    public const string ZevRule = "ZevSuspicious";
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan MinimumLookback = TimeSpan.FromMinutes(2);

    private readonly ScoreCardProvider scoreCardProvider = new();
    private readonly ZevVerdictProvider zevVerdictProvider = new();
    private readonly Dictionary<string, DateTime> evaluatedStates = [];
    private DateTime lastPass = DateTime.MinValue;
    private string? lastZevError;

    public VerdictWorker(SensorRuntime sensorRuntime, ILogger<VerdictWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(10);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        var verdictSettings = SensorRuntime.Configuration.Verdict;
        var passInterval = TimeSpan.FromSeconds(verdictSettings.EvaluationIntervalSeconds);
        if (DateTime.UtcNow - lastPass < passInterval || (!verdictSettings.ScoreCardEnabled && !verdictSettings.ZevEnabled))
            return;

        lastPass = DateTime.UtcNow;
        PruneCache();

        var lookback = passInterval * 2 > MinimumLookback ? passInterval * 2 : MinimumLookback;
        var sinceUnixSeconds = DateTimeOffset.UtcNow.Subtract(lookback).ToUnixTimeSeconds();

        await using var dataContext = SensorRuntime.CreateDataContext();
        var learningPeriod = await LearningPeriod.Load(dataContext);
        SensorRuntime.LearningPeriod = learningPeriod;
        var flowFeatures = await FlowFeatureBuilder.Build(dataContext, SensorRuntime.Blocklist, learningPeriod, sinceUnixSeconds, verdictSettings.MaximumFlowsPerPass);

        var flowVerdicts = new List<FlowVerdict>();
        foreach (var flow in flowFeatures)
            flowVerdicts.AddRange(await Evaluate(flow, verdictSettings, cancellationToken));

        // Routine "Ok" verdicts are only worth keeping while they are being compared against zev.
        var verdictsToStore = verdictSettings.ZevEnabled
            ? flowVerdicts
            : flowVerdicts.Where(flowVerdict => flowVerdict.Verdict != Verdict.Ok).ToList();
        await FlowVerdict.InsertBatch(dataContext, verdictsToStore);
        ReportZevErrors();

        if (flowVerdicts.Count > 0)
            Logger.LogDebug("Stored {Count} flow verdicts", flowVerdicts.Count);
    }

    private async Task<List<FlowVerdict>> Evaluate(FlowFeatures flow, VerdictSettings verdictSettings, CancellationToken cancellationToken)
    {
        var stateHash = flow.ComputeStateHash();
        if (evaluatedStates.ContainsKey(stateHash))
            return [];

        evaluatedStates[stateHash] = DateTime.UtcNow;
        var evaluatedAt = DateTime.UtcNow;
        var featuresJson = JsonSerializer.Serialize(flow);
        var flowVerdicts = new List<FlowVerdict>();

        VerdictResult? scoreCardResult = null;
        if (verdictSettings.ScoreCardEnabled)
        {
            scoreCardResult = await scoreCardProvider.Evaluate(flow, verdictSettings, cancellationToken);
            flowVerdicts.Add(ToFlowVerdict(flow, scoreCardResult!, scoreCardProvider.Name, evaluatedAt, stateHash, featuresJson, isShadow: false, templateVersion: null));
            RaiseScoreCardAlert(flow, scoreCardResult!);
        }

        var zevResult = await zevVerdictProvider.Evaluate(flow, verdictSettings, cancellationToken);
        if (zevResult != null)
        {
            var isShadow = verdictSettings.ZevMode == ExternalVerdictMode.Shadow;
            flowVerdicts.Add(ToFlowVerdict(flow, zevResult, zevVerdictProvider.Name, evaluatedAt, stateHash, featuresJson, isShadow, ZevVerdictProvider.TemplateVersion));
            RaiseZevAnnotation(flow, zevResult, scoreCardResult, verdictSettings);
        }

        return flowVerdicts;
    }

    private void RaiseScoreCardAlert(FlowFeatures flow, VerdictResult scoreCardResult)
    {
        if (scoreCardResult.Verdict != Verdict.Problematic || !SensorRuntime.IsRuleEnabled(ScoreCardRule))
            return;

        var subject = flow.ProcessName ?? flow.LocalIp;
        var destination = flow.Hostname ?? flow.RemoteIp;
        var alert = AlertBuilder.Build(
            ScoreCardRule,
            AlertSeverity.Medium,
            $"Problematic flow: {subject} to {destination}",
            $"The ScoreCard rated this flow {scoreCardResult.Score} points. {string.Join("; ", scoreCardResult.Reasons)}.",
            flow.RemoteIp,
            flow.LocalIp,
            flow.ServicePort,
            flow.Protocol,
            new { scoreCardResult.Score, scoreCardResult.Reasons },
            DateTime.UtcNow,
            flow.ProcessPath);
        SensorRuntime.AlertQueue.Writer.TryWrite(alert);
    }

    private void RaiseZevAnnotation(FlowFeatures flow, VerdictResult zevResult, VerdictResult? scoreCardResult, VerdictSettings verdictSettings)
    {
        var isConfidentlyMalicious = zevResult.Verdict == Verdict.Problematic && zevResult.Confidence >= verdictSettings.ZevMinimumConfidence;
        if (verdictSettings.ZevMode != ExternalVerdictMode.Annotate || !isConfidentlyMalicious || scoreCardResult?.Verdict == Verdict.Problematic)
            return;

        var alert = AlertBuilder.Build(
            ZevRule,
            AlertSeverity.Low,
            $"zev flagged {flow.ProcessName ?? flow.LocalIp} to {flow.Hostname ?? flow.RemoteIp}",
            $"zev classified this flow as malicious with confidence {zevResult.Confidence:0.00}; the ScoreCard rated it {scoreCardResult?.Verdict.ToString() ?? "not evaluated"}. Review before acting.",
            flow.RemoteIp,
            flow.LocalIp,
            flow.ServicePort,
            flow.Protocol,
            new { zevResult.Confidence, scoreCard = scoreCardResult?.Verdict.ToString() },
            DateTime.UtcNow,
            flow.ProcessPath);
        SensorRuntime.AlertQueue.Writer.TryWrite(alert);
    }

    private static FlowVerdict ToFlowVerdict(
        FlowFeatures flow,
        VerdictResult verdictResult,
        string provider,
        DateTime evaluatedAt,
        string stateHash,
        string featuresJson,
        bool isShadow,
        string? templateVersion)
    {
        var reasons = string.Join("; ", verdictResult.Reasons);
        return new FlowVerdict
        {
            EvaluatedAt = evaluatedAt,
            Provider = provider,
            Verdict = verdictResult.Verdict,
            Confidence = verdictResult.Confidence,
            Score = verdictResult.Score,
            Reasons = reasons.Length > 2000 ? reasons[..2000] : reasons,
            IsShadow = isShadow,
            LocalIp = flow.LocalIp,
            RemoteIp = flow.RemoteIp,
            ServicePort = flow.ServicePort,
            Protocol = flow.Protocol,
            Direction = flow.Direction,
            ProcessPath = flow.ProcessPath,
            Hostname = flow.Hostname,
            FeaturesJson = featuresJson,
            StateHash = stateHash,
            TemplateVersion = templateVersion
        };
    }

    private void PruneCache()
    {
        var now = DateTime.UtcNow;
        foreach (var expiredState in evaluatedStates.Where(entry => now - entry.Value > CacheLifetime).Select(entry => entry.Key).ToList())
            evaluatedStates.Remove(expiredState);
    }

    private void ReportZevErrors()
    {
        if (zevVerdictProvider.LastError == lastZevError)
            return;

        lastZevError = zevVerdictProvider.LastError;
        if (lastZevError != null)
            Logger.LogWarning("zev verdict provider unavailable: {Message}", lastZevError);
    }
}
