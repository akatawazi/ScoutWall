using System.Globalization;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Verdicts;

public record VerdictResult(Verdict Verdict, double Confidence, int? Score, IReadOnlyList<string> Reasons);

/// <summary>
/// One opinion about a flow. Providers are independent; the verdict worker decides what each one may do.
/// </summary>
public interface IFlowVerdictProvider
{
    string Name { get; }

    /// <summary>
    /// Returns null when the provider is unavailable or skipped this flow (rate limit, circuit open).
    /// </summary>
    Task<VerdictResult?> Evaluate(FlowFeatures flowFeatures, VerdictSettings verdictSettings, CancellationToken cancellationToken);
}

/// <summary>
/// Deterministic, explainable scoring. Every point has a stated reason, so a verdict can always be traced.
/// This is the authoritative provider and the baseline any external engine has to beat.
/// </summary>
public class ScoreCardProvider : IFlowVerdictProvider
{
    private const long Megabyte = 1024 * 1024;
    private static readonly HashSet<int> CommonOutboundPorts = [53, 80, 123, 443, 853, 993, 995, 587, 465, 22, 3478, 5228, 5223];

    public string Name => FlowVerdict.ScoreCardProvider;

    public Task<VerdictResult?> Evaluate(FlowFeatures flowFeatures, VerdictSettings verdictSettings, CancellationToken cancellationToken)
    {
        var reasons = new List<string>();
        var score = 0;

        void AddPoints(bool condition, int points, string reason)
        {
            if (!condition)
                return;

            score += points;
            reasons.Add($"+{points} {reason}");
        }

        var isOutbound = flowFeatures.Direction == TrafficDirection.Outbound;
        AddPoints(flowFeatures.IsBlocklisted, 80, $"destination is on a threat blocklist ({flowFeatures.BlocklistSource})");
        AddPoints(isOutbound && flowFeatures.SentWhileIdle, 25, "data was sent while nobody was using the computer");
        AddPoints(flowFeatures.IsNewProcess, 20, "program appeared on this computer in the last 24 hours");
        AddPoints(flowFeatures.ProcessInUserWritableFolder, 20, "program runs from a user-writable folder");
        AddPoints(isOutbound && flowFeatures.BytesOut > 50 * Megabyte, 20, "more than 50 MB sent");
        AddPoints(isOutbound && flowFeatures.BytesOut is > 10 * Megabyte and <= 50 * Megabyte, 10, "more than 10 MB sent");
        AddPoints(isOutbound && flowFeatures.BytesOut > Megabyte && flowFeatures.BytesOut > flowFeatures.BytesIn * 10, 15, "sends far more than it receives");
        // Browsers resolve names over encrypted DNS, so a missing name is weak evidence on its own.
        AddPoints(isOutbound && string.IsNullOrEmpty(flowFeatures.Hostname), 5, "no DNS or TLS name seen for the destination");
        AddPoints(isOutbound && !CommonOutboundPorts.Contains(flowFeatures.ServicePort) && flowFeatures.Protocol == "TCP", 10, $"unusual destination port {flowFeatures.ServicePort}");
        AddPoints(flowFeatures.IsNewRemote, 5, "destination not contacted before");
        AddPoints(flowFeatures.CountryCode != null && verdictSettings.HighRiskCountries.Contains(flowFeatures.CountryCode), 15, $"destination country {flowFeatures.CountryCode} is on the high-risk list");
        AddPoints(flowFeatures.Direction == TrafficDirection.Inbound && flowFeatures.ConnectionCount > 0 && flowFeatures.ServicePort < 1024, 15, $"internet host opened connections to local port {flowFeatures.ServicePort}");
        AddPoints(flowFeatures.LocalHour is >= 1 and < 5 && isOutbound && flowFeatures.BytesOut > Megabyte, 5, "large upload in the small hours");

        var verdict = score >= verdictSettings.ScoreCardProblematicScore ? Verdict.Problematic
            : score >= verdictSettings.ScoreCardSuspiciousScore ? Verdict.Suspicious
            : Verdict.Ok;

        // While learning, only strong evidence (a blocklisted destination, data leaving while idle) may stand.
        if (flowFeatures.IsLearningPeriod && verdict == Verdict.Suspicious)
        {
            verdict = Verdict.Ok;
            reasons.Insert(0, "learning period: novelty is not treated as suspicious yet");
        }

        return Task.FromResult<VerdictResult?>(new VerdictResult(verdict, 1.0, score, reasons));
    }
}

/// <summary>
/// Asks a local zev decision engine (https://github.com/bhubbard/zev-rs, run with "zev serve") to classify
/// a flow from a deterministic text rendering of its features. zev is a general text decision engine, not a
/// network model, so its verdicts start in shadow mode and are never allowed to block anything.
/// </summary>
public class ZevVerdictProvider : IFlowVerdictProvider
{
    public const string TemplateVersion = "flow-v1";
    private const int FailuresBeforeOpening = 3;
    private static readonly TimeSpan CircuitOpenDuration = TimeSpan.FromMinutes(1);
    private static readonly HttpClient HttpClient = new();

    private int consecutiveFailures;
    private DateTime circuitOpenUntil = DateTime.MinValue;
    private DateTime rateWindowStart = DateTime.MinValue;
    private int requestsInWindow;

    public string Name => FlowVerdict.ZevProvider;

    public string? LastError { get; private set; }

    public async Task<VerdictResult?> Evaluate(FlowFeatures flowFeatures, VerdictSettings verdictSettings, CancellationToken cancellationToken)
    {
        if (!verdictSettings.ZevEnabled || DateTime.UtcNow < circuitOpenUntil || !TryTakeRequestSlot(verdictSettings))
            return null;

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(verdictSettings.ZevTimeoutMilliseconds);

            var requestBody = BuildRequest(flowFeatures);
            using var response = await HttpClient.PostAsJsonAsync(verdictSettings.ZevEndpointUrl, requestBody, timeout.Token);
            response.EnsureSuccessStatusCode();
            var responseNode = JsonNode.Parse(await response.Content.ReadAsStringAsync(timeout.Token));

            consecutiveFailures = 0;
            LastError = null;
            return ParseResponse(responseNode);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or System.Text.Json.JsonException)
        {
            RecordFailure(exception.Message);
            return null;
        }
    }

    private bool TryTakeRequestSlot(VerdictSettings verdictSettings)
    {
        var now = DateTime.UtcNow;
        if (now - rateWindowStart >= TimeSpan.FromMinutes(1))
        {
            rateWindowStart = now;
            requestsInWindow = 0;
        }

        if (requestsInWindow >= verdictSettings.ZevMaximumRequestsPerMinute)
            return false;

        requestsInWindow++;
        return true;
    }

    private void RecordFailure(string message)
    {
        LastError = message;
        consecutiveFailures++;
        if (consecutiveFailures >= FailuresBeforeOpening)
            circuitOpenUntil = DateTime.UtcNow.Add(CircuitOpenDuration);
    }

    private static object BuildRequest(FlowFeatures flowFeatures)
    {
        return new
        {
            state = FlowStateTemplate.Render(flowFeatures),
            questions = new
            {
                verdict = new
                {
                    type = "choice",
                    instructions = "Classify this network flow observed on a Windows computer.",
                    options = new[]
                    {
                        new { id = "normal", description = "Expected traffic for this program and destination" },
                        new { id = "suspicious", description = "Unusual traffic worth a closer look" },
                        new { id = "malicious", description = "Likely data exfiltration, command and control, or an attack" }
                    }
                }
            }
        };
    }

    /// <summary>
    /// The response shape of zev is not formally documented, so this looks for the "verdict" answer and a
    /// confidence value wherever they appear. Abstention codes such as "__insufficient__" map to Abstain.
    /// </summary>
    public static VerdictResult ParseResponse(JsonNode? responseNode)
    {
        var verdictNode = FindProperty(responseNode, "verdict") ?? responseNode;
        var answer = verdictNode is JsonValue ? verdictNode.ToString() : FindString(verdictNode, "answer", "decision", "choice", "id", "value", "selected", "result");
        var confidence = FindNumber(verdictNode, "confidence", "probability", "score") ?? FindNumber(responseNode, "confidence") ?? 0;

        var verdict = answer?.Trim().ToLowerInvariant() switch
        {
            "normal" => Verdict.Ok,
            "suspicious" => Verdict.Suspicious,
            "malicious" => Verdict.Problematic,
            _ => Verdict.Abstain
        };

        return new VerdictResult(verdict, confidence, null, [$"zev answered '{answer ?? "nothing"}' with confidence {confidence.ToString("0.00", CultureInfo.InvariantCulture)}"]);
    }

    private static JsonNode? FindProperty(JsonNode? node, string propertyName)
    {
        if (node is JsonObject jsonObject)
        {
            foreach (var (key, value) in jsonObject)
            {
                if (string.Equals(key, propertyName, StringComparison.OrdinalIgnoreCase))
                    return value;

                var nested = FindProperty(value, propertyName);
                if (nested != null)
                    return nested;
            }
        }

        if (node is JsonArray jsonArray)
            return jsonArray.Select(item => FindProperty(item, propertyName)).FirstOrDefault(found => found != null);

        return null;
    }

    private static string? FindString(JsonNode? node, params string[] propertyNames)
    {
        return propertyNames
            .Select(propertyName => FindProperty(node, propertyName))
            .OfType<JsonValue>()
            .Select(value => value.TryGetValue<string>(out var text) ? text : null)
            .FirstOrDefault(text => text != null);
    }

    private static double? FindNumber(JsonNode? node, params string[] propertyNames)
    {
        return propertyNames
            .Select(propertyName => FindProperty(node, propertyName))
            .OfType<JsonValue>()
            .Select(value => value.TryGetValue<double>(out var number) ? number : (double?)null)
            .FirstOrDefault(number => number != null);
    }
}

/// <summary>
/// Renders flow features as fixed, versioned prose for a text decision engine. Hostnames, server names and
/// program names come from the network and could be crafted by an attacker, so they are reduced to a safe
/// character set, length-limited and quoted.
/// </summary>
public static partial class FlowStateTemplate
{
    private const int MaximumFieldLength = 80;

    public static string Render(FlowFeatures flowFeatures)
    {
        var builder = new StringBuilder();
        builder.Append($"Direction: {flowFeatures.Direction.ToString().ToLowerInvariant()}. ");
        builder.Append($"Protocol: {flowFeatures.Protocol} port {flowFeatures.ServicePort} ({Quote(flowFeatures.ServiceName)}). ");

        if (flowFeatures.ProcessName != null)
        {
            builder.Append($"Program: {Quote(flowFeatures.ProcessName)} in folder {Quote(Path.GetDirectoryName(flowFeatures.ProcessPath))}, ");
            builder.Append($"first seen {DescribeAge(flowFeatures.ProcessFirstSeenHoursAgo)}. ");
        }
        else
        {
            builder.Append("Program: unknown. ");
        }

        builder.Append($"Destination: {flowFeatures.RemoteIp}, hostname {Quote(flowFeatures.Hostname ?? "none")}, ");
        builder.Append($"network {Quote(flowFeatures.NetworkOwner ?? "unknown")}, country {Quote(flowFeatures.CountryName ?? "unknown")}, ");
        builder.Append($"first seen {DescribeAge(flowFeatures.RemoteFirstSeenHoursAgo)}. ");
        builder.Append($"Volume: sent {Megabytes(flowFeatures.BytesOut)} MB, received {Megabytes(flowFeatures.BytesIn)} MB ");
        builder.Append($"over {flowFeatures.ActiveMinutes} minutes, {flowFeatures.ConnectionCount} new connections. ");
        builder.Append($"Sent while nobody was using the computer: {(flowFeatures.SentWhileIdle ? "yes" : "no")}. ");
        builder.Append($"On a threat blocklist: {(flowFeatures.IsBlocklisted ? "yes" : "no")}. ");
        builder.Append($"Local hour: {flowFeatures.LocalHour:00}.");
        return builder.ToString();
    }

    private static string Quote(string? value)
    {
        var safeValue = UnsafeCharacters().Replace(value ?? string.Empty, string.Empty);
        if (safeValue.Length > MaximumFieldLength)
            safeValue = safeValue[..MaximumFieldLength];

        return $"\"{safeValue}\"";
    }

    private static string DescribeAge(double? hoursAgo)
    {
        return hoursAgo switch
        {
            null => "never before",
            < 1 => "less than an hour ago",
            < 48 => $"{hoursAgo:0} hours ago",
            _ => $"{hoursAgo / 24:0} days ago"
        };
    }

    private static string Megabytes(long bytes)
    {
        return (bytes / 1024.0 / 1024.0).ToString("0.0", CultureInfo.InvariantCulture);
    }

    [GeneratedRegex(@"[^A-Za-z0-9 .:_\-\\/()]")]
    private static partial Regex UnsafeCharacters();
}
