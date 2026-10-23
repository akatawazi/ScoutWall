using ScoutWall.Data.Models;

namespace ScoutWall.Intelligence.Analyst;

/// <summary>
/// One thing the analyst should look at: a program talking to a destination, and any alerts and verdicts
/// about it. The key identifies the activity closely enough that a remembered conclusion only covers the same
/// program build talking to the same named destination (or network and port class when no name is known).
/// </summary>
public class AnalystCase
{
    public string Key { get; set; } = string.Empty;
    public string? ProcessPath { get; set; }
    public string? ProcessFingerprint { get; set; }
    public string? RemoteIp { get; set; }
    public string? Destination { get; set; }
    public string? NetworkOwner { get; set; }
    public int? ServicePort { get; set; }
    public string? Protocol { get; set; }
    public string? RuleName { get; set; }
    public List<long> AlertIds { get; set; } = [];
    public List<string> RuleNames { get; set; } = [];
    public long? FlowVerdictId { get; set; }
    public string? ScoreCardReasons { get; set; }
    public int? ScoreCardScore { get; set; }
    public bool HardRuleInvolved { get; set; }
    public bool BlocklistedInvolved { get; set; }
    public bool ProblematicInvolved { get; set; }
    public long BytesOutLastHour { get; set; }
    public double IdleShare { get; set; }
    public List<string> AlertSummaries { get; set; } = [];
    public string? FeaturesJson { get; set; }

    /// <summary>
    /// For findings from this computer's event logs: what the event is about (a service, task, account or threat).
    /// </summary>
    public string? Subject { get; set; }
    public bool IsHostEvent { get; set; }

    /// <summary>
    /// Event-log findings are one situation per rule and subject, whatever program or time they came with.
    /// </summary>
    public static string BuildHostKey(string ruleName, string? subject)
    {
        return $"host|{ruleName}|{subject ?? "none"}".ToLowerInvariant();
    }

    public static string PortClass(int? servicePort, string? protocol)
    {
        return servicePort switch
        {
            null => "none",
            443 or 80 or 8080 or 8443 => protocol == "UDP" ? "quic" : "web",
            53 or 853 => "dns",
            < 1024 => servicePort.Value.ToString(),
            _ => "high"
        };
    }

    public static string BuildKey(string? processPath, string? processFingerprint, string? destination, string? networkOwner, string? remoteIp, int? servicePort, string? protocol, string? ruleName)
    {
        // Internet hosts probing this computer (scans, SSH or RDP attempts) arrive from ever-changing addresses.
        // They are one situation for the owner, so they share one case per rule and service.
        if (processPath == null && ruleName != null && Alert.HardRules.Contains(ruleName))
            return $"probe|{ruleName}|{PortClass(servicePort, protocol)}".ToLowerInvariant();

        var target = destination ?? networkOwner ?? remoteIp ?? "unknown";
        var program = processPath == null ? "no-program" : $"{processPath}#{processFingerprint}";
        var rulePart = ruleName != null && Alert.HardRules.Contains(ruleName) ? $"|{ruleName}" : string.Empty;
        return $"{program}|{target}|{PortClass(servicePort, protocol)}{rulePart}".ToLowerInvariant();
    }

    /// <summary>
    /// What the analyst is told up front. Network-derived values are data, never instructions.
    /// </summary>
    public string Describe()
    {
        if (IsHostEvent)
        {
            var hostLines = new List<string>
            {
                "Source: this computer's Windows event logs or service list (not network traffic).",
                $"About: {Subject ?? "unknown"}",
                $"Program involved: {ProcessPath ?? "none recorded"}",
                "Events and alerts:"
            };
            hostLines.AddRange(AlertSummaries.Select(summary => $"  - {summary}"));
            return string.Join("\n", hostLines);
        }

        var lines = new List<string>
        {
            $"Program: {ProcessPath ?? "unknown (no per-program data)"}",
            $"Remote address: {RemoteIp ?? "n/a"}",
            $"Destination name: {Destination ?? "none observed"}",
            $"Network owner: {NetworkOwner ?? "unknown"}",
            $"Service: {Protocol} port {ServicePort}",
            $"Bytes sent out in the last hour: {BytesOutLastHour:N0}",
            $"Share of data sent while nobody was using the computer: {IdleShare:P0}"
        };

        if (ScoreCardScore.HasValue)
            lines.Add($"ScoreCard rating: {ScoreCardScore} points ({ScoreCardReasons})");

        if (AlertSummaries.Count > 0)
        {
            lines.Add("Alerts raised by detectors:");
            lines.AddRange(AlertSummaries.Select(summary => $"  - {summary}"));
        }

        if (FeaturesJson != null)
            lines.Add($"Flow features: {FeaturesJson}");

        return string.Join("\n", lines);
    }
}
