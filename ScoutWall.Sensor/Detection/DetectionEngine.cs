using System.Net;
using System.Text.Json;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Network;
using ScoutWall.Sensor.Processing;

namespace ScoutWall.Sensor.Detection;

public static class RuleNames
{
    public const string PortScan = "PortScan";
    public const string SynFlood = "SynFlood";
    public const string HighVolume = "HighVolume";
    public const string Blocklisted = "Blocklisted";
    public const string SensitivePortAccess = "SensitivePortAccess";
    public const string ExcessiveDns = "ExcessiveDns";
    public const string DataBleed = "DataBleed";
    public const string IdleDataBleed = "IdleDataBleed";
    public const string InternalNameLeak = "InternalNameLeak";

    public static readonly IReadOnlyList<string> All =
        [PortScan, SynFlood, HighVolume, Blocklisted, SensitivePortAccess, ExcessiveDns, DataBleed, IdleDataBleed, InternalNameLeak];
}

/// <summary>
/// Packet-level detection rules. Runs on the capture thread, keeps only in-memory counters,
/// and hands alerts to the alert queue so nothing here waits on the database.
/// </summary>
public class DetectionEngine
{
    private static readonly TimeSpan SuppressionWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan SynFloodWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan OneMinute = TimeSpan.FromMinutes(1);

    private readonly SensorRuntime sensorRuntime;
    private readonly WindowedDistinctCounter<IPAddress, int> scannedPorts = new();
    private readonly WindowedCounter<IPAddress> connectionAttemptsPerTarget = new();
    private readonly WindowedCounter<IPAddress> inboundBytesPerSource = new();
    private readonly WindowedCounter<IPAddress> dnsQueriesPerClient = new();
    private readonly Dictionary<(string Rule, string Key), DateTime> lastRaised = [];

    public DetectionEngine(SensorRuntime sensorRuntime)
    {
        this.sensorRuntime = sensorRuntime;
    }

    public void Inspect(PacketSummary packetSummary, Conversation conversation)
    {
        var detectionSettings = sensorRuntime.Configuration.Detection;

        CheckBlocklist(packetSummary, conversation);

        if (packetSummary.IsConnectionAttempt)
        {
            CheckPortScan(packetSummary, detectionSettings);
            CheckSynFlood(packetSummary, detectionSettings);
            CheckSensitivePortAccess(packetSummary, conversation, detectionSettings);
        }

        if (conversation.IsTowardLocal && conversation.Direction != TrafficDirection.Internal)
            CheckHighVolume(packetSummary, conversation, detectionSettings);

        if (packetSummary.DestinationPort == 53 && conversation.Direction == TrafficDirection.Outbound)
            CheckExcessiveDns(packetSummary, detectionSettings);
    }

    /// <summary>
    /// A short company name (WPAD, a printer, a file server) completed with this computer's domain suffix
    /// resolving to an internet address. Requests meant for internal machines then go to whoever runs that address.
    /// </summary>
    public void InspectDnsAnswer(string questionName, IReadOnlyList<Parsing.DnsAnswer> answers, DateTime timestamp)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.InternalNameLeak))
            return;

        var shortName = sensorRuntime.HostContext.MatchInternalShortName(questionName);
        if (shortName == null)
            return;

        foreach (var dnsAnswer in answers)
        {
            if (!IPAddress.TryParse(dnsAnswer.IpAddress, out var answerAddress) || IpNetwork.IsPrivate(answerAddress))
                continue;

            var isProxyAutoDiscovery = shortName.Equals("wpad", StringComparison.OrdinalIgnoreCase);
            var consequence = isProxyAutoDiscovery
                ? "Windows proxy auto-detection asks that address for a proxy configuration, so whoever controls it could route this computer's web traffic."
                : "Anything this computer sends to that name, such as print jobs or file shares, goes to that internet address instead.";

            Raise(timestamp, RuleNames.InternalNameLeak, isProxyAutoDiscovery ? AlertSeverity.High : AlertSeverity.Medium,
                $"Internal name {questionName} resolves to an internet address",
                $"The short name '{shortName}' was completed with this computer's domain suffix and resolved to public address {answerAddress}. {consequence} " +
                "This usually happens when a domain-joined computer is off the company network and the company's public DNS answers every name.",
                answerAddress, null, null, "DNS",
                new { questionName, shortName, answerAddress = answerAddress.ToString(), isProxyAutoDiscovery },
                suppressionKey: questionName);
        }
    }

    public void Prune(DateTime now)
    {
        var portScanWindow = TimeSpan.FromSeconds(sensorRuntime.Configuration.Detection.PortScanWindowSeconds);
        scannedPorts.Prune(now, portScanWindow);
        connectionAttemptsPerTarget.Prune(now, SynFloodWindow);
        inboundBytesPerSource.Prune(now, OneMinute);
        dnsQueriesPerClient.Prune(now, OneMinute);

        var expiredKeys = lastRaised.Where(entry => now - entry.Value > SuppressionWindow).Select(entry => entry.Key).ToList();
        foreach (var expiredKey in expiredKeys)
            lastRaised.Remove(expiredKey);
    }

    private void CheckBlocklist(PacketSummary packetSummary, Conversation conversation)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.Blocklisted))
            return;

        var blocklistSource = sensorRuntime.Blocklist.FindSource(conversation.RemoteAddress);
        if (blocklistSource == null)
            return;

        var directionText = conversation.Direction == TrafficDirection.Inbound ? "from" : "to";
        Raise(packetSummary.Timestamp, RuleNames.Blocklisted, AlertSeverity.High,
            $"Traffic {directionText} blocklisted address {conversation.RemoteAddress}",
            $"{conversation.LocalAddress} exchanged traffic with {conversation.RemoteAddress}, listed by {blocklistSource}.",
            conversation.RemoteAddress, conversation.LocalAddress, conversation.ServicePort, packetSummary.Protocol,
            new { blocklistSource, direction = conversation.Direction.ToString() });
    }

    private void CheckPortScan(PacketSummary packetSummary, DetectionSettings detectionSettings)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.PortScan) || sensorRuntime.NetworkClassifier.IsHostAddress(packetSummary.SourceAddress))
            return;

        var window = TimeSpan.FromSeconds(detectionSettings.PortScanWindowSeconds);
        var distinctPorts = scannedPorts.Add(packetSummary.SourceAddress, packetSummary.DestinationPort, packetSummary.Timestamp, window);
        if (distinctPorts < detectionSettings.PortScanDistinctPorts)
            return;

        var samplePorts = scannedPorts.GetValues(packetSummary.SourceAddress).Order().Take(30).ToList();
        Raise(packetSummary.Timestamp, RuleNames.PortScan, AlertSeverity.High,
            $"Port scan from {packetSummary.SourceAddress}",
            $"{packetSummary.SourceAddress} probed {distinctPorts} distinct ports on {packetSummary.DestinationAddress} within {detectionSettings.PortScanWindowSeconds} seconds.",
            packetSummary.SourceAddress, packetSummary.DestinationAddress, null, "TCP",
            new { distinctPorts, windowSeconds = detectionSettings.PortScanWindowSeconds, samplePorts });
    }

    private void CheckSynFlood(PacketSummary packetSummary, DetectionSettings detectionSettings)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.SynFlood))
            return;

        var attempts = connectionAttemptsPerTarget.Add(packetSummary.DestinationAddress, 1, packetSummary.Timestamp, SynFloodWindow);
        if (attempts < detectionSettings.SynFloodPerTenSeconds)
            return;

        Raise(packetSummary.Timestamp, RuleNames.SynFlood, AlertSeverity.Critical,
            $"Possible SYN flood against {packetSummary.DestinationAddress}",
            $"{attempts} connection attempts to {packetSummary.DestinationAddress} in 10 seconds. Latest source {packetSummary.SourceAddress}.",
            packetSummary.SourceAddress, packetSummary.DestinationAddress, packetSummary.DestinationPort, "TCP",
            new { attemptsInTenSeconds = attempts, threshold = detectionSettings.SynFloodPerTenSeconds },
            suppressionKey: packetSummary.DestinationAddress.ToString());
    }

    private void CheckSensitivePortAccess(PacketSummary packetSummary, Conversation conversation, DetectionSettings detectionSettings)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.SensitivePortAccess)
            || conversation.Direction != TrafficDirection.Inbound
            || !detectionSettings.SensitivePorts.Contains(packetSummary.DestinationPort)
            || IpNetwork.IsPrivate(packetSummary.SourceAddress))
            return;

        var serviceName = ServiceNames.Describe(packetSummary.DestinationPort, packetSummary.Protocol);
        Raise(packetSummary.Timestamp, RuleNames.SensitivePortAccess, AlertSeverity.Medium,
            $"Internet host reaching {serviceName} on {packetSummary.DestinationAddress}",
            $"{packetSummary.SourceAddress} attempted to connect to {serviceName} (port {packetSummary.DestinationPort}) on {packetSummary.DestinationAddress}.",
            packetSummary.SourceAddress, packetSummary.DestinationAddress, packetSummary.DestinationPort, "TCP",
            new { serviceName });
    }

    private void CheckHighVolume(PacketSummary packetSummary, Conversation conversation, DetectionSettings detectionSettings)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.HighVolume))
            return;

        var bytes = inboundBytesPerSource.Add(conversation.RemoteAddress, packetSummary.Length, packetSummary.Timestamp, OneMinute);
        var thresholdBytes = detectionSettings.HighVolumeMegabytesPerMinute * 1024L * 1024L;
        if (bytes < thresholdBytes)
            return;

        inboundBytesPerSource.Reset(conversation.RemoteAddress);
        Raise(packetSummary.Timestamp, RuleNames.HighVolume, AlertSeverity.Medium,
            $"High inbound volume from {conversation.RemoteAddress}",
            $"{conversation.RemoteAddress} sent more than {detectionSettings.HighVolumeMegabytesPerMinute} MB to {conversation.LocalAddress} within one minute.",
            conversation.RemoteAddress, conversation.LocalAddress, conversation.ServicePort, packetSummary.Protocol,
            new { megabytesPerMinute = bytes / 1024.0 / 1024.0 });
    }

    private void CheckExcessiveDns(PacketSummary packetSummary, DetectionSettings detectionSettings)
    {
        if (!sensorRuntime.IsRuleEnabled(RuleNames.ExcessiveDns))
            return;

        var queries = dnsQueriesPerClient.Add(packetSummary.SourceAddress, 1, packetSummary.Timestamp, OneMinute);
        if (queries < detectionSettings.DnsQueriesPerMinute)
            return;

        dnsQueriesPerClient.Reset(packetSummary.SourceAddress);
        Raise(packetSummary.Timestamp, RuleNames.ExcessiveDns, AlertSeverity.Low,
            $"Excessive DNS queries from {packetSummary.SourceAddress}",
            $"{packetSummary.SourceAddress} sent {queries} DNS queries in one minute. This can indicate DNS tunnelling or malware beaconing.",
            packetSummary.SourceAddress, packetSummary.DestinationAddress, 53, packetSummary.Protocol,
            new { queriesPerMinute = queries });
    }

    private void Raise(
        DateTime timestamp,
        string ruleName,
        AlertSeverity severity,
        string title,
        string description,
        IPAddress sourceAddress,
        IPAddress? destinationAddress,
        int? destinationPort,
        string? protocol,
        object details,
        string? suppressionKey = null)
    {
        if (sensorRuntime.Configuration.Detection.IsSuppressed(ruleName, sourceAddress.ToString()))
            return;

        var raisedKey = (ruleName, suppressionKey ?? sourceAddress.ToString());
        if (lastRaised.TryGetValue(raisedKey, out var lastTime) && timestamp - lastTime < SuppressionWindow)
            return;

        lastRaised[raisedKey] = timestamp;
        var alert = AlertBuilder.Build(ruleName, severity, title, description, sourceAddress.ToString(),
            destinationAddress?.ToString(), destinationPort, protocol, details, timestamp);
        sensorRuntime.AlertQueue.Writer.TryWrite(alert);
    }
}

public static class AlertBuilder
{
    public static Alert Build(
        string ruleName,
        AlertSeverity severity,
        string title,
        string description,
        string sourceIp,
        string? destinationIp,
        int? destinationPort,
        string? protocol,
        object details,
        DateTime timestamp,
        string? processPath = null)
    {
        return new Alert
        {
            RuleName = ruleName,
            Severity = severity,
            Status = AlertStatus.Open,
            Title = title,
            Description = description,
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ProcessPath = processPath,
            Details = JsonSerializer.Serialize(details),
            CreatedAt = timestamp,
            LastSeenAt = timestamp,
            OccurrenceCount = 1
        };
    }
}
