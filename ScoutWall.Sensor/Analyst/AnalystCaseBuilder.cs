using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Intelligence.Analyst;

namespace ScoutWall.Sensor.Analyst;

/// <summary>
/// Turns what the detectors nominated (open alerts and ScoreCard suspicious or problematic verdicts) into cases,
/// merging everything about the same program and destination into one.
/// </summary>
public static class AnalystCaseBuilder
{
    public static async Task<List<AnalystCase>> Build(DataContext dataContext, List<Alert> alerts, List<FlowVerdict> flowVerdicts)
    {
        var cases = new Dictionary<string, AnalystCase>();

        foreach (var flowVerdict in flowVerdicts)
        {
            var analystCase = await CreateCase(dataContext, flowVerdict.ProcessPath, flowVerdict.RemoteIp, flowVerdict.Hostname, flowVerdict.ServicePort, flowVerdict.Protocol, null);
            analystCase = Merge(cases, analystCase);
            analystCase.FlowVerdictId = flowVerdict.Id;
            analystCase.ScoreCardScore = flowVerdict.Score;
            analystCase.ScoreCardReasons = flowVerdict.Reasons;
            analystCase.FeaturesJson = flowVerdict.FeaturesJson;
            analystCase.ProblematicInvolved |= flowVerdict.Verdict == Verdict.Problematic;
        }

        foreach (var alert in alerts)
        {
            var analystCase = alert.IsHostEvent
                ? new AnalystCase
                {
                    Key = AnalystCase.BuildHostKey(alert.RuleName, alert.Subject),
                    ProcessPath = alert.ProcessPath,
                    ProcessFingerprint = ProgramIdentity.Fingerprint(alert.ProcessPath),
                    Subject = alert.Subject,
                    IsHostEvent = true
                }
                : await CreateCase(dataContext, alert.ProcessPath, alert.SourceIp, null, alert.DestinationPort, alert.Protocol, alert.RuleName);
            analystCase = Merge(cases, analystCase);
            analystCase.AlertIds.Add(alert.Id);
            analystCase.RuleNames.Add(alert.RuleName);
            analystCase.RuleName ??= alert.RuleName;
            analystCase.HardRuleInvolved |= alert.IsHardRule;
            analystCase.BlocklistedInvolved |= alert.RuleName == "Blocklisted";
            analystCase.AlertSummaries.Add($"[{alert.Severity}] {alert.RuleName}: {alert.Title}. {alert.Description} (seen {alert.OccurrenceCount} times; evidence {alert.Details})");
        }

        return cases.Values.ToList();
    }

    private static AnalystCase Merge(Dictionary<string, AnalystCase> cases, AnalystCase analystCase)
    {
        if (cases.TryGetValue(analystCase.Key, out var existingCase))
            return existingCase;

        cases[analystCase.Key] = analystCase;
        return analystCase;
    }

    private static async Task<AnalystCase> CreateCase(
        DataContext dataContext,
        string? processPath,
        string? remoteIp,
        string? hostname,
        int? servicePort,
        string? protocol,
        string? ruleName)
    {
        var profile = remoteIp == null ? null : await IpAddressProfile.Get(dataContext, item => item.IpAddress == remoteIp);
        hostname ??= remoteIp == null ? null : (await DnsRecord.GetLatestHostnames(dataContext, [remoteIp])).GetValueOrDefault(remoteIp);
        hostname ??= remoteIp == null ? null : (await TlsSession.GetForAddress(dataContext, remoteIp, 1)).FirstOrDefault()?.ServerName;

        var networkOwner = profile?.AutonomousSystemNumber != null ? $"AS{profile.AutonomousSystemNumber} {profile.IspDisplay}" : profile?.IspDisplay;
        var fingerprint = ProgramIdentity.Fingerprint(processPath);
        var (bytesOutLastHour, idleShare) = await RecentUpload(dataContext, processPath, remoteIp);

        return new AnalystCase
        {
            Key = AnalystCase.BuildKey(processPath, fingerprint, hostname, networkOwner, remoteIp, servicePort, protocol, ruleName),
            ProcessPath = processPath,
            ProcessFingerprint = fingerprint,
            RemoteIp = remoteIp,
            Destination = hostname,
            NetworkOwner = networkOwner,
            ServicePort = servicePort,
            Protocol = protocol,
            BlocklistedInvolved = profile?.IsBlocklisted == true,
            BytesOutLastHour = bytesOutLastHour,
            IdleShare = idleShare
        };
    }

    private static async Task<(long BytesOut, double IdleShare)> RecentUpload(DataContext dataContext, string? processPath, string? remoteIp)
    {
        var since = DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();

        if (processPath != null)
        {
            var processImage = await ProcessImage.Get(dataContext, item => item.ImagePath == processPath);
            if (processImage != null)
            {
                var records = dataContext.ProcessTrafficMinutes.AsNoTracking()
                    .Where(record => record.ProcessImageId == processImage.Id && record.BucketStart >= since);
                if (remoteIp != null)
                    records = records.Where(record => record.RemoteIp == remoteIp);

                var sent = await records.SumAsync(record => record.BytesSent);
                var idleSent = await records.SumAsync(record => record.Presence == PresenceState.Away ? record.BytesSent : 0);
                return (sent, sent == 0 ? 0 : (double)idleSent / sent);
            }
        }

        if (remoteIp == null)
            return (0, 0);

        var bytesOut = await dataContext.TrafficMinutes.AsNoTracking()
            .Where(record => record.RemoteIp == remoteIp && record.BucketStart >= since)
            .SumAsync(record => record.BytesOut);
        return (bytesOut, 0);
    }

    /// <summary>
    /// A compact summary of the machine's usual network activity, used to write the baseline profile.
    /// </summary>
    public static async Task<string> DescribeObservedActivity(DataContext dataContext)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds();
        var programs = await ProcessTrafficMinute.GetSummaries(dataContext, since, 30);
        var destinations = await TrafficRecord<TrafficHour>.GetTopRemoteAddresses(dataContext, since, 40, orderByIncoming: false);
        await IpAddressProfile.Enrich(dataContext, destinations);

        var observedActivity = new
        {
            programs = programs.Select(program => new
            {
                path = program.ProcessImage?.ImagePath,
                publisher = ProgramIdentity.Read(program.ProcessImage?.ImagePath)?.Publisher,
                bytes_sent = program.BytesSent,
                bytes_received = program.BytesReceived,
                bytes_sent_while_idle = program.AwayBytesSent,
                bytes_received_while_idle = program.AwayBytesReceived,
                destinations = program.RemoteAddressCount
            }),
            destinations = destinations.Select(destination => new
            {
                ip = destination.IpAddress,
                name = destination.Hostname,
                owner = destination.Profile?.IspDisplay,
                country = destination.Profile?.CountryName,
                bytes_out = destination.BytesOut,
                bytes_in = destination.BytesIn
            })
        };

        return JsonSerializer.Serialize(observedActivity);
    }
}
