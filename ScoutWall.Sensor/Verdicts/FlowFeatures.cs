using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Network;

namespace ScoutWall.Sensor.Verdicts;

/// <summary>
/// The structured description of one flow that verdict providers judge. Built from the stored traffic,
/// enrichment, passive DNS, TLS metadata and per-program records rather than from raw packets.
/// </summary>
public class FlowFeatures
{
    public string LocalIp { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public int ServicePort { get; set; }
    public string ServiceName { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public TrafficDirection Direction { get; set; }

    public string? CountryCode { get; set; }
    public string? CountryName { get; set; }
    public long? AutonomousSystemNumber { get; set; }
    public string? NetworkOwner { get; set; }
    public bool IsBlocklisted { get; set; }
    public string? BlocklistSource { get; set; }
    public double? RemoteFirstSeenHoursAgo { get; set; }

    public string? Hostname { get; set; }
    public string? ServerName { get; set; }
    public string? TlsVersion { get; set; }
    public string? ApplicationProtocols { get; set; }

    public string? ProcessPath { get; set; }
    public string? ProcessName { get; set; }
    public double? ProcessFirstSeenHoursAgo { get; set; }
    public bool ProcessInUserWritableFolder { get; set; }

    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long ConnectionCount { get; set; }
    public int ActiveMinutes { get; set; }
    public long IdleBytesSent { get; set; }
    public int LocalHour { get; set; }

    /// <summary>
    /// True while ScoutWall is still learning what is normal on this machine.
    /// </summary>
    public bool IsLearningPeriod { get; set; }

    public bool RemoteFirstSeenAfterBaseline { get; set; }
    public bool ProcessFirstSeenAfterBaseline { get; set; }

    public bool SentWhileIdle => IdleBytesSent > 0;

    /// <summary>
    /// New means first seen in the last day and after the learning period, so a machine's existing programs
    /// and destinations never count as new just because ScoutWall was installed recently.
    /// </summary>
    public bool IsNewRemote => RemoteFirstSeenHoursAgo is < 24 && RemoteFirstSeenAfterBaseline;
    public bool IsNewProcess => ProcessFirstSeenHoursAgo is < 24 && ProcessFirstSeenAfterBaseline;

    /// <summary>
    /// Identifies the flow's situation, ignoring exact byte counts (bucketed by powers of two) and time,
    /// so an unchanged flow is not re-evaluated every pass.
    /// </summary>
    public string ComputeStateHash()
    {
        var stateKey = new
        {
            LocalIp, RemoteIp, ServicePort, Protocol, Direction, CountryCode, IsBlocklisted, Hostname, ServerName, ProcessPath,
            IsNewRemote, IsNewProcess, SentWhileIdle,
            BytesOutBucket = BitLength(BytesOut),
            BytesInBucket = BitLength(BytesIn)
        };
        var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(stateKey)));
        return Convert.ToHexString(hashBytes, 0, 16);
    }

    private static int BitLength(long value)
    {
        return value <= 0 ? 0 : 64 - (int)ulong.LeadingZeroCount((ulong)value);
    }
}

/// <summary>
/// Assembles <see cref="FlowFeatures"/> for recent flows to public addresses.
/// </summary>
public static class FlowFeatureBuilder
{
    private static readonly string[] UserWritableFolderMarkers =
        [@"\users\public\", @"\temp\", @"\downloads\", @"\$recycle.bin\", @"\windows\tasks\"];

    public static async Task<List<FlowFeatures>> Build(DataContext dataContext, Blocklist blocklist, LearningPeriod learningPeriod, long sinceUnixSeconds, int maximumFlows)
    {
        var flowFeatures = await LoadFlows(dataContext, sinceUnixSeconds);
        flowFeatures = flowFeatures.Where(flow => IPAddress.TryParse(flow.RemoteIp, out var address) && !IpNetwork.IsPrivate(address)).ToList();
        if (flowFeatures.Count == 0)
            return flowFeatures;

        var remoteAddresses = flowFeatures.Select(flow => flow.RemoteIp).Distinct().ToList();
        await AttachProfiles(dataContext, flowFeatures, remoteAddresses, blocklist, learningPeriod);
        await AttachNames(dataContext, flowFeatures, remoteAddresses);
        await AttachProcesses(dataContext, flowFeatures, remoteAddresses, sinceUnixSeconds, learningPeriod);

        foreach (var flow in flowFeatures)
            flow.IsLearningPeriod = learningPeriod.IsActive;

        return flowFeatures
            .OrderByDescending(Priority)
            .ThenByDescending(flow => flow.BytesOut)
            .Take(maximumFlows)
            .ToList();
    }

    private static async Task<List<FlowFeatures>> LoadFlows(DataContext dataContext, long sinceUnixSeconds)
    {
        var localHour = DateTime.Now.Hour;
        var flowRows = await dataContext.TrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds)
            .GroupBy(record => new { record.RemoteIp, record.LocalIp, record.ServicePort, record.Protocol, record.Direction })
            .Select(group => new
            {
                group.Key.RemoteIp,
                group.Key.LocalIp,
                group.Key.ServicePort,
                group.Key.Protocol,
                group.Key.Direction,
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount),
                ActiveMinutes = group.Count()
            })
            .ToListAsync();

        return flowRows.Select(row => new FlowFeatures
        {
            RemoteIp = row.RemoteIp,
            LocalIp = row.LocalIp,
            ServicePort = row.ServicePort,
            Protocol = row.Protocol,
            Direction = row.Direction,
            ServiceName = ServiceNames.Describe(row.ServicePort, row.Protocol),
            BytesIn = row.BytesIn,
            BytesOut = row.BytesOut,
            ConnectionCount = row.ConnectionCount,
            ActiveMinutes = row.ActiveMinutes,
            LocalHour = localHour
        }).ToList();
    }

    private static async Task AttachProfiles(DataContext dataContext, List<FlowFeatures> flowFeatures, List<string> remoteAddresses, Blocklist blocklist, LearningPeriod learningPeriod)
    {
        var profiles = await IpAddressProfile.GetMany(dataContext, remoteAddresses);
        var now = DateTime.UtcNow;

        foreach (var flow in flowFeatures)
        {
            var profile = profiles.GetValueOrDefault(flow.RemoteIp);
            flow.CountryCode = profile?.CountryCode;
            flow.CountryName = profile?.CountryName;
            flow.AutonomousSystemNumber = profile?.AutonomousSystemNumber;
            flow.NetworkOwner = profile?.AutonomousSystemOrganization ?? profile?.Isp;
            flow.RemoteFirstSeenHoursAgo = profile == null ? null : (now - profile.FirstSeenAt).TotalHours;
            flow.RemoteFirstSeenAfterBaseline = profile != null && profile.FirstSeenAt > learningPeriod.EndsAt;
            flow.BlocklistSource = blocklist.FindSource(IPAddress.Parse(flow.RemoteIp)) ?? profile?.BlocklistSource;
            flow.IsBlocklisted = flow.BlocklistSource != null;
        }
    }

    private static async Task AttachNames(DataContext dataContext, List<FlowFeatures> flowFeatures, List<string> remoteAddresses)
    {
        var hostnames = await DnsRecord.GetLatestHostnames(dataContext, remoteAddresses);
        var tlsSessions = await dataContext.TlsSessions.AsNoTracking()
            .Where(tlsSession => remoteAddresses.Contains(tlsSession.ServerIp))
            .OrderByDescending(tlsSession => tlsSession.LastSeenAt)
            .ToListAsync();
        var latestTlsSessions = tlsSessions.GroupBy(tlsSession => tlsSession.ServerIp).ToDictionary(group => group.Key, group => group.First());

        foreach (var flow in flowFeatures)
        {
            var tlsSession = latestTlsSessions.GetValueOrDefault(flow.RemoteIp);
            flow.ServerName = tlsSession?.ServerName;
            flow.TlsVersion = tlsSession?.TlsVersion;
            flow.ApplicationProtocols = tlsSession?.ApplicationProtocols;
            flow.Hostname = hostnames.GetValueOrDefault(flow.RemoteIp) ?? tlsSession?.ServerName;
        }
    }

    private static async Task AttachProcesses(DataContext dataContext, List<FlowFeatures> flowFeatures, List<string> remoteAddresses, long sinceUnixSeconds, LearningPeriod learningPeriod)
    {
        var processRows = await dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && remoteAddresses.Contains(record.RemoteIp))
            .GroupBy(record => new { record.RemoteIp, record.ProcessImageId })
            .Select(group => new
            {
                group.Key.RemoteIp,
                group.Key.ProcessImageId,
                BytesSent = group.Sum(record => record.BytesSent),
                IdleBytesSent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0)
            })
            .ToListAsync();

        var processImageIds = processRows.Select(row => row.ProcessImageId).Distinct().ToList();
        var processImages = await dataContext.ProcessImages.AsNoTracking()
            .Where(processImage => processImageIds.Contains(processImage.Id))
            .ToDictionaryAsync(processImage => processImage.Id);
        var topProcessByRemote = processRows
            .GroupBy(row => row.RemoteIp)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(row => row.BytesSent).First());
        var idleBytesByRemote = processRows
            .GroupBy(row => row.RemoteIp)
            .ToDictionary(group => group.Key, group => group.Sum(row => row.IdleBytesSent));

        foreach (var flow in flowFeatures)
        {
            flow.IdleBytesSent = idleBytesByRemote.GetValueOrDefault(flow.RemoteIp);
            if (!topProcessByRemote.TryGetValue(flow.RemoteIp, out var processRow) || !processImages.TryGetValue(processRow.ProcessImageId, out var processImage))
                continue;

            flow.ProcessPath = processImage.ImagePath;
            flow.ProcessName = processImage.Name;
            flow.ProcessFirstSeenHoursAgo = (DateTime.UtcNow - processImage.FirstSeenAt).TotalHours;
            flow.ProcessFirstSeenAfterBaseline = processImage.FirstSeenAt > learningPeriod.EndsAt;
            flow.ProcessInUserWritableFolder = UserWritableFolderMarkers.Any(marker =>
                processImage.ImagePath.Contains(marker, StringComparison.OrdinalIgnoreCase));
        }
    }

    /// <summary>
    /// Novel, idle-time and blocklisted flows are judged first when there are more flows than the pass allows.
    /// </summary>
    private static int Priority(FlowFeatures flow)
    {
        var priority = 0;
        if (flow.IsBlocklisted)
            priority += 8;
        if (flow.SentWhileIdle)
            priority += 4;
        if (flow.IsNewProcess)
            priority += 2;
        if (flow.IsNewRemote)
            priority += 1;
        return priority;
    }
}
