using ScoutWall.Data.Models;
using ScoutWall.Sensor.Detection;
using ScoutWall.Sensor.Network;

namespace ScoutWall.Sensor.Processes;

/// <summary>
/// Accumulates per-program traffic per minute and watches for data bleed: a program sending more than the
/// configured amount out within ten minutes, with a much lower limit while nobody is using the machine.
/// Called from the ETW thread and drained by the flush loop, so access is locked.
/// </summary>
public class ProcessTrafficAggregator
{
    private static readonly TimeSpan BleedWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan SuppressionWindow = TimeSpan.FromMinutes(5);

    private readonly object syncRoot = new();
    private readonly SensorRuntime sensorRuntime;
    private readonly WindowedCounter<string> sentPerProgram = new();
    private readonly WindowedCounter<string> idleSentPerProgram = new();
    private readonly Dictionary<(string Rule, string ImagePath), DateTime> lastRaised = [];
    private Dictionary<ProcessKey, ProcessTrafficCount> processTrafficCounts = [];

    public ProcessTrafficAggregator(SensorRuntime sensorRuntime)
    {
        this.sensorRuntime = sensorRuntime;
    }

    public void Add(ProcessTrafficEvent processTrafficEvent)
    {
        sensorRuntime.ConnectionOwners.Record(processTrafficEvent);
        var isIdle = sensorRuntime.Idle.IsIdle;
        var isUserIdle = isIdle == true;
        var presence = isIdle switch { true => PresenceState.Away, false => PresenceState.Here, null => PresenceState.Unknown };

        lock (syncRoot)
        {
            Accumulate(processTrafficEvent, presence);
            if (processTrafficEvent.IsSend && !IpNetwork.IsPrivate(processTrafficEvent.RemoteAddress))
                CheckDataBleed(processTrafficEvent, isUserIdle);
        }
    }

    public List<ProcessTrafficCount> Drain()
    {
        lock (syncRoot)
        {
            var drainedCounts = processTrafficCounts;
            processTrafficCounts = [];
            var now = DateTime.UtcNow;
            sentPerProgram.Prune(now, BleedWindow);
            idleSentPerProgram.Prune(now, BleedWindow);
            sensorRuntime.ConnectionOwners.Prune(now);
            return drainedCounts.Values.ToList();
        }
    }

    private void Accumulate(ProcessTrafficEvent processTrafficEvent, PresenceState presence)
    {
        var bucketStart = new DateTimeOffset(processTrafficEvent.Timestamp).ToUnixTimeSeconds();
        bucketStart -= bucketStart % ProcessTrafficMinute.BucketSeconds;
        var processKey = new ProcessKey(bucketStart, processTrafficEvent.ImagePath, processTrafficEvent.RemoteAddress.ToString(),
            processTrafficEvent.Protocol, presence);

        if (!processTrafficCounts.TryGetValue(processKey, out var processTrafficCount))
        {
            processTrafficCount = new ProcessTrafficCount
            {
                BucketStart = bucketStart,
                ImagePath = processKey.ImagePath,
                RemoteIp = processKey.RemoteIp,
                Protocol = processKey.Protocol,
                Presence = presence
            };
            processTrafficCounts[processKey] = processTrafficCount;
        }

        if (processTrafficEvent.IsSend)
            processTrafficCount.BytesSent += processTrafficEvent.Bytes;
        else
            processTrafficCount.BytesReceived += processTrafficEvent.Bytes;
    }

    private void CheckDataBleed(ProcessTrafficEvent processTrafficEvent, bool isUserIdle)
    {
        var detectionSettings = sensorRuntime.Configuration.Detection;
        var imagePath = processTrafficEvent.ImagePath;

        var sentBytes = sentPerProgram.Add(imagePath, processTrafficEvent.Bytes, processTrafficEvent.Timestamp, BleedWindow);
        if (sentBytes >= Megabytes(detectionSettings.DataBleedMegabytesPerTenMinutes))
            RaiseBleed(RuleNames.DataBleed, AlertSeverity.Medium, processTrafficEvent, sentBytes, isUserIdle);

        if (!isUserIdle)
            return;

        var idleSentBytes = idleSentPerProgram.Add(imagePath, processTrafficEvent.Bytes, processTrafficEvent.Timestamp, BleedWindow);
        if (idleSentBytes >= Megabytes(detectionSettings.IdleDataBleedMegabytesPerTenMinutes))
            RaiseBleed(RuleNames.IdleDataBleed, AlertSeverity.High, processTrafficEvent, idleSentBytes, isUserIdle);
    }

    private void RaiseBleed(string ruleName, AlertSeverity severity, ProcessTrafficEvent processTrafficEvent, long sentBytes, bool isUserIdle)
    {
        if (!sensorRuntime.IsRuleEnabled(ruleName))
            return;

        var raisedKey = (ruleName, processTrafficEvent.ImagePath);
        if (lastRaised.TryGetValue(raisedKey, out var lastTime) && processTrafficEvent.Timestamp - lastTime < SuppressionWindow)
            return;

        lastRaised[raisedKey] = processTrafficEvent.Timestamp;
        var programName = Path.GetFileName(processTrafficEvent.ImagePath);
        var sentMegabytes = Math.Round(sentBytes / 1024.0 / 1024.0, 1);
        var idleText = isUserIdle ? " while nobody was using the computer" : string.Empty;
        var title = ruleName == RuleNames.IdleDataBleed
            ? $"{programName} sent data out while the computer was idle"
            : $"{programName} is sending a large amount of data out";

        var alert = AlertBuilder.Build(
            ruleName,
            severity,
            title,
            $"{processTrafficEvent.ImagePath} sent {sentMegabytes} MB in the last 10 minutes{idleText}. Latest destination {processTrafficEvent.RemoteAddress}:{processTrafficEvent.RemotePort}.",
            processTrafficEvent.RemoteAddress.ToString(),
            processTrafficEvent.LocalAddress.ToString(),
            processTrafficEvent.RemotePort,
            processTrafficEvent.Protocol,
            new { sentMegabytes, windowMinutes = BleedWindow.TotalMinutes, isUserIdle, idleFor = sensorRuntime.Idle.IdleFor?.ToString() },
            processTrafficEvent.Timestamp,
            processTrafficEvent.ImagePath);

        sensorRuntime.AlertQueue.Writer.TryWrite(alert);
    }

    private static long Megabytes(int megabytes)
    {
        return megabytes * 1024L * 1024L;
    }

    private record struct ProcessKey(long BucketStart, string ImagePath, string RemoteIp, string Protocol, PresenceState Presence);
}
