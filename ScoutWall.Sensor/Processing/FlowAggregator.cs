using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Processing;

/// <summary>
/// Accumulates per-minute conversation counts in memory until the next flush.
/// </summary>
public class FlowAggregator
{
    private Dictionary<FlowKey, TrafficCount> trafficCounts = [];

    public void Add(PacketSummary packetSummary, Conversation conversation)
    {
        var bucketStart = new DateTimeOffset(packetSummary.Timestamp).ToUnixTimeSeconds();
        bucketStart -= bucketStart % TrafficMinute.BucketSeconds;

        var flowKey = new FlowKey(
            bucketStart,
            conversation.RemoteAddress.ToString(),
            conversation.LocalAddress.ToString(),
            conversation.ServicePort,
            packetSummary.Protocol);

        if (!trafficCounts.TryGetValue(flowKey, out var trafficCount))
        {
            trafficCount = new TrafficCount
            {
                BucketStart = flowKey.BucketStart,
                RemoteIp = flowKey.RemoteIp,
                LocalIp = flowKey.LocalIp,
                ServicePort = flowKey.ServicePort,
                Protocol = flowKey.Protocol,
                Direction = conversation.Direction
            };
            trafficCounts[flowKey] = trafficCount;
        }

        if (conversation.IsTowardLocal)
        {
            trafficCount.BytesIn += packetSummary.Length;
            trafficCount.PacketsIn++;
        }
        else
        {
            trafficCount.BytesOut += packetSummary.Length;
            trafficCount.PacketsOut++;
        }

        if (packetSummary.IsConnectionAttempt)
            trafficCount.ConnectionCount++;
    }

    public List<TrafficCount> Drain()
    {
        var drainedCounts = trafficCounts;
        trafficCounts = [];
        return drainedCounts.Values.ToList();
    }

    private record struct FlowKey(long BucketStart, string RemoteIp, string LocalIp, int ServicePort, string Protocol);
}
