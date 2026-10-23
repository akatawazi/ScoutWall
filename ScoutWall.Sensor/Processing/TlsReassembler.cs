using ScoutWall.Sensor.Parsing;

namespace ScoutWall.Sensor.Processing;

/// <summary>
/// Joins ClientHello records split across TCP segments. Modern browsers send post-quantum key shares that
/// push the ClientHello past one segment, and the server name extension can land in the second one.
/// </summary>
public class TlsReassembler
{
    private const int MaximumPendingRecords = 5000;
    private const int MaximumRecordLength = 16 * 1024 + 5;
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromSeconds(10);

    private readonly Dictionary<string, PendingRecord> pendingRecords = [];

    public TlsClientHello? Add(PacketSummary packetSummary)
    {
        if (packetSummary.Protocol != "TCP" || packetSummary.Payload.Length == 0)
            return null;

        var streamKey = $"{packetSummary.SourceAddress}:{packetSummary.SourcePort}>{packetSummary.DestinationAddress}:{packetSummary.DestinationPort}";

        if (pendingRecords.TryGetValue(streamKey, out var pendingRecord))
            return Continue(streamKey, pendingRecord, packetSummary.Payload);

        if (!TlsClientHelloParser.LooksLikeClientHello(packetSummary.Payload))
            return null;

        var recordLength = TlsClientHelloParser.GetRecordLength(packetSummary.Payload);
        if (packetSummary.Payload.Length >= recordLength || recordLength > MaximumRecordLength)
            return TlsClientHelloParser.Parse(packetSummary.Payload);

        if (pendingRecords.Count >= MaximumPendingRecords)
            RemoveExpired(packetSummary.Timestamp);

        if (pendingRecords.Count < MaximumPendingRecords)
            pendingRecords[streamKey] = new PendingRecord(new List<byte>(packetSummary.Payload), recordLength, packetSummary.Timestamp);

        return null;
    }

    private TlsClientHello? Continue(string streamKey, PendingRecord pendingRecord, byte[] payload)
    {
        pendingRecord.Buffer.AddRange(payload);
        if (pendingRecord.Buffer.Count < pendingRecord.ExpectedLength)
            return null;

        pendingRecords.Remove(streamKey);
        return TlsClientHelloParser.Parse(pendingRecord.Buffer.ToArray());
    }

    private void RemoveExpired(DateTime now)
    {
        var expiredKeys = pendingRecords
            .Where(entry => now - entry.Value.StartedAt > PendingLifetime)
            .Select(entry => entry.Key)
            .ToList();

        foreach (var expiredKey in expiredKeys)
            pendingRecords.Remove(expiredKey);
    }

    private record PendingRecord(List<byte> Buffer, int ExpectedLength, DateTime StartedAt);
}
