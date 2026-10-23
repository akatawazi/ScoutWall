using System.Net;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Capture;
using ScoutWall.Sensor.Detection;
using ScoutWall.Sensor.Network;
using ScoutWall.Sensor.Parsing;

namespace ScoutWall.Sensor.Processing;

/// <summary>
/// Everything collected between two flushes.
/// </summary>
public class FlushBatch
{
    public List<TrafficCount> TrafficCounts { get; init; } = [];
    public List<SeenAddress> SeenAddresses { get; init; } = [];
    public List<DnsObservation> DnsObservations { get; init; } = [];
    public List<TlsObservation> TlsObservations { get; init; } = [];
}

/// <summary>
/// Runs every captured frame through decoding, aggregation, detection, passive DNS, TLS metadata
/// extraction and the packet file ring. Single-threaded: only the capture worker's consumer calls it.
/// </summary>
public class PacketProcessor : IDisposable
{
    private readonly SensorRuntime sensorRuntime;
    private readonly FlowAggregator flowAggregator = new();
    private readonly DetectionEngine detectionEngine;
    private readonly TlsReassembler tlsReassembler = new();
    private readonly QuicInitialParser quicInitialParser = new();
    private readonly Dictionary<string, PacketFileWriter> packetFileWriters = [];
    private List<DnsObservation> dnsObservations = [];
    private List<PendingTlsObservation> pendingTlsObservations = [];

    public PacketProcessor(SensorRuntime sensorRuntime)
    {
        this.sensorRuntime = sensorRuntime;
        detectionEngine = new DetectionEngine(sensorRuntime);
    }

    public void Process(CapturedFrame capturedFrame)
    {
        sensorRuntime.Statistics.RecordPacket(capturedFrame.OriginalLength);
        WritePacketFile(capturedFrame);

        var packetSummary = PacketSummary.FromFrame(capturedFrame);
        if (packetSummary == null)
            return;

        var conversation = Conversation.Classify(packetSummary, sensorRuntime.NetworkClassifier);
        flowAggregator.Add(packetSummary, conversation);
        detectionEngine.Inspect(packetSummary, conversation);
        CollectDns(packetSummary);
        CollectTls(packetSummary, conversation);
    }

    public FlushBatch Drain()
    {
        var trafficCounts = flowAggregator.Drain();
        var flushBatch = new FlushBatch
        {
            TrafficCounts = trafficCounts,
            SeenAddresses = BuildSeenAddresses(trafficCounts),
            DnsObservations = dnsObservations,
            TlsObservations = ResolveTlsOwners()
        };

        dnsObservations = [];
        detectionEngine.Prune(DateTime.UtcNow);

        foreach (var packetFileWriter in packetFileWriters.Values)
            packetFileWriter.Flush();

        return flushBatch;
    }

    public void Dispose()
    {
        foreach (var packetFileWriter in packetFileWriters.Values)
            packetFileWriter.Dispose();

        packetFileWriters.Clear();
        GC.SuppressFinalize(this);
    }

    private void WritePacketFile(CapturedFrame capturedFrame)
    {
        var captureSettings = sensorRuntime.Configuration.Capture;
        if (!captureSettings.WritePacketFiles)
            return;

        if (!packetFileWriters.TryGetValue(capturedFrame.InterfaceName, out var packetFileWriter))
        {
            var filePrefix = $"capture-{packetFileWriters.Count + 1}";
            packetFileWriter = new PacketFileWriter(
                sensorRuntime.PacketFileDirectory,
                filePrefix,
                captureSettings.PacketFileSizeMegabytes,
                captureSettings.PacketFileCount);
            packetFileWriters[capturedFrame.InterfaceName] = packetFileWriter;
        }

        packetFileWriter.Write(capturedFrame);
    }

    private void CollectDns(PacketSummary packetSummary)
    {
        if (packetSummary.Protocol != "UDP" || packetSummary.SourcePort != 53)
            return;

        var dnsMessage = DnsMessageParser.Parse(packetSummary.Payload);
        if (dnsMessage == null || !dnsMessage.IsResponse || string.IsNullOrEmpty(dnsMessage.QuestionName))
            return;

        foreach (var dnsAnswer in dnsMessage.Answers)
            dnsObservations.Add(new DnsObservation(dnsAnswer.IpAddress, dnsMessage.QuestionName, dnsAnswer.RecordType, packetSummary.Timestamp));

        detectionEngine.InspectDnsAnswer(dnsMessage.QuestionName, dnsMessage.Answers, packetSummary.Timestamp);
    }

    private void CollectTls(PacketSummary packetSummary, Conversation conversation)
    {
        var tlsClientHello = IsQuicInitial(packetSummary)
            ? quicInitialParser.Add(packetSummary.Payload, packetSummary.Timestamp)
            : tlsReassembler.Add(packetSummary);

        if (tlsClientHello?.ServerName == null)
            return;

        var tlsObservation = new TlsObservation(
            packetSummary.SourceAddress.ToString(),
            packetSummary.DestinationAddress.ToString(),
            packetSummary.DestinationPort,
            tlsClientHello.ServerName,
            tlsClientHello.TlsVersion,
            tlsClientHello.ApplicationProtocols,
            null,
            packetSummary.Timestamp);
        pendingTlsObservations.Add(new PendingTlsObservation(tlsObservation, packetSummary.Protocol, packetSummary.SourceAddress, packetSummary.SourcePort));
    }

    /// <summary>
    /// A client's QUIC Initial: long header to UDP 443, padded to at least 1200 bytes as RFC 9000 requires.
    /// </summary>
    private static bool IsQuicInitial(PacketSummary packetSummary)
    {
        return packetSummary.Protocol == "UDP"
            && packetSummary.DestinationPort == 443
            && packetSummary.Payload.Length >= 1200
            && (packetSummary.Payload[0] & 0xC0) == 0xC0;
    }

    /// <summary>
    /// The per-program event for a connection often arrives just after its first packet, so the owning program
    /// is looked up at flush time rather than when the ClientHello is seen.
    /// </summary>
    private List<TlsObservation> ResolveTlsOwners()
    {
        var resolvedObservations = pendingTlsObservations
            .Select(pending => pending.Observation with
            {
                ProcessName = sensorRuntime.ConnectionOwners.FindProcessName(pending.Protocol, pending.ClientAddress, pending.ClientPort)
            })
            .ToList();

        pendingTlsObservations = [];
        return resolvedObservations;
    }

    private record PendingTlsObservation(TlsObservation Observation, string Protocol, IPAddress ClientAddress, int ClientPort);

    private List<SeenAddress> BuildSeenAddresses(List<TrafficCount> trafficCounts)
    {
        var seenAt = DateTime.UtcNow;
        return trafficCounts
            .Select(trafficCount => trafficCount.RemoteIp)
            .Distinct()
            .Select(ipAddress => IPAddress.Parse(ipAddress))
            .Select(address => new SeenAddress(
                address.ToString(),
                IpNetwork.IsPrivate(address),
                sensorRuntime.Blocklist.FindSource(address),
                seenAt))
            .ToList();
    }
}
