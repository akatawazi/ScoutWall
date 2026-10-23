using System.Net;
using PacketDotNet;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Capture;
using ScoutWall.Sensor.Network;

namespace ScoutWall.Sensor.Processing;

/// <summary>
/// The fields of one IP packet the sensor cares about.
/// </summary>
public class PacketSummary
{
    public DateTime Timestamp { get; init; }
    public IPAddress SourceAddress { get; init; } = IPAddress.None;
    public IPAddress DestinationAddress { get; init; } = IPAddress.None;
    public int SourcePort { get; init; }
    public int DestinationPort { get; init; }
    public string Protocol { get; init; } = string.Empty;
    public int Length { get; init; }
    public bool IsSynchronize { get; init; }
    public bool IsAcknowledgment { get; init; }
    public byte[] Payload { get; init; } = [];

    /// <summary>
    /// A connection attempt: SYN without ACK.
    /// </summary>
    public bool IsConnectionAttempt => Protocol == "TCP" && IsSynchronize && !IsAcknowledgment;

    public static PacketSummary? FromFrame(CapturedFrame capturedFrame)
    {
        Packet packet;
        try
        {
            packet = Packet.ParsePacket(capturedFrame.LinkType, capturedFrame.Data);
        }
        catch (Exception exception) when (exception is ArgumentException or IndexOutOfRangeException or InvalidOperationException)
        {
            return null;
        }

        var ipPacket = packet.Extract<IPPacket>();
        if (ipPacket == null)
            return null;

        var tcpPacket = packet.Extract<TcpPacket>();
        if (tcpPacket != null)
            return Create(capturedFrame, ipPacket, "TCP", tcpPacket.SourcePort, tcpPacket.DestinationPort, tcpPacket.PayloadData, tcpPacket);

        var udpPacket = packet.Extract<UdpPacket>();
        if (udpPacket != null)
            return Create(capturedFrame, ipPacket, "UDP", udpPacket.SourcePort, udpPacket.DestinationPort, udpPacket.PayloadData, null);

        return Create(capturedFrame, ipPacket, DescribeProtocol(ipPacket.Protocol), 0, 0, [], null);
    }

    private static PacketSummary Create(
        CapturedFrame capturedFrame,
        IPPacket ipPacket,
        string protocol,
        int sourcePort,
        int destinationPort,
        byte[]? payload,
        TcpPacket? tcpPacket)
    {
        return new PacketSummary
        {
            Timestamp = capturedFrame.Timestamp,
            SourceAddress = ipPacket.SourceAddress,
            DestinationAddress = ipPacket.DestinationAddress,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            Protocol = protocol,
            Length = capturedFrame.OriginalLength,
            IsSynchronize = tcpPacket?.Synchronize ?? false,
            IsAcknowledgment = tcpPacket?.Acknowledgment ?? false,
            Payload = payload ?? []
        };
    }

    private static string DescribeProtocol(ProtocolType protocolType)
    {
        return protocolType switch
        {
            ProtocolType.Icmp => "ICMP",
            ProtocolType.IcmpV6 => "ICMPv6",
            ProtocolType.Igmp => "IGMP",
            ProtocolType.Gre => "GRE",
            ProtocolType.Encapsulation => "ESP",
            _ => protocolType.ToString().ToUpperInvariant()
        };
    }
}

/// <summary>
/// A packet seen from the point of view of this network: which side is remote, which port is the service,
/// who started the conversation, and whether this packet travels toward the local side.
/// </summary>
public record Conversation(
    IPAddress RemoteAddress,
    IPAddress LocalAddress,
    int ServicePort,
    TrafficDirection Direction,
    bool IsTowardLocal)
{
    private const int FirstEphemeralPort = 49152;

    public static Conversation Classify(PacketSummary packetSummary, NetworkClassifier networkClassifier)
    {
        var sourceIsClient = SourceIsClient(packetSummary);
        var clientAddress = sourceIsClient ? packetSummary.SourceAddress : packetSummary.DestinationAddress;
        var serverAddress = sourceIsClient ? packetSummary.DestinationAddress : packetSummary.SourceAddress;
        var servicePort = sourceIsClient ? packetSummary.DestinationPort : packetSummary.SourcePort;

        var clientIsLocal = networkClassifier.IsLocal(clientAddress);
        var serverIsLocal = networkClassifier.IsLocal(serverAddress);

        if (serverIsLocal && !clientIsLocal)
            return new Conversation(clientAddress, serverAddress, servicePort, TrafficDirection.Inbound, IsTowardLocal: sourceIsClient);

        var direction = (clientIsLocal, serverIsLocal) switch
        {
            (true, false) => TrafficDirection.Outbound,
            (true, true) => TrafficDirection.Internal,
            _ => TrafficDirection.Transit
        };
        return new Conversation(serverAddress, clientAddress, servicePort, direction, IsTowardLocal: !sourceIsClient);
    }

    /// <summary>
    /// Stateless guess at which side is the client: the sender of a SYN, otherwise the side using the higher
    /// (ephemeral) port. Good enough for aggregation without tracking every connection.
    /// </summary>
    private static bool SourceIsClient(PacketSummary packetSummary)
    {
        if (packetSummary.IsSynchronize)
            return !packetSummary.IsAcknowledgment;

        if (packetSummary.SourcePort == packetSummary.DestinationPort)
            return true;

        var sourceLooksEphemeral = packetSummary.SourcePort >= FirstEphemeralPort;
        var destinationLooksEphemeral = packetSummary.DestinationPort >= FirstEphemeralPort;
        if (sourceLooksEphemeral != destinationLooksEphemeral)
            return sourceLooksEphemeral;

        return packetSummary.SourcePort > packetSummary.DestinationPort;
    }
}
