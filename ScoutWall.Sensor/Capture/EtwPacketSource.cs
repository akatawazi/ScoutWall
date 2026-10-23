using System.Buffers.Binary;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using PacketDotNet;

namespace ScoutWall.Sensor.Capture;

/// <summary>
/// Live capture with what Windows already has: the NDIS packet capture filter that pktmon and "netsh trace" use,
/// read through ETW. Nothing needs installing, so it is the default when Npcap isn't present. It sees this
/// computer's own traffic only (no promiscuous mode, no loopback) and can drop packets under very heavy load;
/// Npcap is used instead whenever it is installed.
/// </summary>
[SupportedOSPlatform("windows")]
public class EtwPacketSource : IPacketSource
{
    private static readonly Guid NdisPacketCaptureProvider = new("2ED6006E-4729-4609-B423-3EE7BCD678EF");
    private const int PacketFragmentEvent = 1001;
    private const string SessionName = "ScoutWall-PacketCapture";

    // Event keywords: the fragment that starts a packet, the one that ends it, and frames in native 802.11 form.
    private const ulong PacketStartKeyword = 0x40000000;
    private const ulong PacketEndKeyword = 0x80000000;
    private const ulong Native80211Keyword = 0x10000;
    private const int MaximumPacketBytes = 256 * 1024;

    private readonly Dictionary<int, string> interfacesByIndex;
    private readonly Dictionary<int, List<byte>> partialPackets = [];

    /// <param name="deviceNames">Capture device names (\Device\NPF_{adapter id}) chosen in settings.</param>
    public EtwPacketSource(IEnumerable<string> deviceNames)
    {
        var wanted = deviceNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        interfacesByIndex = NetworkInterface.GetAllNetworkInterfaces()
            .Where(networkInterface => wanted.Contains($@"\Device\NPF_{networkInterface.Id}"))
            .Select(networkInterface => (Index: InterfaceIndex(networkInterface), Name: $@"\Device\NPF_{networkInterface.Id}"))
            .Where(entry => entry.Index > 0)
            .ToDictionary(entry => entry.Index, entry => entry.Name);
    }

    public string Name => "Windows packet capture";

    /// <summary>
    /// The adapters this source listens on, by capture device name.
    /// </summary>
    public IReadOnlyCollection<string> InterfaceNames => interfacesByIndex.Values;

    public async Task Run(ChannelWriter<CapturedFrame> frameWriter, CaptureStatistics captureStatistics, CancellationToken cancellationToken)
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("Windows packet capture needs the sensor to run as administrator.");

        if (interfacesByIndex.Count == 0)
            throw new InvalidOperationException("None of the selected network adapters is present.");

        using var session = new TraceEventSession(SessionName) { StopOnDispose = true, BufferSizeMB = 128 };
        session.Source.AllEvents += traceEvent =>
        {
            if ((int)traceEvent.ID != PacketFragmentEvent || traceEvent.ProviderGuid != NdisPacketCaptureProvider)
                return;

            var frame = ReadFragment(traceEvent);
            if (frame != null && !frameWriter.TryWrite(frame))
                captureStatistics.RecordDropped();
        };

        session.EnableProvider(NdisPacketCaptureProvider, TraceEventLevel.Verbose, ulong.MaxValue);
        // Lost-event counts can only be read while the session exists, so they are taken just before stopping.
        using var cancellationRegistration = cancellationToken.Register(() =>
        {
            try
            {
                captureStatistics.RecordDropped(session.EventsLost);
            }
            catch (Exception)
            {
                // The session already ended; nothing more to count.
            }

            session.Stop();
        });
        await Task.Run(() => session.Source.Process(), CancellationToken.None);
    }

    /// <summary>
    /// Turns one fragment event into a frame, joining packets Windows split across several events. The same packet
    /// is reported once per filter layer; only the miniport's own copy (lower index equals miniport index) is kept.
    /// </summary>
    private CapturedFrame? ReadFragment(TraceEvent traceEvent)
    {
        // Payload: MiniportIfIndex (4), LowerIfIndex (4), FragmentSize (4), Fragment (FragmentSize bytes), ...
        var data = traceEvent.EventData();
        if (data.Length < 12)
            return null;

        var miniportIndex = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(0));
        var lowerIndex = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(4));
        var fragmentSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8));
        if (miniportIndex != lowerIndex || !interfacesByIndex.TryGetValue(miniportIndex, out var interfaceName)
            || fragmentSize <= 0 || 12 + fragmentSize > data.Length)
            return null;

        var keywords = (ulong)traceEvent.Keywords;
        var fragment = data.AsSpan(12, fragmentSize);
        var isStart = (keywords & PacketStartKeyword) != 0;
        var isEnd = (keywords & PacketEndKeyword) != 0;

        byte[] packet;
        if (isStart && isEnd)
        {
            packet = fragment.ToArray();
        }
        else
        {
            if (isStart || !partialPackets.TryGetValue(miniportIndex, out var parts))
                partialPackets[miniportIndex] = parts = [];

            if (parts.Count + fragmentSize <= MaximumPacketBytes)
                parts.AddRange(fragment.ToArray());

            if (!isEnd)
                return null;

            packet = parts.ToArray();
            partialPackets.Remove(miniportIndex);
        }

        if ((keywords & Native80211Keyword) != 0)
        {
            packet = WifiFrames.ToEthernet(packet)!;
            if (packet == null)
                return null;
        }

        return new CapturedFrame(traceEvent.TimeStamp.ToUniversalTime(), LinkLayers.Ethernet, packet, packet.Length, interfaceName);
    }

    private static int InterfaceIndex(NetworkInterface networkInterface)
    {
        var properties = networkInterface.GetIPProperties();
        try
        {
            return properties.GetIPv4Properties()?.Index ?? properties.GetIPv6Properties()?.Index ?? 0;
        }
        catch (NetworkInformationException)
        {
            return 0;
        }
    }
}

/// <summary>
/// Wi-Fi adapters hand Windows' capture raw 802.11 data frames (already decrypted). The rest of ScoutWall reads
/// Ethernet, so the 802.11 header and LLC/SNAP header are replaced by an Ethernet header with the same addresses.
/// </summary>
public static class WifiFrames
{
    public static byte[]? ToEthernet(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < 24)
            return null;

        var frameControl = frame[0];
        var flags = frame[1];
        var type = (frameControl >> 2) & 0x3;
        var subtype = frameControl >> 4;
        if (type != 2 || (subtype & 0x4) != 0)
            return null;

        var toDistribution = (flags & 0x01) != 0;
        var fromDistribution = (flags & 0x02) != 0;
        var headerLength = 24;
        if (toDistribution && fromDistribution)
            headerLength += 6;
        var isQos = (subtype & 0x8) != 0;
        if (isQos)
            headerLength += 2;
        if (isQos && (flags & 0x80) != 0)
            headerLength += 4;

        // LLC/SNAP: AA AA 03 00 00 00, then the EtherType.
        if (frame.Length < headerLength + 8 || frame[headerLength] != 0xAA || frame[headerLength + 1] != 0xAA || frame[headerLength + 2] != 0x03)
            return null;

        // Which of the up to four addresses are the real destination and source depends on the to/from DS bits.
        var destinationOffset = toDistribution ? 16 : 4;
        var sourceOffset = (toDistribution, fromDistribution) switch
        {
            (false, false) => 10,
            (false, true) => 16,
            (true, false) => 10,
            _ => 24
        };
        var destination = frame.Slice(destinationOffset, 6);
        var source = frame.Slice(sourceOffset, 6);

        var payload = frame[(headerLength + 6)..];
        var ethernet = new byte[12 + payload.Length];
        destination.CopyTo(ethernet);
        source.CopyTo(ethernet.AsSpan(6));
        payload.CopyTo(ethernet.AsSpan(12));
        return ethernet;
    }
}
