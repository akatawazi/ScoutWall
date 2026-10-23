using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Channels;
using PacketDotNet;

namespace ScoutWall.Sensor.Capture;

/// <summary>
/// Generates realistic traffic for demos and development without Npcap: browsing with DNS and TLS
/// ClientHellos, inbound SSH probing, a periodic port scan and occasional large uploads.
/// </summary>
public class SyntheticPacketSource : IPacketSource
{
    private static readonly PhysicalAddress LocalMac = PhysicalAddress.Parse("02-00-5E-10-00-01");
    private static readonly PhysicalAddress GatewayMac = PhysicalAddress.Parse("02-00-5E-10-00-FE");
    private static readonly IPAddress DnsServer = IPAddress.Parse("192.168.1.1");
    private static readonly IPAddress Scanner = IPAddress.Parse("45.33.32.156");
    private static readonly IPAddress[] SshProbers = [IPAddress.Parse("218.92.0.107"), IPAddress.Parse("61.177.172.140"), IPAddress.Parse("185.220.101.34")];

    private static readonly (string Hostname, IPAddress Address)[] Sites =
    [
        ("www.google.com", IPAddress.Parse("142.250.72.100")),
        ("github.com", IPAddress.Parse("140.82.112.3")),
        ("www.microsoft.com", IPAddress.Parse("23.45.229.117")),
        ("login.microsoftonline.com", IPAddress.Parse("20.190.151.68")),
        ("www.reddit.com", IPAddress.Parse("151.101.1.140")),
        ("one.one.one.one", IPAddress.Parse("1.1.1.1")),
        ("www.bbc.co.uk", IPAddress.Parse("151.101.0.81")),
        ("api.spotify.com", IPAddress.Parse("35.186.224.25")),
        ("telemetry.example-vendor.cn", IPAddress.Parse("47.95.164.112")),
        ("files.storage-sync.ru", IPAddress.Parse("95.213.255.5"))
    ];

    private readonly Random random = new();
    private readonly IPAddress localAddress;
    private ushort nextClientPort = 50000;
    private ushort nextDnsId = 1;

    public SyntheticPacketSource()
    {
        localAddress = FindLocalAddress();
    }

    public string Name => "Synthetic";

    public async Task Run(ChannelWriter<CapturedFrame> frameWriter, CaptureStatistics captureStatistics, CancellationToken cancellationToken)
    {
        var tick = 0L;
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(200));

        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            tick++;
            foreach (var frameData in GenerateTick(tick))
            {
                var capturedFrame = new CapturedFrame(DateTime.UtcNow, LinkLayers.Ethernet, frameData, frameData.Length, Name);
                if (!frameWriter.TryWrite(capturedFrame))
                    captureStatistics.RecordDropped();
            }
        }
    }

    private IEnumerable<byte[]> GenerateTick(long tick)
    {
        var frames = new List<byte[]>();

        if (random.Next(3) == 0)
            frames.AddRange(BrowseSite());

        if (tick % 25 == 0)
            frames.Add(SshProbe());

        if (tick % 450 == 100)
            frames.AddRange(PortScan());

        if (tick % 600 == 300)
            frames.AddRange(LargeUpload());

        return frames;
    }

    private IEnumerable<byte[]> BrowseSite()
    {
        var (hostname, siteAddress) = Sites[random.Next(Sites.Length)];
        var dnsPort = NextClientPort();
        var clientPort = NextClientPort();
        var dnsId = nextDnsId++;

        yield return BuildUdp(localAddress, dnsPort, DnsServer, 53, BuildDnsMessage(dnsId, hostname, null));
        yield return BuildUdp(DnsServer, 53, localAddress, dnsPort, BuildDnsMessage(dnsId, hostname, siteAddress));
        yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: true, acknowledge: false, []);
        yield return BuildTcp(siteAddress, 443, localAddress, clientPort, synchronize: true, acknowledge: true, []);
        yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: false, acknowledge: true, BuildClientHello(hostname));

        var responseCount = random.Next(3, 25);
        for (var index = 0; index < responseCount; index++)
            yield return BuildTcp(siteAddress, 443, localAddress, clientPort, synchronize: false, acknowledge: true, RandomPayload(1400));

        yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: false, acknowledge: true, RandomPayload(random.Next(80, 600)));
    }

    private byte[] SshProbe()
    {
        var prober = SshProbers[random.Next(SshProbers.Length)];
        return BuildTcp(prober, (ushort)random.Next(30000, 60000), localAddress, 22, synchronize: true, acknowledge: false, []);
    }

    private IEnumerable<byte[]> PortScan()
    {
        var scannerPort = (ushort)random.Next(40000, 60000);
        for (ushort port = 1; port <= 120; port++)
            yield return BuildTcp(Scanner, scannerPort, localAddress, port, synchronize: true, acknowledge: false, []);
    }

    private IEnumerable<byte[]> LargeUpload()
    {
        var (_, siteAddress) = Sites[^1];
        var clientPort = NextClientPort();
        yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: true, acknowledge: false, []);
        yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: false, acknowledge: true, BuildClientHello("files.storage-sync.ru"));

        for (var index = 0; index < 400; index++)
            yield return BuildTcp(localAddress, clientPort, siteAddress, 443, synchronize: false, acknowledge: true, RandomPayload(1400));
    }

    private ushort NextClientPort()
    {
        nextClientPort = nextClientPort >= 65000 ? (ushort)50000 : (ushort)(nextClientPort + 1);
        return nextClientPort;
    }

    private byte[] RandomPayload(int length)
    {
        var payload = new byte[length];
        random.NextBytes(payload);
        payload[0] = 0x17;
        return payload;
    }

    private static byte[] BuildTcp(IPAddress source, ushort sourcePort, IPAddress destination, ushort destinationPort, bool synchronize, bool acknowledge, byte[] payload)
    {
        var tcpPacket = new TcpPacket(sourcePort, destinationPort)
        {
            Synchronize = synchronize,
            Acknowledgment = acknowledge,
            WindowSize = 64240,
            PayloadData = payload
        };
        return WrapInFrame(source, destination, tcpPacket);
    }

    private static byte[] BuildUdp(IPAddress source, ushort sourcePort, IPAddress destination, ushort destinationPort, byte[] payload)
    {
        var udpPacket = new UdpPacket(sourcePort, destinationPort) { PayloadData = payload };
        return WrapInFrame(source, destination, udpPacket);
    }

    private static byte[] WrapInFrame(IPAddress source, IPAddress destination, Packet transportPacket)
    {
        var ipPacket = new IPv4Packet(source, destination) { TimeToLive = 64, PayloadPacket = transportPacket };
        var ethernetPacket = new EthernetPacket(LocalMac, GatewayMac, EthernetType.IPv4) { PayloadPacket = ipPacket };
        ipPacket.UpdateCalculatedValues();
        transportPacket.UpdateCalculatedValues();
        ipPacket.UpdateIPChecksum();
        return ethernetPacket.Bytes;
    }

    public static byte[] BuildDnsMessage(ushort id, string hostname, IPAddress? answer)
    {
        var message = new List<byte>();
        message.AddRange([(byte)(id >> 8), (byte)id]);
        message.AddRange(answer == null ? [0x01, 0x00] : [0x81, 0x80]);
        message.AddRange([0x00, 0x01, 0x00, (byte)(answer == null ? 0 : 1), 0x00, 0x00, 0x00, 0x00]);

        foreach (var label in hostname.Split('.'))
        {
            message.Add((byte)label.Length);
            message.AddRange(Encoding.ASCII.GetBytes(label));
        }

        message.AddRange([0x00, 0x00, 0x01, 0x00, 0x01]);

        if (answer != null)
        {
            message.AddRange([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
            message.AddRange(answer.GetAddressBytes());
        }

        return message.ToArray();
    }

    public static byte[] BuildClientHello(string serverName)
    {
        var serverNameBytes = Encoding.ASCII.GetBytes(serverName);
        var extensions = new List<byte>();

        var serverNameList = new List<byte> { 0x00 };
        serverNameList.AddRange(UInt16Bytes(serverNameBytes.Length));
        serverNameList.AddRange(serverNameBytes);
        AddExtension(extensions, 0x0000, [.. UInt16Bytes(serverNameList.Count), .. serverNameList]);

        byte[] protocolList = [0x02, (byte)'h', (byte)'2', 0x08, .. "http/1.1"u8.ToArray()];
        AddExtension(extensions, 0x0010, [.. UInt16Bytes(protocolList.Length), .. protocolList]);
        AddExtension(extensions, 0x002B, [0x06, 0x0A, 0x0A, 0x03, 0x04, 0x03, 0x03]);

        var body = new List<byte> { 0x03, 0x03 };
        body.AddRange(new byte[32]);
        body.Add(0x00);
        body.AddRange([0x00, 0x02, 0x13, 0x01]);
        body.AddRange([0x01, 0x00]);
        body.AddRange(UInt16Bytes(extensions.Count));
        body.AddRange(extensions);

        var handshake = new List<byte> { 0x01, 0x00 };
        handshake.AddRange(UInt16Bytes(body.Count));
        handshake.AddRange(body);

        var record = new List<byte> { 0x16, 0x03, 0x01 };
        record.AddRange(UInt16Bytes(handshake.Count));
        record.AddRange(handshake);
        return record.ToArray();
    }

    private static void AddExtension(List<byte> extensions, int extensionType, byte[] data)
    {
        extensions.AddRange(UInt16Bytes(extensionType));
        extensions.AddRange(UInt16Bytes(data.Length));
        extensions.AddRange(data);
    }

    private static byte[] UInt16Bytes(int value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)value);
        return bytes;
    }

    private static IPAddress FindLocalAddress()
    {
        var hostAddress = NetworkInterface.GetAllNetworkInterfaces()
            .Where(networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .SelectMany(networkInterface => networkInterface.GetIPProperties().UnicastAddresses)
            .Select(unicastAddress => unicastAddress.Address)
            .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);

        return hostAddress ?? IPAddress.Parse("192.168.1.50");
    }
}
