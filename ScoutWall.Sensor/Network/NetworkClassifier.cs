using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ScoutWall.Sensor.Network;

/// <summary>
/// Decides which addresses belong to this machine and its local networks, and which must never be blocked.
/// Built from the configured local networks plus the subnets, gateways and DNS servers of the host's interfaces.
/// </summary>
public class NetworkClassifier
{
    private readonly List<IpNetwork> localNetworks;
    private readonly HashSet<IPAddress> hostAddresses;
    private readonly HashSet<IPAddress> protectedAddresses;

    private NetworkClassifier(List<IpNetwork> localNetworks, HashSet<IPAddress> hostAddresses, HashSet<IPAddress> protectedAddresses)
    {
        this.localNetworks = localNetworks;
        this.hostAddresses = hostAddresses;
        this.protectedAddresses = protectedAddresses;
    }

    public IReadOnlyCollection<IPAddress> HostAddresses => hostAddresses;
    public IReadOnlyCollection<IPAddress> ProtectedAddresses => protectedAddresses;

    public static NetworkClassifier Build(IEnumerable<string> configuredLocalNetworks)
    {
        var localNetworks = new List<IpNetwork>();
        var hostAddresses = new HashSet<IPAddress> { IPAddress.Loopback, IPAddress.IPv6Loopback };
        var protectedAddresses = new HashSet<IPAddress>();

        foreach (var configuredNetwork in configuredLocalNetworks)
        {
            if (IpNetwork.TryParse(configuredNetwork, out var ipNetwork))
                localNetworks.Add(ipNetwork!);
        }

        foreach (var networkInterface in GetActiveInterfaces())
            AddInterface(networkInterface, localNetworks, hostAddresses, protectedAddresses);

        return new NetworkClassifier(localNetworks, hostAddresses, protectedAddresses);
    }

    public bool IsLocal(IPAddress address)
    {
        return hostAddresses.Contains(address)
            || IPAddress.IsLoopback(address)
            || localNetworks.Any(ipNetwork => ipNetwork.Contains(address));
    }

    public bool IsHostAddress(IPAddress address)
    {
        return hostAddresses.Contains(address) || IPAddress.IsLoopback(address);
    }

    /// <summary>
    /// Addresses that blocking would cut the machine off from: its own, its gateways and DNS servers,
    /// anything private and anything on a local network.
    /// </summary>
    public bool IsProtected(IPAddress address)
    {
        return protectedAddresses.Contains(address) || IsLocal(address) || IpNetwork.IsPrivate(address);
    }

    private static IEnumerable<NetworkInterface> GetActiveInterfaces()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up);
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    private static void AddInterface(
        NetworkInterface networkInterface,
        List<IpNetwork> localNetworks,
        HashSet<IPAddress> hostAddresses,
        HashSet<IPAddress> protectedAddresses)
    {
        var properties = networkInterface.GetIPProperties();

        foreach (var unicastAddress in properties.UnicastAddresses)
        {
            hostAddresses.Add(unicastAddress.Address);
            if (unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork || !unicastAddress.Address.IsIPv6LinkLocal)
                localNetworks.Add(new IpNetwork(NetworkAddressOf(unicastAddress), unicastAddress.PrefixLength));
        }

        foreach (var gatewayAddress in properties.GatewayAddresses)
            protectedAddresses.Add(gatewayAddress.Address);

        foreach (var dnsAddress in properties.DnsAddresses)
            protectedAddresses.Add(dnsAddress);
    }

    private static IPAddress NetworkAddressOf(UnicastIPAddressInformation unicastAddress)
    {
        var addressBytes = unicastAddress.Address.GetAddressBytes();
        var prefixLength = unicastAddress.PrefixLength;

        for (var index = 0; index < addressBytes.Length; index++)
        {
            var bitsInByte = Math.Clamp(prefixLength - index * 8, 0, 8);
            addressBytes[index] &= (byte)(0xFF << (8 - bitsInByte));
        }

        return new IPAddress(addressBytes);
    }
}
