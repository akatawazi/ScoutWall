using System.Net;
using System.Net.Sockets;

namespace ScoutWall.Sensor.Network;

/// <summary>
/// An address range in CIDR notation, for example 192.168.0.0/16 or fd00::/8.
/// </summary>
public class IpNetwork
{
    private readonly byte[] networkBytes;

    public IpNetwork(IPAddress networkAddress, int prefixLength)
    {
        NetworkAddress = networkAddress;
        PrefixLength = prefixLength;
        networkBytes = networkAddress.GetAddressBytes();
    }

    public IPAddress NetworkAddress { get; }
    public int PrefixLength { get; }

    public static readonly IReadOnlyList<IpNetwork> PrivateRanges =
    [
        Parse("10.0.0.0/8"),
        Parse("172.16.0.0/12"),
        Parse("192.168.0.0/16"),
        Parse("127.0.0.0/8"),
        Parse("169.254.0.0/16"),
        Parse("100.64.0.0/10"),
        Parse("224.0.0.0/4"),
        Parse("255.255.255.255/32"),
        Parse("0.0.0.0/8"),
        Parse("::1/128"),
        Parse("fc00::/7"),
        Parse("fe80::/10"),
        Parse("ff00::/8")
    ];

    public static IpNetwork Parse(string text)
    {
        if (!TryParse(text, out var ipNetwork))
            throw new FormatException($"'{text}' is not a valid address or CIDR range.");

        return ipNetwork!;
    }

    public static bool TryParse(string? text, out IpNetwork? ipNetwork)
    {
        ipNetwork = null;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        var parts = text.Trim().Split('/');
        if (!IPAddress.TryParse(parts[0], out var address))
            return false;

        var maximumPrefix = address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        var prefixLength = maximumPrefix;
        if (parts.Length > 1 && (!int.TryParse(parts[1], out prefixLength) || prefixLength < 0 || prefixLength > maximumPrefix))
            return false;

        ipNetwork = new IpNetwork(address, prefixLength);
        return true;
    }

    public static bool IsPrivate(IPAddress address)
    {
        var normalizedAddress = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return PrivateRanges.Any(range => range.Contains(normalizedAddress));
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != NetworkAddress.AddressFamily)
            return false;

        var addressBytes = address.GetAddressBytes();
        var fullBytes = PrefixLength / 8;
        for (var index = 0; index < fullBytes; index++)
        {
            if (addressBytes[index] != networkBytes[index])
                return false;
        }

        var remainingBits = PrefixLength % 8;
        if (remainingBits == 0)
            return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (addressBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
    }

    public override string ToString()
    {
        return $"{NetworkAddress}/{PrefixLength}";
    }
}
