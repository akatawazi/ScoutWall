using System.Net;
using System.Net.NetworkInformation;

namespace ScoutWall.Data;

/// <summary>
/// The addresses this computer depends on: its own addresses, gateways and DNS servers.
/// </summary>
public static class HostNetwork
{
    public static HashSet<IPAddress> ProtectedAddresses()
    {
        var protectedAddresses = new HashSet<IPAddress>();
        foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces().Where(item => item.OperationalStatus == OperationalStatus.Up))
        {
            var properties = networkInterface.GetIPProperties();
            protectedAddresses.UnionWith(properties.UnicastAddresses.Select(address => address.Address));
            protectedAddresses.UnionWith(properties.GatewayAddresses.Select(gateway => gateway.Address));
            protectedAddresses.UnionWith(properties.DnsAddresses);
        }

        return protectedAddresses;
    }

    /// <summary>
    /// Whether an address or CIDR range written in settings contains the address.
    /// </summary>
    public static bool RangeContains(string range, IPAddress address)
    {
        var parts = range.Split('/');
        if (!IPAddress.TryParse(parts[0], out var networkAddress) || networkAddress.AddressFamily != address.AddressFamily)
            return false;

        var networkBytes = networkAddress.GetAddressBytes();
        var addressBytes = address.GetAddressBytes();
        var prefixLength = parts.Length > 1 && int.TryParse(parts[1], out var prefix) ? prefix : networkBytes.Length * 8;

        for (var bit = 0; bit < prefixLength; bit++)
        {
            var mask = 0x80 >> (bit % 8);
            if ((networkBytes[bit / 8] & mask) != (addressBytes[bit / 8] & mask))
                return false;
        }

        return true;
    }
}
