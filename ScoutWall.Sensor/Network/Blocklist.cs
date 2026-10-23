using System.Net;

namespace ScoutWall.Sensor.Network;

/// <summary>
/// Known-bad addresses and ranges from threat feeds and the static list in settings. Immutable; replaced on refresh.
/// </summary>
public class Blocklist
{
    private readonly Dictionary<IPAddress, string> addresses;
    private readonly List<(IpNetwork Network, string Source)> networks;

    private Blocklist(Dictionary<IPAddress, string> addresses, List<(IpNetwork Network, string Source)> networks)
    {
        this.addresses = addresses;
        this.networks = networks;
    }

    public static Blocklist Empty { get; } = new([], []);

    public int Count => addresses.Count + networks.Count;

    /// <summary>
    /// Builds a blocklist from feed text. Each line holds an address or CIDR range; anything after
    /// '#' or ';' is a comment, which covers the abuse.ch and Spamhaus DROP formats.
    /// </summary>
    public static Blocklist Build(IEnumerable<(string Source, string Content)> feeds)
    {
        var addresses = new Dictionary<IPAddress, string>();
        var networks = new List<(IpNetwork Network, string Source)>();

        foreach (var (source, content) in feeds)
        {
            foreach (var line in content.Split('\n'))
                AddLine(line, source, addresses, networks);
        }

        return new Blocklist(addresses, networks);
    }

    public string? FindSource(IPAddress address)
    {
        if (addresses.TryGetValue(address, out var source))
            return source;

        foreach (var (network, networkSource) in networks)
        {
            if (network.Contains(address))
                return networkSource;
        }

        return null;
    }

    private static void AddLine(
        string line,
        string source,
        Dictionary<IPAddress, string> addresses,
        List<(IpNetwork Network, string Source)> networks)
    {
        var entry = line.Split('#', ';')[0].Trim();
        if (!IpNetwork.TryParse(entry, out var ipNetwork))
            return;

        var isSingleAddress = ipNetwork!.PrefixLength == (ipNetwork.NetworkAddress.GetAddressBytes().Length * 8);
        if (isSingleAddress)
            addresses.TryAdd(ipNetwork.NetworkAddress, source);
        else
            networks.Add((ipNetwork, source));
    }
}
