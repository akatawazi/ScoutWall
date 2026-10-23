using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace ScoutWall.Sensor.Network;

public record HostInterface(string Name, string Description, string Addresses, bool IsVirtualOverlay);

/// <summary>
/// Facts about this computer that explain a lot of its traffic: domain membership, DNS suffixes, network
/// adapters and overlay networks such as ZeroTier or Tailscale. Shared with the analyst agent as context.
/// </summary>
public class HostContext
{
    private static readonly string[] OverlayMarkers = ["ZeroTier", "Tailscale", "WireGuard", "OpenVPN", "TAP-Windows", "Hyper-V", "VirtualBox", "VMware", "WSL"];

    public string MachineName { get; init; } = Environment.MachineName;
    public string OperatingSystem { get; init; } = RuntimeInformation.OSDescription;
    public string? DomainName { get; init; }
    public bool IsDomainJoined => !string.IsNullOrEmpty(DomainName);
    public List<string> SearchSuffixes { get; init; } = [];
    public List<HostInterface> Interfaces { get; init; } = [];

    /// <summary>
    /// Suffixes Windows appends to short names. A short name plus one of these resolving to a public address
    /// means company-internal lookups (WPAD, printers, file servers) are leaking to the internet.
    /// </summary>
    public IReadOnlyList<string> InternalSuffixes => SearchSuffixes
        .Append(DomainName ?? string.Empty)
        .Where(suffix => !string.IsNullOrWhiteSpace(suffix) && !suffix.EndsWith(".ts.net", StringComparison.OrdinalIgnoreCase))
        .Select(suffix => suffix.Trim('.').ToLowerInvariant())
        .Distinct()
        .ToList();

    public IEnumerable<string> Overlays => Interfaces.Where(item => item.IsVirtualOverlay).Select(item => item.Description).Distinct();

    public static HostContext Gather()
    {
        return new HostContext
        {
            DomainName = ReadDomainName(),
            SearchSuffixes = ReadSearchSuffixes(),
            Interfaces = ReadInterfaces()
        };
    }

    /// <summary>
    /// The single label in front of an internal suffix ("wpad" for wpad.ad.example.com), or null.
    /// </summary>
    public string? MatchInternalShortName(string hostname)
    {
        foreach (var suffix in InternalSuffixes)
        {
            if (!hostname.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                continue;

            var shortName = hostname[..^(suffix.Length + 1)];
            if (shortName.Length > 0 && !shortName.Contains('.'))
                return shortName;
        }

        return null;
    }

    public string Describe()
    {
        var lines = new List<string>
        {
            $"Computer: {MachineName} ({OperatingSystem})",
            IsDomainJoined ? $"Joined to Active Directory domain {DomainName}" : "Not joined to a domain",
            $"DNS search suffixes: {(SearchSuffixes.Count == 0 ? "none" : string.Join(", ", SearchSuffixes))}",
            $"Overlay / virtual networks: {(Overlays.Any() ? string.Join(", ", Overlays) : "none")}",
            "Active network adapters:"
        };
        lines.AddRange(Interfaces.Select(item => $"  - {item.Name}: {item.Description} [{item.Addresses}]"));
        return string.Join("\n", lines);
    }

    private static string? ReadDomainName()
    {
        try
        {
            var domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            return string.IsNullOrWhiteSpace(domainName) ? null : domainName;
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    private static List<string> ReadSearchSuffixes()
    {
        if (!System.OperatingSystem.IsWindows())
            return [];

        using var parameters = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
        var searchList = parameters?.GetValue("SearchList") as string ?? string.Empty;
        return searchList.Split(',', ' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
    }

    private static List<HostInterface> ReadInterfaces()
    {
        return NetworkInterface.GetAllNetworkInterfaces()
            .Where(networkInterface => networkInterface.OperationalStatus == OperationalStatus.Up
                && networkInterface.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(networkInterface => new HostInterface(
                networkInterface.Name,
                networkInterface.Description,
                string.Join(", ", networkInterface.GetIPProperties().UnicastAddresses.Select(address => address.Address.ToString())),
                OverlayMarkers.Any(marker => networkInterface.Description.Contains(marker, StringComparison.OrdinalIgnoreCase)
                    || networkInterface.Name.Contains(marker, StringComparison.OrdinalIgnoreCase))))
            .ToList();
    }
}
