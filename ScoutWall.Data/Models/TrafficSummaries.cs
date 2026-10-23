namespace ScoutWall.Data.Models;

/// <summary>
/// One aggregated conversation count produced by the sensor for a time bucket. Not persisted directly.
/// </summary>
public class TrafficCount
{
    public long BucketStart { get; set; }
    public string RemoteIp { get; set; } = string.Empty;
    public string LocalIp { get; set; } = string.Empty;
    public int ServicePort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public TrafficDirection Direction { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long PacketsIn { get; set; }
    public long PacketsOut { get; set; }
    public long ConnectionCount { get; set; }

    public TrafficCount MoveToBucket(int bucketSeconds)
    {
        var trafficCount = (TrafficCount)MemberwiseClone();
        trafficCount.BucketStart = BucketStart - BucketStart % bucketSeconds;
        return trafficCount;
    }
}

public class TrafficTotals
{
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long PacketsIn { get; set; }
    public long PacketsOut { get; set; }
    public long ConnectionCount { get; set; }
    public long InboundConnectionCount { get; set; }
    public int UniqueRemoteAddresses { get; set; }
}

public class TrafficTimelinePoint
{
    public long BucketStart { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long ConnectionCount { get; set; }
}

public class AddressSummary
{
    public string IpAddress { get; set; } = string.Empty;
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long PacketCount { get; set; }
    public long ConnectionCount { get; set; }
    public int ServiceCount { get; set; }

    public IpAddressProfile? Profile { get; set; }
    public string? Hostname { get; set; }

    public long TotalBytes => BytesIn + BytesOut;
}

public class ServiceSummary
{
    public int ServicePort { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public TrafficDirection Direction { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long ConnectionCount { get; set; }
    public int RemoteAddressCount { get; set; }

    public long TotalBytes => BytesIn + BytesOut;
    public string ServiceName => ServiceNames.Describe(ServicePort, Protocol);
}

public class CountrySummary
{
    public string CountryCode { get; set; } = string.Empty;
    public string CountryName { get; set; } = string.Empty;
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public long ConnectionCount { get; set; }
    public int RemoteAddressCount { get; set; }

    public long TotalBytes => BytesIn + BytesOut;
}

public class LocationSummary
{
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public string? City { get; set; }
    public string? CountryName { get; set; }
    public long BytesIn { get; set; }
    public long BytesOut { get; set; }
    public int RemoteAddressCount { get; set; }

    /// <summary>
    /// The address that moved the most data at this place, so the map can link somewhere useful.
    /// </summary>
    public string LargestAddress { get; set; } = string.Empty;

    public long TotalBytes => BytesIn + BytesOut;
    public string PlaceName => string.Join(", ", new[] { City, CountryName }.Where(part => !string.IsNullOrWhiteSpace(part))) is { Length: > 0 } name ? name : "Unknown place";
}

public static class ServiceNames
{
    private static readonly Dictionary<int, string> KnownPorts = new()
    {
        [20] = "FTP data", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS",
        [67] = "DHCP", [68] = "DHCP", [80] = "HTTP", [110] = "POP3", [123] = "NTP", [135] = "MS RPC",
        [137] = "NetBIOS", [138] = "NetBIOS", [139] = "NetBIOS", [143] = "IMAP", [161] = "SNMP",
        [389] = "LDAP", [443] = "HTTPS", [445] = "SMB", [465] = "SMTPS", [500] = "IKE", [514] = "Syslog",
        [587] = "SMTP submission", [636] = "LDAPS", [853] = "DNS over TLS", [993] = "IMAPS", [995] = "POP3S",
        [1194] = "OpenVPN", [1433] = "SQL Server", [1883] = "MQTT", [1900] = "SSDP", [3306] = "MySQL",
        [3389] = "RDP", [4500] = "IPsec NAT-T", [5060] = "SIP", [5353] = "mDNS", [5355] = "LLMNR",
        [5432] = "PostgreSQL", [5900] = "VNC", [5985] = "WinRM", [5986] = "WinRM", [6379] = "Redis",
        [8080] = "HTTP alt", [8443] = "HTTPS alt", [9200] = "Elasticsearch", [27017] = "MongoDB",
        [51820] = "WireGuard"
    };

    public static string Describe(int port, string protocol)
    {
        if (protocol.StartsWith("ICMP", StringComparison.OrdinalIgnoreCase))
            return protocol;

        if (protocol == "UDP" && port == 443)
            return "QUIC";

        return KnownPorts.TryGetValue(port, out var serviceName) ? serviceName : $"{protocol}/{port}";
    }
}
