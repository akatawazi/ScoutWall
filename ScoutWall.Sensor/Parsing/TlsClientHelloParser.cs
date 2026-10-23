using System.Text;

namespace ScoutWall.Sensor.Parsing;

public record TlsClientHello(string? ServerName, string TlsVersion, string? ApplicationProtocols);

/// <summary>
/// Reads the unencrypted metadata from a TLS ClientHello record: SNI, ALPN and the highest offered version.
/// Note that Encrypted Client Hello hides the real server name, and TLS 1.3 hides the server certificate.
/// </summary>
public static class TlsClientHelloParser
{
    private const int RecordHeaderLength = 5;
    private const byte HandshakeContentType = 0x16;
    private const byte ClientHelloHandshakeType = 0x01;
    private const int ServerNameExtension = 0;
    private const int ApplicationProtocolExtension = 16;
    private const int SupportedVersionsExtension = 43;

    public static bool LooksLikeClientHello(ReadOnlySpan<byte> payload)
    {
        return payload.Length >= 6
            && payload[0] == HandshakeContentType
            && payload[1] == 0x03
            && payload[5] == ClientHelloHandshakeType;
    }

    /// <summary>
    /// Total length of the TLS record including its header, used to reassemble ClientHellos split over segments.
    /// </summary>
    public static int GetRecordLength(ReadOnlySpan<byte> payload)
    {
        return RecordHeaderLength + ((payload[3] << 8) | payload[4]);
    }

    public static TlsClientHello? Parse(ReadOnlySpan<byte> record)
    {
        if (!LooksLikeClientHello(record))
            return null;

        try
        {
            return ParseUnchecked(record);
        }
        catch (Exception exception) when (exception is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static TlsClientHello ParseUnchecked(ReadOnlySpan<byte> record)
    {
        var offset = RecordHeaderLength + 4;
        var legacyVersion = ReadUInt16(record, offset);
        offset += 2 + 32;
        offset += 1 + record[offset];
        offset += 2 + ReadUInt16(record, offset);
        offset += 1 + record[offset];

        var extensionsEnd = Math.Min(record.Length, offset + 2 + ReadUInt16(record, offset));
        offset += 2;

        string? serverName = null;
        string? applicationProtocols = null;
        var highestVersion = legacyVersion;

        while (offset + 4 <= extensionsEnd)
        {
            var extensionType = ReadUInt16(record, offset);
            var extensionLength = ReadUInt16(record, offset + 2);
            var extensionData = record.Slice(offset + 4, extensionLength);
            offset += 4 + extensionLength;

            if (extensionType == ServerNameExtension)
                serverName = ReadServerName(extensionData);
            else if (extensionType == ApplicationProtocolExtension)
                applicationProtocols = ReadApplicationProtocols(extensionData);
            else if (extensionType == SupportedVersionsExtension)
                highestVersion = ReadHighestVersion(extensionData, highestVersion);
        }

        return new TlsClientHello(serverName, DescribeVersion(highestVersion), applicationProtocols);
    }

    private static string? ReadServerName(ReadOnlySpan<byte> extensionData)
    {
        var nameType = extensionData[2];
        if (nameType != 0)
            return null;

        var nameLength = ReadUInt16(extensionData, 3);
        return Encoding.ASCII.GetString(extensionData.Slice(5, nameLength)).ToLowerInvariant();
    }

    private static string ReadApplicationProtocols(ReadOnlySpan<byte> extensionData)
    {
        var protocols = new List<string>();
        var listEnd = 2 + ReadUInt16(extensionData, 0);
        var offset = 2;

        while (offset < listEnd)
        {
            var protocolLength = extensionData[offset];
            protocols.Add(Encoding.ASCII.GetString(extensionData.Slice(offset + 1, protocolLength)));
            offset += 1 + protocolLength;
        }

        return string.Join(",", protocols);
    }

    private static int ReadHighestVersion(ReadOnlySpan<byte> extensionData, int currentVersion)
    {
        var highestVersion = currentVersion;
        var listLength = extensionData[0];

        for (var offset = 1; offset + 1 <= listLength; offset += 2)
        {
            var version = ReadUInt16(extensionData, offset);
            if (!IsGreaseValue(version) && version > highestVersion && version <= 0x0304)
                highestVersion = version;
        }

        return highestVersion;
    }

    /// <summary>
    /// GREASE values (RFC 8701) are random placeholders browsers insert; they are not real versions.
    /// </summary>
    private static bool IsGreaseValue(int value)
    {
        return (value & 0x0F0F) == 0x0A0A;
    }

    private static string DescribeVersion(int version)
    {
        return version switch
        {
            0x0304 => "TLS 1.3",
            0x0303 => "TLS 1.2",
            0x0302 => "TLS 1.1",
            0x0301 => "TLS 1.0",
            0x0300 => "SSL 3.0",
            _ => $"0x{version:X4}"
        };
    }

    private static int ReadUInt16(ReadOnlySpan<byte> data, int offset)
    {
        return (data[offset] << 8) | data[offset + 1];
    }
}
