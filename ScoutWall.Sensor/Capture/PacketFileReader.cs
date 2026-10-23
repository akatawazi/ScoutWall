using System.Buffers.Binary;
using PacketDotNet;

namespace ScoutWall.Sensor.Capture;

/// <summary>
/// Reads classic pcap and pcapng capture files directly, so offline analysis does not depend on Npcap.
/// </summary>
public static class PacketFileReader
{
    private const uint PcapMagicMicroseconds = 0xA1B2C3D4;
    private const uint PcapMagicNanoseconds = 0xA1B23C4D;
    private const uint PcapNextGenerationSectionHeader = 0x0A0D0D0A;
    private const uint PcapNextGenerationByteOrderMagic = 0x1A2B3C4D;
    private const uint InterfaceDescriptionBlock = 1;
    private const uint SimplePacketBlock = 3;
    private const uint EnhancedPacketBlock = 6;

    public static IEnumerable<CapturedFrame> Read(Stream stream, string interfaceName)
    {
        var reader = new BinaryReader(stream);
        var magic = reader.ReadUInt32();
        stream.Position = 0;

        if (magic == PcapNextGenerationSectionHeader)
            return ReadNextGeneration(reader, interfaceName);

        return ReadClassic(reader, interfaceName);
    }

    private static IEnumerable<CapturedFrame> ReadClassic(BinaryReader reader, string interfaceName)
    {
        var header = reader.ReadBytes(24);
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(header);
        var isLittleEndian = magic is PcapMagicMicroseconds or PcapMagicNanoseconds;
        var magicValue = isLittleEndian ? magic : BinaryPrimitives.ReverseEndianness(magic);
        if (magicValue is not (PcapMagicMicroseconds or PcapMagicNanoseconds))
            throw new InvalidDataException("Not a pcap or pcapng file.");

        var fractionPerSecond = magicValue == PcapMagicNanoseconds ? 1_000_000_000L : 1_000_000L;
        var linkType = (LinkLayers)ReadUInt32(header.AsSpan(20), isLittleEndian);

        while (reader.BaseStream.Position + 16 <= reader.BaseStream.Length)
        {
            var recordHeader = reader.ReadBytes(16);
            var seconds = ReadUInt32(recordHeader, isLittleEndian);
            var fraction = ReadUInt32(recordHeader.AsSpan(4), isLittleEndian);
            var capturedLength = (int)ReadUInt32(recordHeader.AsSpan(8), isLittleEndian);
            var originalLength = (int)ReadUInt32(recordHeader.AsSpan(12), isLittleEndian);
            var data = reader.ReadBytes(capturedLength);
            if (data.Length < capturedLength)
                yield break;

            var timestamp = DateTime.UnixEpoch.AddSeconds(seconds).AddTicks(fraction * TimeSpan.TicksPerSecond / fractionPerSecond);
            yield return new CapturedFrame(timestamp, linkType, data, originalLength, interfaceName);
        }
    }

    private static IEnumerable<CapturedFrame> ReadNextGeneration(BinaryReader reader, string interfaceName)
    {
        var isLittleEndian = true;
        var interfaces = new List<(LinkLayers LinkType, long TicksPerUnit)>();

        while (reader.BaseStream.Position + 12 <= reader.BaseStream.Length)
        {
            var blockStart = reader.BaseStream.Position;
            var blockType = reader.ReadUInt32();
            var lengthBytes = reader.ReadBytes(4);

            if (blockType == PcapNextGenerationSectionHeader)
            {
                var byteOrderMagic = reader.ReadUInt32();
                isLittleEndian = byteOrderMagic == PcapNextGenerationByteOrderMagic;
                interfaces.Clear();
            }

            var blockLength = ReadUInt32(lengthBytes, isLittleEndian);
            if (blockLength < 12 || blockStart + blockLength > reader.BaseStream.Length)
                yield break;

            reader.BaseStream.Position = blockStart + 8;
            var body = reader.ReadBytes((int)blockLength - 12);
            reader.BaseStream.Position = blockStart + blockLength;

            var capturedFrame = ReadNextGenerationBlock(blockType, body, isLittleEndian, interfaces, interfaceName);
            if (capturedFrame != null)
                yield return capturedFrame;
        }
    }

    private static CapturedFrame? ReadNextGenerationBlock(
        uint blockType,
        byte[] body,
        bool isLittleEndian,
        List<(LinkLayers LinkType, long TicksPerUnit)> interfaces,
        string interfaceName)
    {
        if (blockType == InterfaceDescriptionBlock)
        {
            var linkType = (LinkLayers)ReadUInt16(body, isLittleEndian);
            interfaces.Add((linkType, ReadTimestampResolution(body, isLittleEndian)));
            return null;
        }

        if (blockType == EnhancedPacketBlock)
        {
            var interfaceId = (int)ReadUInt32(body, isLittleEndian);
            var timestampHigh = (long)ReadUInt32(body.AsSpan(4), isLittleEndian);
            var timestampLow = (long)ReadUInt32(body.AsSpan(8), isLittleEndian);
            var capturedLength = (int)ReadUInt32(body.AsSpan(12), isLittleEndian);
            var originalLength = (int)ReadUInt32(body.AsSpan(16), isLittleEndian);
            var (linkType, ticksPerUnit) = interfaceId < interfaces.Count ? interfaces[interfaceId] : (LinkLayers.Ethernet, 10L);
            var units = (timestampHigh << 32) | timestampLow;
            var timestamp = DateTime.UnixEpoch.AddTicks(ticksPerUnit > 0 ? units * ticksPerUnit : units / -ticksPerUnit);
            var data = body.AsSpan(20, Math.Min(capturedLength, body.Length - 20)).ToArray();
            return new CapturedFrame(timestamp, linkType, data, originalLength, interfaceName);
        }

        if (blockType == SimplePacketBlock && interfaces.Count > 0)
        {
            var originalLength = (int)ReadUInt32(body, isLittleEndian);
            var data = body.AsSpan(4, Math.Min(originalLength, body.Length - 4)).ToArray();
            return new CapturedFrame(DateTime.UtcNow, interfaces[0].LinkType, data, originalLength, interfaceName);
        }

        return null;
    }

    /// <summary>
    /// Ticks per timestamp unit from the if_tsresol option. Positive means multiply, negative means divide.
    /// Defaults to microseconds.
    /// </summary>
    private static long ReadTimestampResolution(byte[] body, bool isLittleEndian)
    {
        const int timestampResolutionOption = 9;
        var offset = 8;

        while (offset + 4 <= body.Length)
        {
            var optionCode = ReadUInt16(body.AsSpan(offset), isLittleEndian);
            var optionLength = ReadUInt16(body.AsSpan(offset + 2), isLittleEndian);
            if (optionCode == 0)
                break;

            if (optionCode == timestampResolutionOption && optionLength >= 1)
                return TicksPerUnit(body[offset + 4]);

            offset += 4 + ((optionLength + 3) & ~3);
        }

        return 10;
    }

    private static long TicksPerUnit(byte resolution)
    {
        var isPowerOfTwo = (resolution & 0x80) != 0;
        var exponent = resolution & 0x7F;
        var unitsPerSecond = isPowerOfTwo ? Math.Pow(2, exponent) : Math.Pow(10, exponent);
        var ticksPerUnit = TimeSpan.TicksPerSecond / unitsPerSecond;
        return ticksPerUnit >= 1 ? (long)ticksPerUnit : -(long)(unitsPerSecond / TimeSpan.TicksPerSecond);
    }

    private static uint ReadUInt32(ReadOnlySpan<byte> data, bool isLittleEndian)
    {
        return isLittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(data) : BinaryPrimitives.ReadUInt32BigEndian(data);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, bool isLittleEndian)
    {
        return isLittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(data) : BinaryPrimitives.ReadUInt16BigEndian(data);
    }
}
