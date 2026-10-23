using System.Net;
using System.Text;

namespace ScoutWall.Sensor.Parsing;

public record DnsAnswer(string IpAddress, string RecordType);

public record DnsMessage(bool IsResponse, string? QuestionName, IReadOnlyList<DnsAnswer> Answers);

/// <summary>
/// Minimal DNS wire-format parser: the question name plus A and AAAA answers. Handles name compression.
/// </summary>
public static class DnsMessageParser
{
    private const int HeaderLength = 12;
    private const int RecordTypeA = 1;
    private const int RecordTypeAaaa = 28;
    private const int MaximumNameJumps = 16;

    public static DnsMessage? Parse(ReadOnlySpan<byte> payload)
    {
        try
        {
            return ParseUnchecked(payload);
        }
        catch (Exception exception) when (exception is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static DnsMessage? ParseUnchecked(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderLength)
            return null;

        var isResponse = (payload[2] & 0x80) != 0;
        var questionCount = ReadUInt16(payload, 4);
        var answerCount = ReadUInt16(payload, 6);
        if (questionCount == 0)
            return null;

        var offset = HeaderLength;
        var questionName = ReadName(payload, ref offset);
        offset += 4;

        for (var questionIndex = 1; questionIndex < questionCount; questionIndex++)
        {
            ReadName(payload, ref offset);
            offset += 4;
        }

        var answers = new List<DnsAnswer>();
        for (var answerIndex = 0; answerIndex < answerCount; answerIndex++)
        {
            var dnsAnswer = ReadAnswer(payload, ref offset);
            if (dnsAnswer != null)
                answers.Add(dnsAnswer);
        }

        return new DnsMessage(isResponse, questionName, answers);
    }

    private static DnsAnswer? ReadAnswer(ReadOnlySpan<byte> payload, ref int offset)
    {
        ReadName(payload, ref offset);
        var recordType = ReadUInt16(payload, offset);
        var dataLength = ReadUInt16(payload, offset + 8);
        var dataOffset = offset + 10;
        offset = dataOffset + dataLength;

        if (recordType == RecordTypeA && dataLength == 4)
            return new DnsAnswer(new IPAddress(payload.Slice(dataOffset, 4)).ToString(), "A");

        if (recordType == RecordTypeAaaa && dataLength == 16)
            return new DnsAnswer(new IPAddress(payload.Slice(dataOffset, 16)).ToString(), "AAAA");

        return null;
    }

    private static string ReadName(ReadOnlySpan<byte> payload, ref int offset)
    {
        var nameBuilder = new StringBuilder();
        var position = offset;
        var jumped = false;
        var jumpCount = 0;

        while (true)
        {
            var labelLength = payload[position];
            if (labelLength == 0)
            {
                position++;
                break;
            }

            if ((labelLength & 0xC0) == 0xC0)
            {
                if (++jumpCount > MaximumNameJumps)
                    throw new IndexOutOfRangeException("DNS name compression loop.");

                if (!jumped)
                    offset = position + 2;

                position = ((labelLength & 0x3F) << 8) | payload[position + 1];
                jumped = true;
                continue;
            }

            if (nameBuilder.Length > 0)
                nameBuilder.Append('.');

            nameBuilder.Append(Encoding.ASCII.GetString(payload.Slice(position + 1, labelLength)));
            position += labelLength + 1;
        }

        if (!jumped)
            offset = position;

        return nameBuilder.ToString().ToLowerInvariant();
    }

    private static int ReadUInt16(ReadOnlySpan<byte> payload, int offset)
    {
        return (payload[offset] << 8) | payload[offset + 1];
    }
}
