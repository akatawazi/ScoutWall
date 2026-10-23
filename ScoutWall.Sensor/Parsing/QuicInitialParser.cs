using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace ScoutWall.Sensor.Parsing;

/// <summary>
/// Recovers the TLS ClientHello from QUIC version 1 Initial packets (RFC 9000/9001), so HTTP/3 traffic such as
/// Chrome's still shows its server name. Initial packets are protected with keys derived from the public
/// destination connection ID, which is metadata any observer on the path can read; this does not decrypt
/// application data.
/// </summary>
public class QuicInitialParser
{
    private const uint QuicVersion1 = 0x00000001;
    private const int MaximumPendingConnections = 2000;
    private const int MaximumCryptoBytes = 16 * 1024;
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromSeconds(10);
    private static readonly byte[] InitialSaltVersion1 = Convert.FromHexString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a");

    private readonly Dictionary<string, PendingHandshake> pendingHandshakes = [];

    /// <summary>
    /// Feeds one client-to-server UDP datagram. Returns the ClientHello once all of its CRYPTO data has arrived.
    /// </summary>
    public TlsClientHello? Add(byte[] datagram, DateTime timestamp)
    {
        try
        {
            return AddUnchecked(datagram, timestamp);
        }
        catch (Exception exception) when (exception is ArgumentException or IndexOutOfRangeException or CryptographicException)
        {
            return null;
        }
    }

    private TlsClientHello? AddUnchecked(byte[] datagram, DateTime timestamp)
    {
        var offset = 0;
        while (offset < datagram.Length)
        {
            var packetLength = ReadInitialPacket(datagram, offset, timestamp, out var clientHello);
            if (clientHello != null)
                return clientHello;

            if (packetLength <= 0)
                return null;

            offset += packetLength;
        }

        return null;
    }

    /// <summary>
    /// Processes one (possibly coalesced) long-header packet. Returns its length, or 0 when it is not a
    /// QUIC v1 Initial packet.
    /// </summary>
    private int ReadInitialPacket(byte[] datagram, int start, DateTime timestamp, out TlsClientHello? clientHello)
    {
        clientHello = null;
        var firstByte = datagram[start];
        var isLongHeader = (firstByte & 0x80) != 0;
        var isInitial = ((firstByte >> 4) & 0x03) == 0;
        if (!isLongHeader || !isInitial || BinaryPrimitives.ReadUInt32BigEndian(datagram.AsSpan(start + 1)) != QuicVersion1)
            return 0;

        var offset = start + 5;
        var destinationIdLength = datagram[offset++];
        var destinationId = datagram.AsSpan(offset, destinationIdLength).ToArray();
        offset += destinationIdLength;
        var sourceIdLength = datagram[offset++];
        offset += sourceIdLength;
        var tokenLength = (int)ReadVariableInteger(datagram, ref offset);
        offset += tokenLength;
        var payloadLength = (int)ReadVariableInteger(datagram, ref offset);
        var packetNumberOffset = offset;
        var packetEnd = packetNumberOffset + payloadLength;
        if (packetEnd > datagram.Length)
            return 0;

        var plaintext = Unprotect(datagram, start, packetNumberOffset, packetEnd, destinationId);
        if (plaintext == null)
            return packetEnd - start;

        var connectionKey = Convert.ToHexString(destinationId);
        clientHello = CollectCrypto(connectionKey, plaintext, timestamp);
        return packetEnd - start;
    }

    private static byte[]? Unprotect(byte[] datagram, int start, int packetNumberOffset, int packetEnd, byte[] destinationId)
    {
        var (key, initializationVector, headerProtectionKey) = DeriveClientKeys(destinationId);

        var sample = datagram.AsSpan(packetNumberOffset + 4, 16).ToArray();
        using var headerCipher = Aes.Create();
        headerCipher.Key = headerProtectionKey;
        var mask = headerCipher.EncryptEcb(sample, PaddingMode.None);

        var header = datagram.AsSpan(start, packetNumberOffset - start + 4).ToArray();
        header[0] ^= (byte)(mask[0] & 0x0F);
        var packetNumberLength = (header[0] & 0x03) + 1;
        var headerLength = packetNumberOffset - start + packetNumberLength;

        long packetNumber = 0;
        for (var index = 0; index < packetNumberLength; index++)
        {
            header[packetNumberOffset - start + index] ^= mask[1 + index];
            packetNumber = (packetNumber << 8) | header[packetNumberOffset - start + index];
        }

        var nonce = (byte[])initializationVector.Clone();
        for (var index = 0; index < 8; index++)
            nonce[nonce.Length - 1 - index] ^= (byte)(packetNumber >> (8 * index));

        var ciphertextStart = packetNumberOffset + packetNumberLength;
        var ciphertextLength = packetEnd - ciphertextStart - 16;
        if (ciphertextLength <= 0)
            return null;

        var plaintext = new byte[ciphertextLength];
        using var payloadCipher = new AesGcm(key, 16);
        payloadCipher.Decrypt(
            nonce,
            datagram.AsSpan(ciphertextStart, ciphertextLength),
            datagram.AsSpan(packetEnd - 16, 16),
            plaintext,
            header.AsSpan(0, headerLength));
        return plaintext;
    }

    public static (byte[] Key, byte[] InitializationVector, byte[] HeaderProtectionKey) DeriveClientKeys(byte[] destinationId)
    {
        var initialSecret = HKDF.Extract(HashAlgorithmName.SHA256, destinationId, InitialSaltVersion1);
        var clientSecret = ExpandLabel(initialSecret, "client in", 32);
        return (ExpandLabel(clientSecret, "quic key", 16), ExpandLabel(clientSecret, "quic iv", 12), ExpandLabel(clientSecret, "quic hp", 16));
    }

    /// <summary>
    /// HKDF-Expand-Label from TLS 1.3 (RFC 8446 section 7.1) with an empty context.
    /// </summary>
    private static byte[] ExpandLabel(byte[] secret, string label, int length)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + fullLabel.Length + 1];
        BinaryPrimitives.WriteUInt16BigEndian(info, (ushort)length);
        info[2] = (byte)fullLabel.Length;
        fullLabel.CopyTo(info, 3);
        return HKDF.Expand(HashAlgorithmName.SHA256, secret, length, info);
    }

    /// <summary>
    /// Gathers CRYPTO frames by offset. Chrome splits large ClientHellos over several Initial packets and
    /// shuffles frame order, so data is placed by offset and parsed once the handshake message is complete.
    /// </summary>
    private TlsClientHello? CollectCrypto(string connectionKey, byte[] plaintext, DateTime timestamp)
    {
        if (!pendingHandshakes.TryGetValue(connectionKey, out var pendingHandshake))
        {
            if (pendingHandshakes.Count >= MaximumPendingConnections)
                RemoveExpired(timestamp);

            pendingHandshake = new PendingHandshake(new byte[MaximumCryptoBytes], new bool[MaximumCryptoBytes], timestamp);
            pendingHandshakes[connectionKey] = pendingHandshake;
        }

        foreach (var (frameOffset, frameData) in ReadCryptoFrames(plaintext))
        {
            if (frameOffset + frameData.Length > MaximumCryptoBytes)
                continue;

            frameData.CopyTo(pendingHandshake.Buffer, frameOffset);
            Array.Fill(pendingHandshake.Received, true, frameOffset, frameData.Length);
        }

        if (!pendingHandshake.Received[0] || !pendingHandshake.Received[1] || !pendingHandshake.Received[2] || !pendingHandshake.Received[3])
            return null;

        var handshakeLength = 4 + ((pendingHandshake.Buffer[1] << 16) | (pendingHandshake.Buffer[2] << 8) | pendingHandshake.Buffer[3]);
        if (pendingHandshake.Buffer[0] != 0x01 || handshakeLength > MaximumCryptoBytes)
        {
            pendingHandshakes.Remove(connectionKey);
            return null;
        }

        if (Array.IndexOf(pendingHandshake.Received, false, 0, handshakeLength) >= 0)
            return null;

        pendingHandshakes.Remove(connectionKey);
        return TlsClientHelloParser.Parse(WrapInRecord(pendingHandshake.Buffer.AsSpan(0, handshakeLength)));
    }

    /// <summary>
    /// QUIC carries the bare handshake message; the TLS parser expects it inside a TLS record.
    /// </summary>
    private static byte[] WrapInRecord(ReadOnlySpan<byte> handshake)
    {
        var record = new byte[5 + handshake.Length];
        record[0] = 0x16;
        record[1] = 0x03;
        record[2] = 0x01;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(3), (ushort)handshake.Length);
        handshake.CopyTo(record.AsSpan(5));
        return record;
    }

    private static IEnumerable<(int Offset, byte[] Data)> ReadCryptoFrames(byte[] plaintext)
    {
        var frames = new List<(int, byte[])>();
        var offset = 0;

        while (offset < plaintext.Length)
        {
            var frameType = ReadVariableInteger(plaintext, ref offset);
            if (frameType is 0x00 or 0x01)
                continue;

            if (frameType is 0x02 or 0x03)
            {
                SkipAcknowledgementFrame(plaintext, ref offset, frameType == 0x03);
                continue;
            }

            if (frameType != 0x06)
                break;

            var cryptoOffset = (int)ReadVariableInteger(plaintext, ref offset);
            var cryptoLength = (int)ReadVariableInteger(plaintext, ref offset);
            frames.Add((cryptoOffset, plaintext.AsSpan(offset, cryptoLength).ToArray()));
            offset += cryptoLength;
        }

        return frames;
    }

    private static void SkipAcknowledgementFrame(byte[] plaintext, ref int offset, bool hasEcnCounts)
    {
        ReadVariableInteger(plaintext, ref offset);
        ReadVariableInteger(plaintext, ref offset);
        var rangeCount = ReadVariableInteger(plaintext, ref offset);
        ReadVariableInteger(plaintext, ref offset);

        for (var range = 0L; range < rangeCount; range++)
        {
            ReadVariableInteger(plaintext, ref offset);
            ReadVariableInteger(plaintext, ref offset);
        }

        if (!hasEcnCounts)
            return;

        for (var count = 0; count < 3; count++)
            ReadVariableInteger(plaintext, ref offset);
    }

    /// <summary>
    /// QUIC variable-length integer (RFC 9000 section 16): the top two bits give the length.
    /// </summary>
    private static long ReadVariableInteger(byte[] data, ref int offset)
    {
        var firstByte = data[offset];
        var length = 1 << (firstByte >> 6);
        long value = firstByte & 0x3F;

        for (var index = 1; index < length; index++)
            value = (value << 8) | data[offset + index];

        offset += length;
        return value;
    }

    private void RemoveExpired(DateTime now)
    {
        foreach (var expiredKey in pendingHandshakes.Where(entry => now - entry.Value.StartedAt > PendingLifetime).Select(entry => entry.Key).ToList())
            pendingHandshakes.Remove(expiredKey);

        if (pendingHandshakes.Count >= MaximumPendingConnections)
            pendingHandshakes.Clear();
    }

    private record PendingHandshake(byte[] Buffer, bool[] Received, DateTime StartedAt);
}
