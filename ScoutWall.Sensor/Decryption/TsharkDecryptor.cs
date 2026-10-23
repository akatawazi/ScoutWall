using System.Diagnostics;
using System.Globalization;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Decryption;

/// <summary>
/// Decrypts TLS in finished packet files with Wireshark's tshark and an SSLKEYLOGFILE, and extracts HTTP request
/// metadata. This only works for traffic from programs on this machine that write their session keys to the
/// key log file (Chrome, Edge, Firefox and curl do when the SSLKEYLOGFILE environment variable is set).
/// Traffic from other devices, or from programs that do not export keys, cannot be decrypted.
/// </summary>
public static class TsharkDecryptor
{
    private const int MaximumRequestsPerFile = 5000;

    private static readonly string[] Fields =
    [
        "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport",
        "http.request.method", "http.host", "http.request.uri", "http.user_agent", "http.request.version",
        "http2.headers.method", "http2.headers.authority", "http2.headers.path", "http2.headers.user_agent"
    ];

    public static async Task<List<DecryptedRequest>> Decrypt(string tsharkPath, string keyLogFilePath, string packetFilePath, CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo(tsharkPath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var argument in BuildArguments(keyLogFilePath, packetFilePath))
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start tshark.");
        var decryptedRequests = new List<DecryptedRequest>();
        var sourceFile = Path.GetFileName(packetFilePath);

        while (await process.StandardOutput.ReadLineAsync(cancellationToken) is { } line)
        {
            var decryptedRequest = ParseLine(line, sourceFile);
            if (decryptedRequest != null && decryptedRequests.Count < MaximumRequestsPerFile)
                decryptedRequests.Add(decryptedRequest);
        }

        await process.WaitForExitAsync(cancellationToken);
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"tshark failed: {await process.StandardError.ReadToEndAsync(cancellationToken)}");

        return decryptedRequests;
    }

    private static IEnumerable<string> BuildArguments(string keyLogFilePath, string packetFilePath)
    {
        yield return "-r";
        yield return packetFilePath;
        yield return "-o";
        yield return $"tls.keylog_file:{keyLogFilePath}";
        yield return "-Y";
        yield return "http.request or http2.headers.method";
        yield return "-T";
        yield return "fields";
        yield return "-E";
        yield return "separator=/t";
        yield return "-E";
        yield return "occurrence=f";

        foreach (var field in Fields)
        {
            yield return "-e";
            yield return field;
        }
    }

    private static DecryptedRequest? ParseLine(string line, string sourceFile)
    {
        var values = line.Split('\t');
        if (values.Length < Fields.Length)
            return null;

        var isHttp2 = !string.IsNullOrEmpty(values[11]);
        var method = isHttp2 ? values[11] : values[6];
        if (string.IsNullOrEmpty(method))
            return null;

        var epochSeconds = double.TryParse(values[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds) ? seconds : 0;
        return new DecryptedRequest
        {
            CapturedAt = DateTime.UnixEpoch.AddSeconds(epochSeconds),
            ClientIp = FirstNonEmpty(values[1], values[2]),
            ServerIp = FirstNonEmpty(values[3], values[4]),
            ServerPort = int.TryParse(values[5], out var port) ? port : 0,
            HttpVersion = isHttp2 ? "HTTP/2" : FirstNonEmpty(values[10], "HTTP/1.1"),
            Method = Truncate(method, 16),
            Host = Truncate(isHttp2 ? values[12] : values[7], 256),
            Path = Truncate(DecryptedRequest.RemoveQueryString(isHttp2 ? values[13] : values[8]), 2048),
            UserAgent = Truncate(isHttp2 ? values[14] : values[9], 512),
            SourceFile = sourceFile
        };
    }

    private static string FirstNonEmpty(string first, string second)
    {
        return string.IsNullOrEmpty(first) ? second : first;
    }

    private static string Truncate(string value, int maximumLength)
    {
        return value.Length > maximumLength ? value[..maximumLength] : value;
    }
}
