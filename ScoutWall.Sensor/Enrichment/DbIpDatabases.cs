using System.IO.Compression;
using ScoutWall.Data;

namespace ScoutWall.Sensor.Enrichment;

/// <summary>
/// The default location source: DB-IP's free "Lite" databases (city and network owner), downloaded on first use and
/// refreshed monthly into the data folder. They are licensed under Creative Commons Attribution 4.0, which allows
/// any use with credit to DB-IP, so they suit an MIT project; the console shows the credit wherever locations appear.
/// MaxMind GeoLite2 databases, when configured in settings, take their place.
/// </summary>
public class DbIpDatabases
{
    public const string Attribution = "IP geolocation by DB-IP";
    public const string AttributionUrl = "https://db-ip.com";

    private const string DownloadBase = "https://download.db-ip.com/free/";
    private static readonly TimeSpan RefreshAfter = TimeSpan.FromDays(32);
    private static readonly TimeSpan RetryAfterFailure = TimeSpan.FromHours(6);
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromMinutes(10) };

    private readonly ILogger logger;
    private DateTime lastAttempt = DateTime.MinValue;

    public DbIpDatabases(ILogger logger)
    {
        this.logger = logger;
    }

    public static string Folder => Path.Combine(ScoutWallPaths.DataFolder, "geo");
    public static string CityPath => Path.Combine(Folder, "dbip-city-lite.mmdb");
    public static string AsnPath => Path.Combine(Folder, "dbip-asn-lite.mmdb");

    /// <summary>
    /// Downloads the databases when they are missing or more than a month old. Failures are retried a few hours later.
    /// </summary>
    public async Task EnsureCurrent(CancellationToken cancellationToken)
    {
        if (!IsStale(CityPath) && !IsStale(AsnPath))
            return;

        if (DateTime.UtcNow - lastAttempt < RetryAfterFailure)
            return;

        lastAttempt = DateTime.UtcNow;
        Directory.CreateDirectory(Folder);
        foreach (var (name, path) in new[] { ("asn-lite", AsnPath), ("city-lite", CityPath) })
        {
            if (!IsStale(path))
                continue;

            try
            {
                await Download(name, path, cancellationToken);
                logger.LogInformation("Downloaded the DB-IP {Name} location database", name);
            }
            catch (Exception exception) when (exception is HttpRequestException or IOException or TaskCanceledException or InvalidDataException)
            {
                logger.LogWarning("Could not download the DB-IP {Name} location database: {Message}", name, exception.Message);
            }
        }
    }

    private static bool IsStale(string path)
    {
        return !File.Exists(path) || DateTime.UtcNow - File.GetLastWriteTimeUtc(path) > RefreshAfter;
    }

    /// <summary>
    /// The newest monthly file; early in a month it may not be published yet, so last month's is tried next.
    /// </summary>
    private static async Task Download(string name, string path, CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;
        HttpRequestException? lastError = null;
        foreach (var month in new[] { now, now.AddMonths(-1) })
        {
            var url = $"{DownloadBase}dbip-{name}-{month:yyyy-MM}.mmdb.gz";
            using var response = await HttpClient.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                lastError = new HttpRequestException($"{url} answered {(int)response.StatusCode}");
                continue;
            }

            // Unpacked next to the final file and moved into place, so a half-written database is never opened.
            var temporaryPath = path + ".download";
            await using (var compressed = await response.Content.ReadAsStreamAsync(cancellationToken))
            await using (var unpacked = new GZipStream(compressed, CompressionMode.Decompress))
            await using (var file = File.Create(temporaryPath))
                await unpacked.CopyToAsync(file, cancellationToken);

            File.Move(temporaryPath, path, overwrite: true);
            return;
        }

        throw lastError ?? new HttpRequestException("No DB-IP database was available.");
    }
}
