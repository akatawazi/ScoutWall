using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using ScoutWall.Data;

namespace ScoutWall.Sensor.Updates;

/// <summary>
/// The newest ScoutWall release on GitHub and its download for this platform, checked against the release's
/// SHA-256 checksums. Used by "scoutwall update" and by the console's "Install update" (through the sensor).
/// </summary>
public class ReleaseClient : IDisposable
{
    public record Release(string Tag, string Url, JsonElement Executable, JsonElement Checksums)
    {
        public string Version => Tag.TrimStart('v', 'V');
        public bool IsNewer => ScoutWallVersion.IsNewer(Tag);
    }

    public static string AssetName => OperatingSystem.IsWindows() ? "scoutwall-win-x64.exe" : "scoutwall-linux-x64";

    private readonly HttpClient http;
    private JsonDocument? document;

    /// <param name="token">A GitHub token, needed only while the repository is private.</param>
    public ReleaseClient(string? token = null, TimeSpan? timeout = null)
    {
        http = new HttpClient { Timeout = timeout ?? TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"ScoutWall/{ScoutWallVersion.Current}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        if (!string.IsNullOrWhiteSpace(token))
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// The newest release. Throws <see cref="UpdateException"/> with a message fit to show a person.
    /// </summary>
    public async Task<Release> GetLatest(CancellationToken cancellationToken = default)
    {
        try
        {
            using var response = await http.GetAsync($"https://api.github.com/repos/{ScoutWallVersion.Repository}/releases/latest", cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                throw new UpdateException((int)response.StatusCode == 404
                    ? "No release found. If the repository is private, sign in with the GitHub CLI (gh auth login) or set GITHUB_TOKEN."
                    : $"GitHub answered {(int)response.StatusCode}.");
            }

            document?.Dispose();
            document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            throw new UpdateException($"Couldn't reach GitHub: {exception.Message}");
        }

        var root = document.RootElement;
        var assets = root.TryGetProperty("assets", out var list) ? list.EnumerateArray().ToList() : [];
        return new Release(
            root.GetProperty("tag_name").GetString() ?? string.Empty,
            root.TryGetProperty("html_url", out var url) ? url.GetString() ?? string.Empty : string.Empty,
            assets.FirstOrDefault(asset => asset.GetProperty("name").GetString() == AssetName),
            assets.FirstOrDefault(asset => asset.GetProperty("name").GetString() == "SHA256SUMS"));
    }

    /// <summary>
    /// Downloads the release's executable into a new temporary folder and checks it against SHA256SUMS. Returns
    /// the path of the verified file; nothing is installed.
    /// </summary>
    public async Task<string> DownloadVerified(Release release, CancellationToken cancellationToken = default)
    {
        if (release.Executable.ValueKind == JsonValueKind.Undefined || release.Checksums.ValueKind == JsonValueKind.Undefined)
            throw new UpdateException($"The release has no {AssetName} or SHA256SUMS.");

        var folder = Directory.CreateTempSubdirectory("scoutwall-update-").FullName;
        var downloaded = Path.Combine(folder, OperatingSystem.IsWindows() ? "scoutwall.exe" : "scoutwall");
        var sumsPath = Path.Combine(folder, "SHA256SUMS");
        try
        {
            await Download(release.Executable, downloaded, cancellationToken);
            await Download(release.Checksums, sumsPath, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            throw new UpdateException($"The download failed: {exception.Message}");
        }

        var expected = File.ReadAllLines(sumsPath)
            .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .FirstOrDefault(parts => parts.Length == 2 && parts[1].TrimStart('*') == AssetName)?[0];
        await using (var stream = File.OpenRead(downloaded))
        {
            var actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
            if (expected == null || !string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                throw new UpdateException("The download didn't match its checksum; nothing was changed.");
        }

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(downloaded, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        return downloaded;
    }

    private async Task Download(JsonElement asset, string path, CancellationToken cancellationToken)
    {
        // The asset API address works for private repositories (with a token) as well as public ones.
        using var request = new HttpRequestMessage(HttpMethod.Get, asset.GetProperty("url").GetString());
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var file = File.Create(path);
        await response.Content.CopyToAsync(file, cancellationToken);
    }

    public void Dispose()
    {
        document?.Dispose();
        http.Dispose();
    }
}

public class UpdateException(string message) : Exception(message);
