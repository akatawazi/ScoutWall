using System.Diagnostics;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using ScoutWall.Data;

namespace ScoutWall.Installation;

/// <summary>
/// "scoutwall update": downloads the newest release from GitHub, checks it against the release's SHA-256 checksums
/// and runs its "install", which upgrades in place and keeps the data and settings. "--check" only reports.
/// While the repository is private, a GitHub token is needed: GITHUB_TOKEN, or a signed-in GitHub CLI.
/// </summary>
public static class Updater
{
    public static async Task<int> Update(string[] args)
    {
        var checkOnly = args.Contains("--check", StringComparer.OrdinalIgnoreCase);
        if (!checkOnly && !Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine(OperatingSystem.IsWindows() ? "Run this from an administrator prompt." : "Run this as root: sudo scoutwall update");
            return 1;
        }

        var assetName = OperatingSystem.IsWindows() ? "scoutwall-win-x64.exe" : "scoutwall-linux-x64";
        using var http = CreateClient();
        JsonDocument release;
        try
        {
            using var response = await http.GetAsync($"https://api.github.com/repos/{ScoutWallVersion.Repository}/releases/latest");
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine((int)response.StatusCode == 404
                    ? "No release found. If the repository is private, sign in with the GitHub CLI (gh auth login) or set GITHUB_TOKEN."
                    : $"GitHub answered {(int)response.StatusCode}.");
                return 1;
            }

            release = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        }
        catch (HttpRequestException exception)
        {
            Console.Error.WriteLine($"Couldn't reach GitHub: {exception.Message}");
            return 1;
        }

        using (release)
        {
            var tag = release.RootElement.GetProperty("tag_name").GetString() ?? string.Empty;
            Console.WriteLine($"Running ScoutWall {ScoutWallVersion.Current}; newest release is {tag.TrimStart('v')}.");
            if (!ScoutWallVersion.IsNewer(tag))
            {
                Console.WriteLine("You're up to date.");
                return 0;
            }

            if (checkOnly)
            {
                Console.WriteLine("Run \"scoutwall update\" as administrator to install it.");
                return 0;
            }

            var assets = release.RootElement.GetProperty("assets").EnumerateArray().ToList();
            var executableAsset = assets.FirstOrDefault(asset => asset.GetProperty("name").GetString() == assetName);
            var sumsAsset = assets.FirstOrDefault(asset => asset.GetProperty("name").GetString() == "SHA256SUMS");
            if (executableAsset.ValueKind == JsonValueKind.Undefined || sumsAsset.ValueKind == JsonValueKind.Undefined)
            {
                Console.Error.WriteLine($"The release has no {assetName} or SHA256SUMS.");
                return 1;
            }

            var folder = Directory.CreateTempSubdirectory("scoutwall-update-").FullName;
            var downloaded = Path.Combine(folder, OperatingSystem.IsWindows() ? "scoutwall.exe" : "scoutwall");
            Console.WriteLine($"Downloading {assetName}...");
            await Download(http, executableAsset, downloaded);
            var sumsPath = Path.Combine(folder, "SHA256SUMS");
            await Download(http, sumsAsset, sumsPath);

            var expected = File.ReadAllLines(sumsPath)
                .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .FirstOrDefault(parts => parts.Length == 2 && parts[1].TrimStart('*') == assetName)?[0];
            await using (var stream = File.OpenRead(downloaded))
            {
                var actual = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream));
                if (expected == null || !string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                {
                    Console.Error.WriteLine("The download didn't match its checksum; nothing was changed.");
                    return 1;
                }
            }

            Console.WriteLine("Checksum verified. Installing...");
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(downloaded, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            // The new version installs itself, replacing this one.
            using var installer = Process.Start(new ProcessStartInfo(downloaded, "install") { UseShellExecute = false })
                ?? throw new InvalidOperationException("Couldn't start the new version.");
            await installer.WaitForExitAsync();
            return installer.ExitCode;
        }
    }

    private static async Task Download(HttpClient http, JsonElement asset, string path)
    {
        // The asset API address works for private repositories (with a token) as well as public ones.
        using var request = new HttpRequestMessage(HttpMethod.Get, asset.GetProperty("url").GetString());
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();
        await using var file = File.Create(path);
        await response.Content.CopyToAsync(file);
    }

    private static HttpClient CreateClient()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromMinutes(10) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"ScoutWall/{ScoutWallVersion.Current}");
        http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        var token = Environment.GetEnvironmentVariable("GITHUB_TOKEN") ?? GitHubCliToken();
        if (!string.IsNullOrWhiteSpace(token))
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return http;
    }

    /// <summary>
    /// The signed-in GitHub CLI's token, if the CLI is installed, so updating from a private repository just works.
    /// </summary>
    private static string? GitHubCliToken()
    {
        try
        {
            var (exitCode, output) = Installer.Run("gh", "auth", "token");
            return exitCode == 0 && !output.Contains(' ') ? output.Trim() : null;
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }
}
