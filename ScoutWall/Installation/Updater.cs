using System.Diagnostics;
using ScoutWall.Data;
using ScoutWall.Sensor.Updates;

namespace ScoutWall.Installation;

/// <summary>
/// "scoutwall update": downloads the newest release from GitHub, checks it against the release's SHA-256 checksums
/// and runs its "install", which upgrades in place and keeps the data and settings. "--check" only reports. The
/// console's "Install update" button does the same through the sensor.
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

        using var releaseClient = new ReleaseClient(Environment.GetEnvironmentVariable("GITHUB_TOKEN") ?? GitHubCliToken());
        try
        {
            var release = await releaseClient.GetLatest();
            Console.WriteLine($"Running ScoutWall {ScoutWallVersion.Current}; newest release is {release.Version}.");
            if (!release.IsNewer)
            {
                Console.WriteLine("You're up to date.");
                return 0;
            }

            if (checkOnly)
            {
                Console.WriteLine("Run \"scoutwall update\" as administrator to install it.");
                return 0;
            }

            Console.WriteLine($"Downloading {ReleaseClient.AssetName}...");
            var downloaded = await releaseClient.DownloadVerified(release);
            Console.WriteLine("Checksum verified. Installing...");

            // The new version installs itself, replacing this one.
            using var installer = Process.Start(new ProcessStartInfo(downloaded, "install") { UseShellExecute = false })
                ?? throw new InvalidOperationException("Couldn't start the new version.");
            await installer.WaitForExitAsync();
            return installer.ExitCode;
        }
        catch (UpdateException exception)
        {
            Console.Error.WriteLine(exception.Message);
            return 1;
        }
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
