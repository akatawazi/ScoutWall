using System.Runtime.Versioning;
using Microsoft.Win32;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Finds where each person's own folders really are. Documents, Desktop and the rest are often moved (OneDrive's
/// folder backup, a data drive), so they are read from each signed-in user's "User Shell Folders" and OneDrive
/// accounts rather than assumed to be under C:\Users.
/// </summary>
[SupportedOSPlatform("windows")]
public static class MyFolders
{
    private const string ProfileListKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    private const string ShellFoldersKey = @"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    private const string OneDriveAccountsKey = @"Software\Microsoft\OneDrive\Accounts";

    /// <summary>
    /// The "User Shell Folders" values for Documents, Desktop, Pictures, Videos, Music and Downloads.
    /// </summary>
    private static readonly string[] PersonalShellFolders =
        ["Personal", "Desktop", "My Pictures", "My Video", "My Music", "{374DE290-123F-4565-9164-39C4925E467B}"];

    public static FileAreaRules Discover(IEnumerable<string> extraFolders)
    {
        var windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var rules = new FileAreaRules
        {
            FoundAt = DateTime.UtcNow,
            WindowsFolder = windowsFolder,
            SystemDrive = Path.GetPathRoot(windowsFolder)?.TrimEnd('\\') ?? "C:",
            ProgramDataFolder = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ProgramFilesFolders = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
                }
                .Where(folder => folder.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList(),
            ExtraFolders = extraFolders.ToList()
        };

        var personal = new List<string>();
        var publicFolder = Environment.GetEnvironmentVariable("PUBLIC");
        if (!string.IsNullOrEmpty(publicFolder))
            personal.Add(publicFolder);

        foreach (var (sid, profilePath) in Profiles())
        {
            rules.ProfileFolders.Add(profilePath);
            if (sid.Length == 0)
                continue;

            using var userKey = Registry.Users.OpenSubKey(sid);
            if (userKey == null)
                continue;

            using (var shellFolders = userKey.OpenSubKey(ShellFoldersKey))
            {
                foreach (var valueName in PersonalShellFolders)
                {
                    if (shellFolders?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is string folder)
                        personal.Add(Expand(folder, profilePath));
                }
            }

            using var accounts = userKey.OpenSubKey(OneDriveAccountsKey);
            foreach (var accountName in accounts?.GetSubKeyNames() ?? [])
            {
                using var account = accounts!.OpenSubKey(accountName);
                if (account?.GetValue("UserFolder") is string oneDriveFolder && oneDriveFolder.Length > 2)
                    personal.Add(oneDriveFolder);
            }
        }

        rules.PersonalFolders = personal
            .Where(folder => folder.Length > 2 && folder[1] == ':')
            .Select(folder => folder.TrimEnd('\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        return rules;
    }

    /// <summary>
    /// Real people's profiles (S-1-5-21-...) with their profile folder. The SID is empty for people who aren't
    /// signed in: their registry isn't loaded, so only the default folders under their profile are known.
    /// </summary>
    private static IEnumerable<(string Sid, string ProfilePath)> Profiles()
    {
        using var profileList = Registry.LocalMachine.OpenSubKey(ProfileListKey);
        if (profileList == null)
            yield break;

        var loaded = Registry.Users.GetSubKeyNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var sid in profileList.GetSubKeyNames().Where(sid => sid.StartsWith("S-1-5-21-", StringComparison.Ordinal)))
        {
            using var profile = profileList.OpenSubKey(sid);
            if (profile?.GetValue("ProfileImagePath") is not string profilePath)
                continue;

            profilePath = Environment.ExpandEnvironmentVariables(profilePath);
            if (loaded.Contains(sid))
                yield return (sid, profilePath);
            else
                yield return (string.Empty, profilePath);
        }
    }

    /// <summary>
    /// Expands a per-user folder value: %USERPROFILE% is that user's profile, not the sensor's.
    /// </summary>
    private static string Expand(string folder, string profilePath)
    {
        var withProfile = folder.Replace("%USERPROFILE%", profilePath, StringComparison.OrdinalIgnoreCase);
        return Environment.ExpandEnvironmentVariables(withProfile);
    }
}
