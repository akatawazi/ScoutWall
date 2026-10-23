using System.Reflection;
using System.Text.Json;
using ScoutWall.Data.Models;

namespace ScoutWall.Data;

/// <summary>
/// The running version and where releases are published, for update checks and "scoutwall update".
/// </summary>
public static class ScoutWallVersion
{
    /// <summary>
    /// The GitHub repository releases come from. Forks change this one line.
    /// </summary>
    public const string Repository = "akatawazi/ScoutWall";

    public static string Current =>
        (Assembly.GetEntryAssembly() ?? typeof(ScoutWallVersion).Assembly)
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0";

    /// <summary>
    /// Whether a release tag ("v0.2.0") is newer than the running version.
    /// </summary>
    public static bool IsNewer(string? releaseTag, string? currentVersion = null)
    {
        return Version.TryParse(releaseTag?.TrimStart('v', 'V'), out var release)
            && Version.TryParse((currentVersion ?? Current).Split('-')[0], out var current)
            && release > current;
    }
}

/// <summary>
/// The newest release the sensor found on GitHub, for the update notice in the console.
/// </summary>
public class LatestRelease
{
    public const string StateKey = "latest_release";

    public string Tag { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public DateTime CheckedAt { get; set; }

    public string Version => Tag.TrimStart('v', 'V');
    public bool IsNewerThanRunning => ScoutWallVersion.IsNewer(Tag);

    public static async Task<LatestRelease?> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (string.IsNullOrEmpty(json))
            return null;

        try
        {
            return JsonSerializer.Deserialize<LatestRelease>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }
}
