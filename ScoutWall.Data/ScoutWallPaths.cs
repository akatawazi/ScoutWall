namespace ScoutWall.Data;

/// <summary>
/// Where ScoutWall keeps its data. Windows: %ProgramData%\ScoutWall. Linux: /var/lib/scoutwall. The SCOUTWALL_DATA
/// environment variable overrides both. Configured paths may start with %ProgramData%\ScoutWall (the Windows form
/// used in appsettings.json); on Linux that part is replaced with the Linux data folder.
/// </summary>
public static class ScoutWallPaths
{
    private const string WindowsPrefix = @"%ProgramData%\ScoutWall";

    public static string DataFolder
    {
        get
        {
            var overridden = Environment.GetEnvironmentVariable("SCOUTWALL_DATA");
            if (!string.IsNullOrWhiteSpace(overridden))
                return Path.GetFullPath(overridden);

            return OperatingSystem.IsWindows()
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "ScoutWall")
                : "/var/lib/scoutwall";
        }
    }

    public static string Resolve(string configuredPath)
    {
        if (configuredPath.StartsWith(WindowsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var rest = configuredPath[WindowsPrefix.Length..].TrimStart('\\', '/').Replace('\\', Path.DirectorySeparatorChar);
            return Path.GetFullPath(Path.Combine(DataFolder, rest));
        }

        return Path.GetFullPath(Environment.ExpandEnvironmentVariables(configuredPath));
    }
}
