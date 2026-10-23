namespace ScoutWall.Data.Models;

/// <summary>
/// Programs that must never be blocked or slowed down, because doing so would cut Windows, its security updates
/// or ScoutWall itself off from the network. Checked when a block is requested and again before a firewall rule
/// is written. A protected name only counts in its real Windows folder: "svchost.exe" in Users\Public is exactly
/// the kind of program someone may want to block.
/// </summary>
public static class ProtectedPrograms
{
    private static readonly HashSet<string> WindowsProgramNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "winlogon.exe", "csrss.exe", "smss.exe",
        "MoUsoCoreWorker.exe", "usocoreworker.exe", "wuauclt.exe", "TiWorker.exe", "TrustedInstaller.exe",
        "MsMpEng.exe", "NisSrv.exe", "MpDefenderCoreService.exe",
        // The desktop itself: ending these leaves a black screen or no keyboard input.
        "explorer.exe", "dwm.exe", "sihost.exe", "ctfmon.exe", "RuntimeBroker.exe", "StartMenuExperienceHost.exe",
        "ShellExperienceHost.exe", "SearchHost.exe", "fontdrvhost.exe", "taskhostw.exe", "audiodg.exe", "conhost.exe",
        "LogonUI.exe", "userinit.exe", "smartscreen.exe", "SecurityHealthService.exe", "SecurityHealthSystray.exe"
    };

    /// <summary>
    /// Why the program cannot be blocked, or null when it can.
    /// </summary>
    public static string? ReasonNotBlockable(string programPath)
    {
        var fullPath = Normalize(programPath);
        if (fullPath == null)
            return "ScoutWall needs the program's full path, for example C:\\Users\\Public\\app.exe.";

        if (fullPath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) || fullPath.Contains(@"\SystemApps\", StringComparison.OrdinalIgnoreCase))
            return "This is a Microsoft Store or built-in Windows app. Windows Firewall can't block those by program yet; block the addresses it talks to instead.";

        var fileName = Path.GetFileName(fullPath);
        if (WindowsProgramNames.Contains(fileName) && WindowsFolders().Any(folder => IsInside(fullPath, folder)))
            return $"{fileName} is part of Windows. Blocking it would cut Windows off from the network or from security updates.";

        if (ScoutWallFolders().Any(folder => IsInside(fullPath, folder)))
            return "That is part of ScoutWall itself.";

        var dotnetHost = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "dotnet", "dotnet.exe");
        if (string.Equals(fullPath, dotnetHost, StringComparison.OrdinalIgnoreCase))
            return "dotnet.exe runs many programs, including parts of ScoutWall. Block the specific program instead.";

        return null;
    }

    /// <summary>
    /// Blocking from running is stricter than blocking internet access: nothing in the Windows folder may be
    /// blocked from running, because tools like PowerShell are what Windows and ScoutWall use to manage the
    /// computer. Block the task or startup entry that launches it instead.
    /// </summary>
    public static string? ReasonNotBlockableFromRunning(string programPath)
    {
        var reason = ReasonNotBlockable(programPath);
        if (reason != null)
            return reason;

        var fullPath = Normalize(programPath)!;
        return WindowsFolders().Any(folder => IsInside(fullPath, folder))
            ? $"{Path.GetFileName(fullPath)} is part of Windows, so it can't be blocked from running. Deal with whatever starts it instead."
            : null;
    }

    /// <summary>
    /// Whether the program is part of ScoutWall, so its own installation is not reported as suspicious.
    /// </summary>
    public static bool IsScoutWall(string? programPath)
    {
        var fullPath = programPath == null ? null : Normalize(programPath);
        return fullPath != null && ScoutWallFolders().Any(folder => IsInside(fullPath, folder));
    }

    /// <summary>
    /// A plain drive-letter path, or null for device paths, relative paths and anything else a firewall rule
    /// could not match.
    /// </summary>
    public static string? Normalize(string programPath)
    {
        var trimmedPath = programPath.Trim().Trim('"');
        if (trimmedPath.StartsWith(@"\\?\", StringComparison.Ordinal))
            trimmedPath = trimmedPath[4..];

        if (trimmedPath.Length < 3 || !char.IsAsciiLetter(trimmedPath[0]) || trimmedPath[1] != ':' || trimmedPath[2] != '\\')
            return null;

        try
        {
            return Path.GetFullPath(trimmedPath);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return null;
        }
    }

    private static IEnumerable<string> WindowsFolders()
    {
        yield return Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender");
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender");
    }

    private static IEnumerable<string> ScoutWallFolders()
    {
        yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ScoutWall");

        // The folder this copy runs from, which covers installs elsewhere and development builds.
        var runningFolder = Path.GetDirectoryName(Environment.ProcessPath);
        if (runningFolder != null && Path.GetFileName(Environment.ProcessPath)?.StartsWith("ScoutWall", StringComparison.OrdinalIgnoreCase) == true)
            yield return runningFolder;
    }

    private static bool IsInside(string fullPath, string folder)
    {
        if (string.IsNullOrEmpty(folder))
            return false;

        var folderWithSeparator = Path.TrimEndingDirectorySeparator(folder) + Path.DirectorySeparatorChar;
        return fullPath.StartsWith(folderWithSeparator, StringComparison.OrdinalIgnoreCase);
    }
}
