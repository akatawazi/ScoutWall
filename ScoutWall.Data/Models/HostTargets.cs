using System.Text.RegularExpressions;

namespace ScoutWall.Data.Models;

/// <summary>
/// Which scheduled tasks and services ScoutWall may disable, remove or stop. Windows Update, Defender, the task
/// scheduler itself, networking and ScoutWall are never touched, because doing so would leave the computer
/// unprotected, offline or unable to recover.
/// </summary>
public static partial class HostTargets
{
    private static readonly string[] ProtectedTaskFolders =
    [
        @"\Microsoft\Windows\UpdateOrchestrator\",
        @"\Microsoft\Windows\WindowsUpdate\",
        @"\Microsoft\Windows\Windows Defender\",
        @"\Microsoft\Windows\TaskScheduler\",
        @"\Microsoft\Windows\Time Synchronization\",
        @"\Microsoft\Windows\ExploitGuard\"
    ];

    private static readonly HashSet<string> ProtectedServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "ScoutWall Sensor", "ScoutWall Web", "npcap", "RpcSs", "RpcEptMapper", "DcomLaunch", "LSM", "EventLog", "Schedule",
        "Dnscache", "Dhcp", "NlaSvc", "nsi", "BFE", "mpssvc", "WinDefend", "WdNisSvc", "WdFilter", "Sense",
        "SecurityHealthService", "wscsvc", "wuauserv", "UsoSvc", "TrustedInstaller", "CryptSvc", "Winmgmt",
        "LanmanWorkstation", "ProfSvc", "Power", "PlugPlay", "SamSs", "gpsvc", "BrokerInfrastructure",
        "SystemEventsBroker", "CoreMessagingRegistrar", "StateRepository", "Netman", "netprofm", "WinHttpAutoProxySvc",
        "Audiosrv", "AudioEndpointBuilder", "Themes", "UserManager", "Appinfo", "msiserver", "VaultSvc", "KeyIso",
        "TermService", "UmRdpService", "SessionEnv", "W32Time", "Netlogon"
    };

    [GeneratedRegex(@"^[A-Za-z0-9_.\- ]{1,256}$")]
    private static partial Regex ServiceNamePattern();

    /// <summary>
    /// Why the task can't be acted on, or null when it can.
    /// </summary>
    public static string? ReasonTaskNotActionable(string taskPath, bool deleting)
    {
        if (taskPath.Length is < 2 or > 512 || !taskPath.StartsWith('\\') || taskPath.EndsWith('\\')
            || taskPath.Any(character => char.IsControl(character) || character is '"' or '\'' or '<' or '>' or '|' or '*' or '?'))
            return "That doesn't look like a scheduled task name.";

        if (taskPath.StartsWith(@"\ScoutWall", StringComparison.OrdinalIgnoreCase))
            return "That task is part of ScoutWall.";

        if (ProtectedTaskFolders.Any(folder => taskPath.StartsWith(folder, StringComparison.OrdinalIgnoreCase)))
            return "That task keeps Windows updated or protected, so ScoutWall won't touch it.";

        // Windows servicing owns its own tasks and does not always recreate them, so they can be disabled, not removed.
        return deleting && taskPath.StartsWith(@"\Microsoft\Windows\", StringComparison.OrdinalIgnoreCase)
            ? "That is one of Windows' own tasks. It can be disabled, but not removed."
            : null;
    }

    /// <summary>
    /// Why the service can't be stopped, or null when it can.
    /// </summary>
    public static string? ReasonServiceNotActionable(string serviceName, string? binaryPath)
    {
        if (!ServiceNamePattern().IsMatch(serviceName))
            return "That doesn't look like a service name.";

        if (ProtectedServices.Contains(serviceName))
            return "Windows, its protection or ScoutWall needs that service, so ScoutWall won't stop it.";

        var program = ProgramFromCommand(binaryPath);
        if (ProtectedPrograms.IsScoutWall(program))
            return "That service is part of ScoutWall.";

        if (program != null && program.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
            return "That is a device driver, which ScoutWall won't stop.";

        // Built-in Windows services run inside svchost.exe from the Windows folder. Unwanted services almost never do.
        var windowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + Path.DirectorySeparatorChar;
        var isWindowsService = program != null
            && program.StartsWith(windowsFolder, StringComparison.OrdinalIgnoreCase)
            && Path.GetFileName(program).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase);
        return isWindowsService ? "That is a built-in Windows service, so ScoutWall won't stop it." : null;
    }

    /// <summary>
    /// The executable from a service command line such as "C:\Program Files\App\svc.exe" -k run.
    /// </summary>
    public static string? ProgramFromCommand(string? commandLine)
    {
        var text = Environment.ExpandEnvironmentVariables(commandLine?.Trim() ?? string.Empty);
        if (text.Length == 0 || text == "-")
            return null;

        if (text.StartsWith('"'))
        {
            var closingQuote = text.IndexOf('"', 1);
            return closingQuote > 1 ? text[1..closingQuote] : text.Trim('"');
        }

        var exeEnd = text.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        var path = exeEnd > 0 ? text[..(exeEnd + 4)] : text.Split(' ')[0];
        if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), path[12..]);
        else if (path.StartsWith(@"\??\", StringComparison.Ordinal))
            path = path[4..];

        return path;
    }
}
