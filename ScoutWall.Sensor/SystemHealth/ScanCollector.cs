using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Win32;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Analyst;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Gathers what runs on this computer or starts with it (programs, services, scheduled tasks, startup entries)
/// and scores each one on plain warning signs. Only items with real warning signs are kept; the assistant then
/// gives its view on those. A few files Windows ships aren't in any catalog, so "unknown publisher" is never
/// counted against anything in the Windows folder.
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class ScanCollector
{
    public const int MinimumScore = 3;
    public const int MaximumFlagged = 40;

    public record Candidate(ScanItemKind Kind, string Name, string Target, string? ProgramPath, string? Command, List<string> Signals, int Score, bool IsHidden = false);

    private static readonly string WindowsFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows) + Path.DirectorySeparatorChar;

    private static readonly HashSet<string> WindowsLookalikeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "winlogon.exe", "explorer.exe", "rundll32.exe",
        "dllhost.exe", "taskhostw.exe", "conhost.exe", "smss.exe", "spoolsv.exe", "wininit.exe", "dwm.exe", "sihost.exe"
    };

    [GeneratedRegex(@"(powershell|pwsh)(\.exe)?\b.*(\s-e(nc(odedcommand)?)?\s|-w(indowstyle)?\s+hidden|iex\b|invoke-expression|downloadstring|frombase64string)|\bmshta(\.exe)?\b|\b(wscript|cscript)(\.exe)?\b.*\.(vbs|js|jse|vbe)\b|\brundll32(\.exe)?\b.*(https?:|javascript:)|\bregsvr32(\.exe)?\b.*/i:\s*https?:|\bbitsadmin\b.*/transfer|\bcertutil\b.*-urlcache", RegexOptions.IgnoreCase)]
    private static partial Regex SuspiciousCommandPattern();

    public static async Task<(List<Candidate> Flagged, int Checked)> Collect(DataContext dataContext, CancellationToken cancellationToken)
    {
        var items = new List<Candidate>();
        items.AddRange(await RunningPrograms(dataContext));
        items.AddRange(await Services(dataContext));
        items.AddRange(ScheduledTasks());
        items.AddRange(StartupEntries());
        cancellationToken.ThrowIfCancellationRequested();

        var networkSignals = await NetworkSignals(dataContext);
        var newPrograms = await RecentlySeenPrograms(dataContext);

        var scored = items
            .Select(item => Score(item, networkSignals, newPrograms))
            .Where(item => item.Score >= MinimumScore)
            .GroupBy(item => (item.Kind, item.Target.ToLowerInvariant()))
            .Select(group => group.First())
            .OrderByDescending(item => item.Score)
            .Take(MaximumFlagged)
            .ToList();

        return (scored, items.Count);
    }

    private static Candidate Score(Candidate item, Dictionary<string, List<string>> networkSignals, HashSet<string> newPrograms)
    {
        var signals = new List<string>(item.Signals);
        var score = item.Score;
        var path = item.ProgramPath;

        if (path != null && Path.IsPathFullyQualified(path))
        {
            var inWindowsFolder = path.StartsWith(WindowsFolder, StringComparison.OrdinalIgnoreCase);

            if (IsUserWritable(path))
            {
                signals.Add("runs from a folder any program can write to (" + DescribeFolder(path) + ")");
                score += 3;
            }

            if (!inWindowsFolder && WindowsLookalikeNames.Contains(Path.GetFileName(path)))
            {
                signals.Add("uses the name of a Windows program but isn't in the Windows folder");
                score += 5;
            }

            if (!File.Exists(path))
            {
                signals.Add("its program file is missing");
                score += 1;
            }
            else if (!inWindowsFolder && ProgramIdentity.Read(path)?.Publisher == null)
            {
                signals.Add("not signed by a known publisher");
                score += 2;
            }

            if (newPrograms.Contains(path))
            {
                signals.Add("first seen in the last two days");
                score += 1;
            }

            if (networkSignals.TryGetValue(path, out var programNetworkSignals))
            {
                signals.AddRange(programNetworkSignals);
                score += programNetworkSignals.Count * 3;
            }
        }

        if (item.Command != null && SuspiciousCommandPattern().IsMatch(item.Command))
        {
            signals.Add("starts with a command often used by malware to hide or download code");
            score += 4;
        }

        if (item.IsHidden)
        {
            signals.Add("hidden from the Task Scheduler window");
            score += 1;
        }

        return item with { Signals = signals, Score = score };
    }

    private static async Task<List<Candidate>> RunningPrograms(DataContext dataContext)
    {
        var snapshot = await RunningProgramSnapshot.Load(dataContext);
        return snapshot.Programs
            .Where(program => Path.IsPathFullyQualified(program.ImagePath))
            .Select(program => new Candidate(ScanItemKind.Program, program.Name, program.ImagePath, program.ImagePath, null, [], 0))
            .ToList();
    }

    private static async Task<List<Candidate>> Services(DataContext dataContext)
    {
        var services = await SystemService.GetCurrent(dataContext);
        return services.Select(service =>
        {
            var signals = new List<string>();
            var score = 0;
            if (service.IsNew)
            {
                signals.Add("installed in the last week");
                score += 1;
            }

            return new Candidate(ScanItemKind.Service, service.DisplayName, service.ServiceName, HostTargets.ProgramFromCommand(service.BinaryPath), service.BinaryPath, signals, score);
        }).ToList();
    }

    private static List<Candidate> ScheduledTasks()
    {
        var tasks = new List<Candidate>();
        try
        {
            var schedulerType = Type.GetTypeFromProgID("Schedule.Service");
            if (schedulerType == null)
                return tasks;

            dynamic scheduler = Activator.CreateInstance(schedulerType)!;
            scheduler.Connect();
            CollectFolder(scheduler.GetFolder(@"\"), tasks, 0);
        }
        catch (Exception exception) when (exception is System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
        {
        }

        return tasks;
    }

    private static void CollectFolder(dynamic folder, List<Candidate> tasks, int depth)
    {
        const int IncludeHidden = 1;
        const int ExecAction = 0;
        if (depth > 12 || tasks.Count > 2000)
            return;

        foreach (dynamic task in folder.GetTasks(IncludeHidden))
        {
            try
            {
                string taskPath = task.Path;
                dynamic definition = task.Definition;
                bool isHidden = definition.Settings.Hidden;
                foreach (dynamic action in definition.Actions)
                {
                    if ((int)action.Type != ExecAction)
                        continue;

                    string program = Environment.ExpandEnvironmentVariables(((string?)action.Path ?? string.Empty).Trim('"'));
                    string arguments = (string?)action.Arguments ?? string.Empty;
                    tasks.Add(new Candidate(ScanItemKind.ScheduledTask, taskPath, taskPath, ResolveProgram(program), $"{program} {arguments}".Trim(), [], 0, isHidden));
                }
            }
            catch (Exception exception) when (exception is System.Runtime.InteropServices.COMException or UnauthorizedAccessException)
            {
            }
        }

        foreach (dynamic subfolder in folder.GetFolders(0))
            CollectFolder(subfolder, tasks, depth + 1);
    }

    /// <summary>
    /// Run and RunOnce keys for the whole computer and for each signed-in user (only hives Windows already has
    /// loaded; loading another user's hive could lock it and break their next sign-in), plus Startup folders.
    /// </summary>
    private static List<Candidate> StartupEntries()
    {
        var entries = new List<Candidate>();
        string[] runKeys =
        [
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
            @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ];

        foreach (var runKey in runKeys)
            ReadRunKey(Registry.LocalMachine, runKey, "all users", entries);

        foreach (var userSid in Registry.Users.GetSubKeyNames().Where(name => name.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !name.EndsWith("_Classes", StringComparison.Ordinal)))
        {
            using var userKey = Registry.Users.OpenSubKey(userSid);
            if (userKey == null)
                continue;

            foreach (var runKey in runKeys.Take(2))
                ReadRunKey(userKey, runKey, "one user", entries);
        }

        var startupFolders = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) };
        var usersFolder = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments)) ?? @"C:\Users";
        foreach (var profile in SafeDirectories(usersFolder))
            startupFolders.Add(Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));

        foreach (var startupFolder in startupFolders.Where(Directory.Exists))
        {
            foreach (var file in SafeFiles(startupFolder).Where(file => !file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)))
            {
                var isShortcut = file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase);
                entries.Add(new Candidate(ScanItemKind.StartupEntry, Path.GetFileName(file), file, isShortcut ? null : file, file, [], 0));
            }
        }

        return entries;
    }

    private static void ReadRunKey(RegistryKey root, string subKey, string scope, List<Candidate> entries)
    {
        try
        {
            using var key = root.OpenSubKey(subKey);
            if (key == null)
                return;

            foreach (var valueName in key.GetValueNames())
            {
                if (key.GetValue(valueName) is not string command || string.IsNullOrWhiteSpace(command))
                    continue;

                var program = ResolveProgram(HostTargets.ProgramFromCommand(command));
                entries.Add(new Candidate(ScanItemKind.StartupEntry, $"{valueName} (starts for {scope})", program ?? valueName, program, command, [], 0));
            }
        }
        catch (Exception exception) when (exception is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
        }
    }

    /// <summary>
    /// Turns "powershell.exe" or "%windir%\x.exe" into a full path where possible.
    /// </summary>
    private static string? ResolveProgram(string? program)
    {
        if (string.IsNullOrWhiteSpace(program))
            return null;

        program = Environment.ExpandEnvironmentVariables(program.Trim('"'));
        if (Path.IsPathFullyQualified(program))
            return program;

        var inSystem32 = Path.Combine(Environment.SystemDirectory, program);
        if (File.Exists(inSystem32))
            return inSystem32;

        return File.Exists(inSystem32 + ".exe") ? inSystem32 + ".exe" : program;
    }

    private static async Task<Dictionary<string, List<string>>> NetworkSignals(DataContext dataContext)
    {
        var since = DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds();
        var blocklisted = await dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= since)
            .Join(dataContext.IpAddressProfiles.AsNoTracking().Where(profile => profile.IsBlocklisted), record => record.RemoteIp, profile => profile.IpAddress, (record, _) => record.ProcessImageId)
            .Distinct()
            .ToListAsync();

        var idleUploaders = await dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= since && record.Presence == PresenceState.Away)
            .GroupBy(record => record.ProcessImageId)
            .Where(group => group.Sum(record => record.BytesSent) > 50L * 1024 * 1024)
            .Select(group => group.Key)
            .ToListAsync();

        var ids = blocklisted.Concat(idleUploaders).Distinct().ToList();
        var paths = await dataContext.ProcessImages.AsNoTracking().Where(image => ids.Contains(image.Id)).ToDictionaryAsync(image => image.Id, image => image.ImagePath);
        var signals = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var id in blocklisted.Where(paths.ContainsKey))
            GetOrAdd(signals, paths[id]).Add("talked to an address on a threat blocklist this week");
        foreach (var id in idleUploaders.Where(paths.ContainsKey))
            GetOrAdd(signals, paths[id]).Add("sent over 50 MB while nobody was using the computer this week");

        return signals;
    }

    private static async Task<HashSet<string>> RecentlySeenPrograms(DataContext dataContext)
    {
        var since = DateTime.UtcNow.AddDays(-2);
        var paths = await dataContext.ProcessImages.AsNoTracking().Where(image => image.FirstSeenAt >= since).Select(image => image.ImagePath).ToListAsync();
        return paths.ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static List<string> GetOrAdd(Dictionary<string, List<string>> signals, string key)
    {
        if (!signals.TryGetValue(key, out var list))
            signals[key] = list = [];

        return list;
    }

    private static bool IsUserWritable(string path)
    {
        var lowered = path.ToLowerInvariant();
        return lowered.Contains(@"\appdata\local\temp\") || lowered.Contains(@"\windows\temp\")
            || lowered.Contains(@"\users\public\") || lowered.Contains(@"\downloads\") || lowered.Contains(@"\desktop\")
            || (lowered.Contains(@"\appdata\") && !lowered.Contains(@"\appdata\local\programs\") && !lowered.Contains(@"\appdata\local\microsoft\"))
            || (lowered.StartsWith(@"c:\programdata\") && !lowered.StartsWith(@"c:\programdata\microsoft\"));
    }

    private static string DescribeFolder(string path)
    {
        var folder = Path.GetDirectoryName(path) ?? path;
        return folder.Length <= 60 ? folder : "…" + folder[^59..];
    }

    private static IEnumerable<string> SafeDirectories(string folder)
    {
        try
        {
            return Directory.GetDirectories(folder);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }

    private static IEnumerable<string> SafeFiles(string folder)
    {
        try
        {
            return Directory.GetFiles(folder);
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
        {
            return [];
        }
    }
}
