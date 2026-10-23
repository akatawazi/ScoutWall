using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Xml.Linq;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// A notable event read from a Windows log, ready to store, plus the alert it should raise (if any).
/// </summary>
public record CollectedEvent(SystemEvent SystemEvent, long RecordId);

/// <summary>
/// One query against one log: which event ids matter and how they are categorised.
/// </summary>
public record EventSource(string Name, string Channel, string Filter);

/// <summary>
/// Reads the handful of Windows events that say something about security or stability. Queries are filtered by the
/// log service itself (event ids in the XPath) and capped per pass, so a busy Security log is never read in full.
/// </summary>
[SupportedOSPlatform("windows")]
public static class EventLogCollector
{
    public const int MaximumPerPass = 500;
    public const string DefenderChannel = "Microsoft-Windows-Windows Defender/Operational";
    public const string TaskSchedulerChannel = "Microsoft-Windows-TaskScheduler/Operational";
    private static readonly XNamespace EventNamespace = "http://schemas.microsoft.com/win/2004/08/events/event";

    public static readonly IReadOnlyList<EventSource> Sources =
    [
        new("system", "System", "(EventID=7045 or EventID=7031 or EventID=7034 or EventID=41 or EventID=6008 or EventID=104)"),
        new("system-disk", "System", "Provider[@Name='disk' or @Name='Ntfs' or @Name='volmgr'] and (Level=1 or Level=2)"),
        new("security", "Security", "(EventID=4625 or EventID=4720 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=1102)"),
        new("defender", DefenderChannel, "(EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=5001 or EventID=5010 or EventID=5012)"),
        new("tasks", TaskSchedulerChannel, "(EventID=106)"),
        new("application", "Application", "Provider[@Name='Application Error' or @Name='Application Hang'] and (EventID=1000 or EventID=1002)")
    ];

    /// <summary>
    /// Groups whose new members can take over the computer.
    /// </summary>
    private static readonly HashSet<string> PowerfulGroups = new(StringComparer.OrdinalIgnoreCase)
    {
        "Administrators", "Domain Admins", "Enterprise Admins", "Schema Admins", "Backup Operators", "Remote Desktop Users", "Hyper-V Administrators"
    };

    /// <summary>
    /// Events after <paramref name="afterRecordId"/>, or from the last day when there is no bookmark yet.
    /// </summary>
    public static List<CollectedEvent> Read(EventSource source, long? afterRecordId)
    {
        var position = afterRecordId.HasValue ? $"EventRecordID > {afterRecordId.Value}" : "TimeCreated[timediff(@SystemTime) <= 86400000]";
        var query = new EventLogQuery(source.Channel, PathType.LogName, $"*[System[{source.Filter} and {position}]]");
        var collected = new List<CollectedEvent>();

        using var reader = new EventLogReader(query);
        for (var record = reader.ReadEvent(); record != null && collected.Count < MaximumPerPass; record = reader.ReadEvent())
        {
            using (record)
            {
                var systemEvent = Interpret(source, record);
                if (systemEvent != null)
                    collected.Add(new CollectedEvent(systemEvent, record.RecordId ?? 0));
            }
        }

        return collected;
    }

    public static bool IsChannelEnabled(string channel)
    {
        try
        {
            using var configuration = new EventLogConfiguration(channel);
            return configuration.IsEnabled;
        }
        catch (EventLogException)
        {
            return false;
        }
    }

    private static SystemEvent? Interpret(EventSource source, EventRecord record)
    {
        var data = ReadData(record);
        string Value(string name) => data.Named.GetValueOrDefault(name) ?? string.Empty;
        string Positional(int index) => index < data.Positional.Count ? data.Positional[index] : string.Empty;

        var systemEvent = new SystemEvent
        {
            OccurredAt = (record.TimeCreated ?? DateTime.Now).ToUniversalTime(),
            Channel = Truncate(source.Channel, 128)!,
            EventId = record.Id,
            Level = record.Level ?? 4,
            Provider = Truncate(record.ProviderName ?? string.Empty, 256)!
        };

        switch (source.Name, record.Id)
        {
            case ("system", 7045):
                systemEvent.Category = SystemEventCategory.Service;
                systemEvent.Subject = Value("ServiceName");
                systemEvent.ProgramPath = ExecutablePath(Value("ImagePath"));
                systemEvent.Summary = $"New service \"{Value("ServiceName")}\" was installed. It runs {Value("ImagePath")} as {Value("AccountName")}.";
                break;
            case ("system", 7031 or 7034):
                systemEvent.Category = SystemEventCategory.Service;
                systemEvent.Subject = Value("param1");
                systemEvent.Summary = $"The {Value("param1")} service stopped unexpectedly.";
                break;
            case ("system", 41):
                systemEvent.Category = SystemEventCategory.Stability;
                systemEvent.Summary = "Windows restarted without shutting down cleanly (a crash, freeze or power loss).";
                break;
            case ("system", 6008):
                systemEvent.Category = SystemEventCategory.Stability;
                systemEvent.Summary = "The previous shutdown was unexpected.";
                break;
            case ("system", 104):
                systemEvent.Category = SystemEventCategory.Security;
                systemEvent.Subject = Value("Channel");
                systemEvent.Summary = $"The {Value("Channel")} event log was cleared by {Value("SubjectDomainName")}\\{Value("SubjectUserName")}.";
                break;
            case ("system-disk", _):
                systemEvent.Category = SystemEventCategory.Disk;
                systemEvent.Subject = record.ProviderName;
                systemEvent.Summary = $"Disk or file system problem reported by {record.ProviderName}: {Describe(record)}";
                break;
            case ("security", 4625):
                systemEvent.Category = SystemEventCategory.Security;
                systemEvent.Subject = $"{Value("TargetDomainName")}\\{Value("TargetUserName")}".Trim('\\');
                var address = Value("IpAddress");
                systemEvent.RemoteAddress = address is "" or "-" or "::1" or "127.0.0.1" ? null : address;
                systemEvent.ProgramPath = ExecutablePath(Value("ProcessName"));
                systemEvent.Summary = $"Failed sign-in for {systemEvent.Subject} from {systemEvent.RemoteAddress ?? "this computer"}.";
                break;
            case ("security", 4720):
                systemEvent.Category = SystemEventCategory.Account;
                systemEvent.Subject = Value("TargetUserName");
                systemEvent.Summary = $"User account {Value("TargetUserName")} was created by {Value("SubjectUserName")}.";
                break;
            case ("security", 4728 or 4732 or 4756):
                systemEvent.Category = SystemEventCategory.Account;
                systemEvent.Subject = Value("TargetUserName");
                var member = Value("MemberName") is "" or "-" ? Value("MemberSid") : Value("MemberName");
                systemEvent.Summary = $"{member} was added to the {Value("TargetUserName")} group by {Value("SubjectUserName")}.";
                break;
            case ("security", 1102):
                systemEvent.Category = SystemEventCategory.Security;
                systemEvent.Subject = "Security";
                systemEvent.Summary = $"The Security event log was cleared by {Value("SubjectDomainName")}\\{Value("SubjectUserName")}.";
                break;
            case ("defender", 1116 or 1117 or 1118 or 1119):
                systemEvent.Category = SystemEventCategory.Defender;
                systemEvent.Subject = Value("Threat Name");
                systemEvent.ProgramPath = Value("Path");
                systemEvent.Summary = record.Id switch
                {
                    1116 => $"Microsoft Defender found {Value("Threat Name")} ({Value("Severity Name")}) in {Value("Path")}.",
                    1117 => $"Microsoft Defender dealt with {Value("Threat Name")}: {Value("Action Name")}.",
                    _ => $"Microsoft Defender could NOT remove {Value("Threat Name")} from {Value("Path")}: {Value("Error Description")}."
                };
                break;
            case ("defender", 5001 or 5010 or 5012):
                systemEvent.Category = SystemEventCategory.Defender;
                systemEvent.Subject = record.Id switch { 5001 => "Real-time protection", 5010 => "Spyware scanning", _ => "Virus scanning" };
                systemEvent.Summary = $"Microsoft Defender {systemEvent.Subject.ToLowerInvariant()} was turned off.";
                break;
            case ("tasks", 106):
                systemEvent.Category = SystemEventCategory.ScheduledTask;
                systemEvent.Subject = Value("TaskName");
                systemEvent.Summary = $"Scheduled task {Value("TaskName")} was created by {Value("UserContext")}.";
                break;
            case ("application", 1000):
                systemEvent.Category = SystemEventCategory.AppCrash;
                systemEvent.Subject = Positional(0);
                systemEvent.ProgramPath = Positional(10) is { Length: > 0 } faultingPath ? faultingPath : null;
                systemEvent.Summary = $"{Positional(0)} crashed (in {Positional(3)}).";
                break;
            case ("application", 1002):
                systemEvent.Category = SystemEventCategory.AppCrash;
                systemEvent.Subject = Positional(0);
                systemEvent.Summary = $"{Positional(0)} stopped responding and was closed.";
                break;
            default:
                return null;
        }

        systemEvent.Subject = Truncate(systemEvent.Subject, 512);
        systemEvent.ProgramPath = Truncate(systemEvent.ProgramPath, 2048);
        systemEvent.RemoteAddress = Truncate(systemEvent.RemoteAddress, 64);
        systemEvent.Summary = Truncate(systemEvent.Summary, 2048)!;
        return systemEvent;
    }

    /// <summary>
    /// The alert an event should raise, or null when it is context only.
    /// </summary>
    public static (string Rule, AlertSeverity Severity, string Title)? AlertFor(SystemEvent systemEvent)
    {
        return (systemEvent.Channel, systemEvent.EventId) switch
        {
            ("System", 104) or ("Security", 1102) => ("LogCleared", AlertSeverity.High, $"The {systemEvent.Subject} event log was cleared"),
            ("System", 7045) => ("NewService", AlertSeverity.Medium, $"New service installed: {systemEvent.Subject}"),
            (DefenderChannel, 1116 or 1117) => ("DefenderDetection", AlertSeverity.Medium, $"Microsoft Defender caught {systemEvent.Subject}"),
            (DefenderChannel, 1118 or 1119) => ("DefenderActionFailed", AlertSeverity.Critical, $"Microsoft Defender could not remove {systemEvent.Subject}"),
            (DefenderChannel, 5001 or 5010 or 5012) => ("ProtectionDisabled", AlertSeverity.High, $"Microsoft Defender {systemEvent.Subject?.ToLowerInvariant()} was turned off"),
            (TaskSchedulerChannel, 106) => ("NewScheduledTask", AlertSeverity.Medium, $"New scheduled task: {systemEvent.Subject}"),
            ("Security", 4720) => ("AccountChange", AlertSeverity.Medium, $"New user account: {systemEvent.Subject}"),
            ("Security", 4728 or 4732 or 4756) when systemEvent.Subject != null && PowerfulGroups.Contains(systemEvent.Subject)
                => ("AccountChange", AlertSeverity.High, $"Someone was added to {systemEvent.Subject}"),
            _ => null
        };
    }

    /// <summary>
    /// Named EventData/UserData values, plus the values in order for events whose data has no names.
    /// </summary>
    private static (Dictionary<string, string> Named, List<string> Positional) ReadData(EventRecord record)
    {
        var named = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var positional = new List<string>();
        try
        {
            var document = XDocument.Parse(record.ToXml());
            foreach (var dataElement in document.Descendants(EventNamespace + "Data"))
            {
                var value = dataElement.Value.Trim();
                positional.Add(value);
                var name = dataElement.Attribute("Name")?.Value;
                if (name != null)
                    named[name] = value;
            }

            // UserData (used by 104 and 1102) has one element per value.
            var userData = document.Root?.Element(EventNamespace + "UserData");
            foreach (var leaf in userData?.Descendants().Where(element => !element.HasElements) ?? [])
                named.TryAdd(leaf.Name.LocalName, leaf.Value.Trim());
        }
        catch (Exception exception) when (exception is System.Xml.XmlException or EventLogException)
        {
        }

        return (named, positional);
    }

    private static string Describe(EventRecord record)
    {
        try
        {
            return Truncate(record.FormatDescription(), 400) ?? $"event {record.Id}";
        }
        catch (EventLogException)
        {
            return $"event {record.Id}";
        }
    }

    /// <summary>
    /// The folder of a scheduled task, such as \Microsoft\Windows\UpdateOrchestrator\, or the root folder.
    /// </summary>
    public static string TaskFolder(string? taskName)
    {
        if (string.IsNullOrEmpty(taskName))
            return @"\";

        var lastSeparator = taskName.LastIndexOf('\\');
        return lastSeparator <= 0 ? @"\" : taskName[..(lastSeparator + 1)];
    }

    /// <summary>
    /// The program file from a command line such as "C:\Program Files\App\app.exe" -k service.
    /// </summary>
    public static string? ExecutablePath(string commandLine)
    {
        var text = Environment.ExpandEnvironmentVariables(commandLine.Trim());
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

    private static string? Truncate(string? text, int maximumLength)
    {
        if (text == null)
            return null;

        return text.Length <= maximumLength ? text : text[..(maximumLength - 1)] + "…";
    }
}
