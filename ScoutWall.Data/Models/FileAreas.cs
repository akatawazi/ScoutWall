using System.ComponentModel.DataAnnotations;
using System.Text.Json;

namespace ScoutWall.Data.Models;

/// <summary>
/// Where on the computer a file lives, from the owner's point of view.
/// </summary>
public enum FileArea
{
    /// <summary>
    /// The owner's own files: their profile folders (Documents, Desktop, Downloads and so on, wherever Windows points
    /// them), OneDrive, Users\Public, other data drives, and any folder they add.
    /// </summary>
    MyFiles = 1,

    /// <summary>
    /// Program data and settings: AppData, dot-folders in the profile, and ProgramData. Anyone can write here,
    /// which also makes it where malware is often unpacked.
    /// </summary>
    AppData = 2,

    ProgramFiles = 3,
    Windows = 4,
    Other = 5
}

/// <summary>
/// The folders that decide each area on this computer. The sensor reads them from Windows (each user's
/// "User Shell Folders" and OneDrive accounts, so moved Documents folders are found) and stores them, so the
/// console can show what counts as "my files".
/// </summary>
public class FileAreaRules
{
    public const string StateKey = "file_area_rules";

    public DateTime FoundAt { get; set; }
    public string SystemDrive { get; set; } = @"C:";
    public string WindowsFolder { get; set; } = @"C:\Windows";
    public List<string> ProgramFilesFolders { get; set; } = [];
    public string ProgramDataFolder { get; set; } = @"C:\ProgramData";
    public List<string> ProfileFolders { get; set; } = [];

    /// <summary>
    /// Personal folders found in Windows (Documents, Desktop, Downloads, Pictures, Videos, Music, OneDrive).
    /// </summary>
    public List<string> PersonalFolders { get; set; } = [];

    /// <summary>
    /// Folders the owner added in settings.
    /// </summary>
    public List<string> ExtraFolders { get; set; } = [];

    public IEnumerable<string> MyFolders => PersonalFolders.Concat(ExtraFolders).Distinct(StringComparer.OrdinalIgnoreCase);

    public FileArea Classify(string path)
    {
        if (IsInside(path, WindowsFolder))
            return FileArea.Windows;
        if (ProgramFilesFolders.Any(folder => IsInside(path, folder)))
            return FileArea.ProgramFiles;
        if (IsInside(path, ProgramDataFolder))
            return FileArea.AppData;
        if (MyFolders.Any(folder => IsInside(path, folder)))
            return FileArea.MyFiles;

        foreach (var profile in ProfileFolders)
        {
            if (!IsInside(path, profile))
                continue;

            // Files right in the profile folder are settings (NTUSER.DAT, the registry, is written constantly).
            var rest = path[(profile.TrimEnd('\\').Length + 1)..];
            var firstFolder = rest.Split('\\')[0];
            return !rest.Contains('\\') || firstFolder.Equals("AppData", StringComparison.OrdinalIgnoreCase) || firstFolder.StartsWith('.')
                ? FileArea.AppData
                : FileArea.MyFiles;
        }

        if (path.Length < 4 || path[1] != ':' || path[2] != '\\')
            return FileArea.Other;

        // Folders people make at the top of a drive (C:\AI, D:\Photos) are their own files; the drive's own
        // system folders and loose files at the top of the system drive are not.
        var rootFolder = path[3..].Split('\\')[0];
        var isOnSystemDrive = path.StartsWith(SystemDrive, StringComparison.OrdinalIgnoreCase);
        var isLooseRootFile = !path[3..].Contains('\\');
        if (rootFolder.StartsWith('$') || rootFolder.StartsWith('(') || SystemRootFolders.Contains(rootFolder) || (isOnSystemDrive && isLooseRootFile))
            return FileArea.Other;

        return FileArea.MyFiles;
    }

    /// <summary>
    /// Folders Windows, installers and drivers keep at the top of a drive.
    /// </summary>
    public static readonly IReadOnlySet<string> SystemRootFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "System Volume Information", "Recovery", "PerfLogs", "Boot", "Config.Msi", "MSOCache", "Intel", "AMD", "NVIDIA",
        "inetpub", "OneDriveTemp", "ESD", "Windows.old", "$WINDOWS.~BT", "$WinREAgent", "Documents and Settings", "ProgramData", "Drivers"
    };

    public static bool IsInside(string path, string folder)
    {
        if (string.IsNullOrEmpty(folder))
            return false;

        var prefix = folder.TrimEnd('\\') + @"\";
        return path.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    public static async Task<FileAreaRules> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new FileAreaRules();

        try
        {
            return JsonSerializer.Deserialize<FileAreaRules>(json) ?? new FileAreaRules();
        }
        catch (JsonException)
        {
            return new FileAreaRules();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }

    public static string Label(FileArea area) => area switch
    {
        FileArea.MyFiles => "My files",
        FileArea.AppData => "App data",
        FileArea.ProgramFiles => "Program Files",
        FileArea.Windows => "Windows",
        _ => "Other"
    };
}

/// <summary>
/// What the owner chose about file tracking.
/// </summary>
public class FileTrackingSettings : ISettingsSection<FileTrackingSettings>
{
    /// <summary>
    /// Record which programs read the owner's files. Off until the owner turns it on: it switches on Windows file
    /// auditing, marks the personal folders for auditing and makes the Security log bigger; turning it off undoes all three.
    /// </summary>
    public bool ReadTrackingEnabled { get; set; }

    /// <summary>
    /// More folders that count as "my files", such as D:\Photos.
    /// </summary>
    public List<string> ExtraMyFilesFolders { get; set; } = [];

    [MaxLength(4000)]
    public string ExtraMyFilesFoldersText
    {
        get => string.Join(Environment.NewLine, ExtraMyFilesFolders);
        set => ExtraMyFilesFolders = (value ?? string.Empty)
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(folder => folder.Length > 2 && folder[1] == ':')
            .Select(folder => folder.TrimEnd('\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public void PrepareForSave(FileTrackingSettings existingSection)
    {
    }
}

/// <summary>
/// What read tracking has changed on this computer, so it can be undone exactly, and how it is doing.
/// </summary>
public class FileReadAuditState
{
    public const string StateKey = "file_read_audit";

    public bool Applied { get; set; }
    public DateTime? AppliedAt { get; set; }
    public uint PreviousPolicyFlags { get; set; }
    public long PreviousSecurityLogBytes { get; set; }
    public long SecurityLogBytes { get; set; }
    public List<string> AuditedFolders { get; set; } = [];

    /// <summary>
    /// The last Security log record read, so each event is counted once.
    /// </summary>
    public long LastRecordId { get; set; }

    /// <summary>
    /// False when something (usually Group Policy) has switched file auditing off again.
    /// </summary>
    public bool PolicyOn { get; set; }
    public DateTime? CheckedAt { get; set; }
    public string? LastError { get; set; }

    /// <summary>
    /// Reads by indexing, antivirus and sync programs, counted rather than listed: program name to count, today.
    /// </summary>
    public Dictionary<string, long> BackgroundReadsToday { get; set; } = [];
    public DateTime BackgroundReadsDay { get; set; }

    public static async Task<FileReadAuditState> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new FileReadAuditState();

        try
        {
            return JsonSerializer.Deserialize<FileReadAuditState>(json) ?? new FileReadAuditState();
        }
        catch (JsonException)
        {
            return new FileReadAuditState();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }
}
