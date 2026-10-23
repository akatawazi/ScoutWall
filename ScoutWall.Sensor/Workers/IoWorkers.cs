using System.Diagnostics.Eventing.Reader;
using System.Security.AccessControl;
using System.Text.Json;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Analyst;
using ScoutWall.Sensor.SystemHealth;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Records how much each physical disk reads and writes every minute, and keeps drive free space current.
/// </summary>
public class DiskActivityWorker : SensorWorker
{
    private static readonly TimeSpan SpaceInterval = TimeSpan.FromMinutes(5);
    private readonly DiskPerformance diskPerformance = new();
    private DateTime lastSpaceCheck;

    public DiskActivityWorker(SensorRuntime sensorRuntime, ILogger<DiskActivityWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(30);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var now = DateTime.UtcNow;
        var activity = diskPerformance.Sample();
        await using var dataContext = SensorRuntime.CreateDataContext();

        if (activity.Count > 0)
        {
            var nowUnixSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var minuteBucket = nowUnixSeconds - nowUnixSeconds % 60;
            await DiskIoMinute.Record(dataContext, activity.Select(disk => new DiskIoMinute
            {
                BucketStart = minuteBucket,
                DiskNumber = disk.DiskNumber,
                Drives = disk.Drives,
                ReadBytes = disk.ReadBytes,
                WriteBytes = disk.WriteBytes,
                ReadCount = disk.ReadCount,
                WriteCount = disk.WriteCount,
                BusyPercent = disk.BusyPercent,
                QueueDepth = disk.QueueDepth
            }).ToList());
        }

        if (now - lastSpaceCheck >= SpaceInterval)
        {
            lastSpaceCheck = now;
            var snapshot = new DriveSpaceSnapshot
            {
                TakenAt = now,
                Drives = DiskPerformance.ReadDriveSpace().Select(drive => new DriveSpaceEntry
                {
                    Name = drive.Name,
                    Label = drive.Label,
                    Format = drive.Format,
                    TotalBytes = drive.TotalBytes,
                    FreeBytes = drive.FreeBytes
                }).ToList()
            };
            await snapshot.Save(dataContext);
        }
    }
}

/// <summary>
/// Reads every NTFS drive's change journal, records which files were created, changed, deleted and renamed (and by
/// which program, where known), and raises the two file-activity alerts:
/// <list type="bullet">
/// <item>FileExtensionRenames (High): many files renamed to one new extension from several old ones, or a handful of
/// documents, photos or music given a new extension, which is how ransomware leaves files. Raised to Critical when
/// nobody is at the computer. Installs and updates by verified, signed programs that leave the owner's data alone
/// are not reported.</item>
/// <item>MassFileChange (Medium): one program changing hundreds of personal files, or deleting dozens of data files,
/// within two minutes. High when nobody is at the computer or data files were deleted. Sync and backup programs
/// are left out.</item>
/// </list>
/// Nothing is ended or blocked automatically; the alerts offer End and Block from running.
/// </summary>
public class FileActivityWorker : SensorWorker
{
    private const string PositionsStateKey = "change_journal_positions";
    private const int RecordsPerPass = 100_000;
    private const int RowsPerMinute = 2000;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(30);
    private const int RenameThreshold = 30;
    private const int MassChangeThreshold = 200;
    private const int DataRenameThreshold = 10;
    private const int DataDeleteThreshold = 50;

    /// <summary>
    /// Programs whose job is to change many files: sync clients, backup and version control.
    /// </summary>
    private static readonly HashSet<string> BulkFilePrograms = new(StringComparer.OrdinalIgnoreCase)
    {
        "OneDrive.exe", "Dropbox.exe", "GoogleDriveFS.exe", "iCloudDrive.exe", "iCloudServices.exe", "Box.exe", "BoxSync.exe",
        "git.exe", "explorer.exe", "robocopy.exe", "MsMpEng.exe", "SearchIndexer.exe", "TiWorker.exe", "TrustedInstaller.exe"
    };

    private static readonly string[] NoiseFragments =
    [
        @"\Windows\Prefetch\", @"\Windows\Logs\", @"\Windows\System32\LogFiles\", @"\Windows\System32\winevt\Logs\",
        @"\Windows\SoftwareDistribution\DataStore\", @"\ProgramData\Microsoft\Windows Defender\Scans\",
        @"\ProgramData\Microsoft\Diagnosis\", @"\ProgramData\Microsoft\Search\Data\",
        @"\Cache\Cache_Data\", @"\Code Cache\", @"\GPUCache\", @"\Service Worker\CacheStorage\", @"\Service Worker\ScriptCache\",
        @"\cache2\entries\", @"\INetCache\", @"\WebCache\", @"\Microsoft\Windows\Explorer\thumbcache", @"\Microsoft\Windows\Notifications\",
        @"\.git\objects\", @"\System Volume Information\"
    ];

    private static readonly HashSet<string> NoiseFileNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "pagefile.sys", "hiberfil.sys", "swapfile.sys", "DumpStack.log.tmp"
    };

    private const string WindowsInstallerRollbackFolder = @":\Config.Msi\";

    private static readonly TimeSpan RulesInterval = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Build output and version control churn through thousands of files; they never count toward MassFileChange.
    /// </summary>
    private static readonly string[] BuildFragments =
        [@"\bin\", @"\obj\", @"\node_modules\", @"\.git\", @"\.vs\", @"\packages\", @"\.nuget\", @"\target\", @"\dist\", @"\__pycache__\"];

    private static readonly HashSet<string> BuildPrograms = new(StringComparer.OrdinalIgnoreCase)
    {
        "MSBuild.exe", "VBCSCompiler.exe", "dotnet.exe", "devenv.exe", "node.exe", "npm.exe", "cl.exe", "link.exe", "python.exe", "cargo.exe"
    };

    private readonly Dictionary<string, ChangeJournal> journals = new(StringComparer.OrdinalIgnoreCase);
    private FileAreaRules areaRules = new();
    private DateTime rulesFoundAt;
    private string extraFoldersSeen = string.Empty;
    private readonly List<(DateTime At, JournalChange Change, string? ImagePath)> recent = [];
    private readonly Dictionary<string, DateTime> lastAlerts = [];
    private readonly string scoutWallDataFolder = Path.GetDirectoryName(DataContext.ResolveDatabasePath(null)) ?? string.Empty;
    private bool warnedAboutAccess;

    public FileActivityWorker(SensorRuntime sensorRuntime, ILogger<FileActivityWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(15);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        await RefreshAreaRules(dataContext);
        var positions = await LoadPositions(dataContext);
        OpenJournals(positions);

        var now = DateTime.UtcNow;
        var counts = new Dictionary<(long Bucket, string Path, FileChangeKind Kind), (string? OldPath, string? ImagePath, int Count)>();
        foreach (var journal in journals.Values)
        {
            foreach (var change in journal.ReadNew(RecordsPerPass))
            {
                if (IsNoise(change.Path))
                    continue;

                var imagePath = change.Kind == FileChangeKind.Modified ? null : FileActors.Find(change.Path) ?? (change.OldPath != null ? FileActors.Find(change.OldPath) : null);
                var changedUnix = new DateTimeOffset(change.ChangedAt).ToUnixTimeSeconds();
                var key = (changedUnix - changedUnix % FileChange.BucketSeconds, change.Path, change.Kind);
                var existing = counts.GetValueOrDefault(key);
                counts[key] = (existing.OldPath ?? change.OldPath, existing.ImagePath ?? imagePath, existing.Count + 1);

                if (now - change.ChangedAt <= Window)
                    recent.Add((change.ChangedAt, change, imagePath));
            }

            positions[journal.Drive] = new JournalPosition { JournalId = journal.JournalId, NextUsn = journal.NextUsn };
        }

        FileActors.Prune(now);
        await FileChange.Record(dataContext, Cap(counts, areaRules));
        await SystemState.SetValue(dataContext, PositionsStateKey, JsonSerializer.Serialize(positions));

        recent.RemoveAll(entry => now - entry.At > Window);
        await Detect(now);
    }

    /// <summary>
    /// At most a set number of rows per minute: every create, delete and rename first, then the most-changed files.
    /// </summary>
    private static List<FileChangeCount> Cap(Dictionary<(long Bucket, string Path, FileChangeKind Kind), (string? OldPath, string? ImagePath, int Count)> counts, FileAreaRules rules)
    {
        return counts
            .GroupBy(entry => entry.Key.Bucket)
            .SelectMany(minute => minute
                .OrderBy(entry => entry.Key.Kind == FileChangeKind.Modified ? 1 : 0)
                .ThenByDescending(entry => entry.Value.Count)
                .Take(RowsPerMinute))
            .Select(entry => new FileChangeCount(entry.Key.Bucket, entry.Key.Path, entry.Key.Kind, entry.Value.OldPath, entry.Value.ImagePath, entry.Value.Count,
                rules.Classify(entry.Key.Path)))
            .ToList();
    }

    /// <summary>
    /// Re-reads where the owner's folders are every few minutes, and at once when they add folders in settings.
    /// </summary>
    private async Task RefreshAreaRules(DataContext dataContext)
    {
        var extraFolders = SensorRuntime.Configuration.FileTracking.ExtraMyFilesFolders;
        var extraKey = string.Join("|", extraFolders);
        if (DateTime.UtcNow - rulesFoundAt < RulesInterval && extraKey == extraFoldersSeen)
            return;

        areaRules = MyFolders.Discover(extraFolders);
        rulesFoundAt = DateTime.UtcNow;
        extraFoldersSeen = extraKey;
        await areaRules.Save(dataContext);
    }

    private void OpenJournals(Dictionary<string, JournalPosition> positions)
    {
        if (journals.Count > 0)
            return;

        foreach (var drive in DriveInfo.GetDrives())
        {
            try
            {
                if (drive.DriveType != DriveType.Fixed || !drive.IsReady || drive.DriveFormat != "NTFS")
                    continue;
            }
            catch (IOException)
            {
                continue;
            }

            var letter = drive.Name.TrimEnd('\\');
            var journal = ChangeJournal.Open(letter);
            if (journal == null)
                continue;

            if (positions.TryGetValue(letter, out var position) && journal.ResumeFrom(position.JournalId, position.NextUsn))
                Logger.LogInformation("Catching up on file changes on {Drive} since the sensor last ran", letter);

            journals[letter] = journal;
        }

        if (journals.Count == 0 && !warnedAboutAccess)
        {
            warnedAboutAccess = true;
            Logger.LogWarning("File change tracking needs the sensor to run as administrator on NTFS drives; no change journal could be opened");
        }
    }

    private bool IsNoise(string path)
    {
        if (scoutWallDataFolder.Length > 0 && path.StartsWith(scoutWallDataFolder, StringComparison.OrdinalIgnoreCase))
            return true;

        var name = Path.GetFileName(path);
        if (NoiseFileNames.Contains(name) || name.EndsWith(".etl", StringComparison.OrdinalIgnoreCase))
            return true;

        // NTFS's own files at the root of a drive ($Extend, $LogFile and so on).
        if (path.Length > 3 && path[2] == '\\' && path[3] == '$' && path.IndexOf('\\', 3) < 0)
            return true;

        return NoiseFragments.Any(fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    private async Task Detect(DateTime now)
    {
        var away = SensorRuntime.Idle.IsIdle == true;

        // Many files renamed to the same new extension, coming from several different ones. Windows Installer moves
        // every file it replaces into Config.Msi as a .rbf rollback copy, which looks the same, so those are left out,
        // and so are program files (DLLs, executables) that updates set aside before replacing them.
        var extensionRenames = recent
            .Where(entry => entry.Change.Kind == FileChangeKind.Renamed && entry.Change.OldPath != null
                && !entry.Change.Path.Contains(WindowsInstallerRollbackFolder, StringComparison.OrdinalIgnoreCase)
                && FileKinds.Classify(entry.Change.OldPath) != FileKind.Routine)
            .Select(entry => (entry, OldExtension: Path.GetExtension(entry.Change.OldPath!), NewExtension: Path.GetExtension(entry.Change.Path)))
            .Where(rename => FileChange.IsExtensionChange(rename.entry.Change.OldPath, rename.entry.Change.Path))
            .GroupBy(rename => rename.NewExtension.ToLowerInvariant());
        foreach (var group in extensionRenames)
        {
            var files = group.Select(rename => rename.entry.Change.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var oldExtensions = group.Select(rename => rename.OldExtension.ToLowerInvariant()).Distinct().Count();

            // Documents, photos and music given an extension that isn't a document, photo or song is what scrambled
            // files look like, even when they were all one kind (a folder of .docx files), so fewer are enough.
            var dataFiles = group.Where(rename => FileKinds.Classify(rename.entry.Change.OldPath) == FileKind.Data)
                .Select(rename => rename.entry.Change.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var scrambledData = dataFiles >= DataRenameThreshold && FileKinds.FromExtension(group.Key) != FileKind.Data;
            if (!scrambledData && (files < RenameThreshold || oldExtensions < 2))
                continue;

            var program = group.Select(rename => rename.entry.ImagePath).OfType<string>().GroupBy(path => path, StringComparer.OrdinalIgnoreCase)
                .OrderByDescending(paths => paths.Count()).FirstOrDefault()?.Key;
            var programName = program == null ? "An unknown program" : Path.GetFileName(program);

            // A program installed where only administrators can write, with a signature Windows verifies, renaming
            // files outside the owner's own folders is installing or updating software. Ransomware wants the owner's
            // data; when that is touched the alert is still raised, because an installer runs whatever custom code
            // the package brings inside msiexec.exe.
            var signer = TrustedSigner(program);
            var touchesMyFiles = dataFiles > 0 || group.Any(rename => areaRules.Classify(rename.entry.Change.Path) == FileArea.MyFiles);
            if (signer != null && !touchesMyFiles)
                continue;

            // Data files first in the examples: they are what the owner will recognise.
            var examples = group.OrderByDescending(rename => FileKinds.Classify(rename.entry.Change.OldPath) == FileKind.Data).Take(3)
                .Select(rename => $"{Path.GetFileName(rename.entry.Change.OldPath)} → {Path.GetFileName(rename.entry.Change.Path)}");
            await Raise("FileExtensionRenames", group.Key + (program ?? string.Empty), away ? AlertSeverity.Critical : AlertSeverity.High,
                $"{programName} renamed {files} files to {group.Key}",
                $"{files} files were renamed to the extension {group.Key} within two minutes, from {oldExtensions} different kinds of file " +
                $"(for example {string.Join(", ", examples)})" +
                (dataFiles > 0 ? $"; {dataFiles} of them were documents, photos, music or other data files. " : ". ") +
                "Ransomware leaves files like this after scrambling them. " +
                (signer != null ? "The program is genuine signed software, but it renamed your own files, so check that you were installing or updating something. " : string.Empty) +
                $"{(away ? "Nobody was at the computer. " : string.Empty)}If you didn't expect this, end the program and disconnect the computer from the network.",
                group.Key, program, now, new { files, dataFiles, newExtension = group.Key, oldExtensions, examples, away, signer });
        }

        // One program changing a large number of personal files, or deleting a good number of documents, photos and
        // music. Program files and logs inside personal folders (a portable app, a game in Documents) don't count.
        var personalChanges = recent
            .Where(entry => areaRules.Classify(entry.Change.Path) == FileArea.MyFiles
                && FileKinds.Classify(entry.Change.Path) != FileKind.Routine
                && !BuildFragments.Any(fragment => entry.Change.Path.Contains(fragment, StringComparison.OrdinalIgnoreCase)))
            .GroupBy(entry => entry.ImagePath ?? string.Empty, StringComparer.OrdinalIgnoreCase);
        foreach (var group in personalChanges)
        {
            var program = group.Key.Length == 0 ? null : group.Key;
            if (program != null && (BulkFilePrograms.Contains(Path.GetFileName(program)) || BuildPrograms.Contains(Path.GetFileName(program))))
                continue;

            var files = group.Select(entry => entry.Change.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var dataDeleted = group.Where(entry => entry.Change.Kind == FileChangeKind.Deleted && FileKinds.Classify(entry.Change.Path) == FileKind.Data)
                .Select(entry => entry.Change.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (files < MassChangeThreshold && dataDeleted < DataDeleteThreshold)
                continue;

            var programName = program == null ? "Programs ScoutWall couldn't identify" : Path.GetFileName(program);
            var folders = group.Select(entry => Path.GetDirectoryName(entry.Change.Path)).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            var deleted = group.Count(entry => entry.Change.Kind == FileChangeKind.Deleted);
            var dataFiles = group.Where(entry => FileKinds.Classify(entry.Change.Path) == FileKind.Data)
                .Select(entry => entry.Change.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count();
            await Raise("MassFileChange", program ?? "(unknown)", away || dataDeleted >= DataDeleteThreshold ? AlertSeverity.High : AlertSeverity.Medium,
                dataDeleted >= DataDeleteThreshold
                    ? $"{programName} deleted {dataDeleted} of your documents, photos or other data files"
                    : $"{programName} changed {files} personal files in two minutes",
                $"{files} of your own files (Documents, Desktop, Pictures and the like) across {folders} folders were changed, " +
                $"{deleted} of them deleted, within two minutes{(away ? ", while nobody was at the computer" : string.Empty)}. " +
                $"{dataFiles} were documents, photos, music or other data files ({dataDeleted} deleted). " +
                "Copying, moving or syncing a folder does this too; if you weren't doing that, look at the I/O page and check the Recycle Bin.",
                programName, program, now, new { files, dataFiles, folders, deleted, dataDeleted, away });
        }
    }

    /// <summary>
    /// Who signed the program, when it lives in Windows or Program Files and Windows verifies the signature.
    /// </summary>
    private static string? TrustedSigner(string? programPath)
    {
        if (programPath == null || !TrustedPaths.IsInProtectedFolder(programPath))
            return null;

        var programFileInfo = ProgramIdentity.Read(programPath);
        return programFileInfo is { PublisherVerified: true } ? programFileInfo.Publisher : null;
    }

    private async Task Raise(string rule, string key, AlertSeverity severity, string title, string description, string subject, string? programPath, DateTime now, object details)
    {
        if (!SensorRuntime.IsRuleEnabled(rule))
            return;

        var alertKey = $"{rule}|{key}";
        if (lastAlerts.TryGetValue(alertKey, out var lastAt) && now - lastAt < AlertCooldown)
            return;

        lastAlerts[alertKey] = now;
        await SensorRuntime.AlertQueue.Writer.WriteAsync(HostAlerts.Create(rule, severity, title, description, subject, programPath, now, details));
    }

    private static async Task<Dictionary<string, JournalPosition>> LoadPositions(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, PositionsStateKey);
        if (json == null)
            return new Dictionary<string, JournalPosition>(StringComparer.OrdinalIgnoreCase);

        try
        {
            return new Dictionary<string, JournalPosition>(
                JsonSerializer.Deserialize<Dictionary<string, JournalPosition>>(json) ?? [], StringComparer.OrdinalIgnoreCase);
        }
        catch (JsonException)
        {
            return new Dictionary<string, JournalPosition>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public override void Dispose()
    {
        foreach (var journal in journals.Values)
            journal.Dispose();
        base.Dispose();
    }

    private sealed class JournalPosition
    {
        public ulong JournalId { get; set; }
        public long NextUsn { get; set; }
    }
}

/// <summary>
/// Read tracking for the owner's files. Applies or undoes the Windows audit settings to match the owner's choice,
/// notices when Group Policy switches auditing back off, and turns "file read" audit events (4663 with read access)
/// into rows on the I/O page. Indexing, antivirus and sync programs read everything, so they are only counted.
/// </summary>
public class FileReadWorker : SensorWorker
{
    private const int EventsPerPass = 20_000;

    private static readonly HashSet<string> BackgroundReaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "MsMpEng.exe", "MpDefenderCoreService.exe", "NisSrv.exe", "MsSense.exe", "SearchProtocolHost.exe", "SearchIndexer.exe",
        "SearchFilterHost.exe", "OneDrive.exe", "OneDrive.Sync.Service.exe", "Dropbox.exe", "GoogleDriveFS.exe", "SgrmBroker.exe"
    };

    public FileReadWorker(SensorRuntime sensorRuntime, ILogger<FileReadWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(30);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        var state = await FileReadAuditState.Load(dataContext);
        var wanted = SensorRuntime.Configuration.FileTracking.ReadTrackingEnabled;
        var rules = await FileAreaRules.Load(dataContext);

        try
        {
            if (wanted)
            {
                var folders = rules.MyFolders.ToList();
                var firstTime = !state.Applied;
                if (firstTime || !folders.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(state.AuditedFolders))
                {
                    FileReadAudit.Apply(state, folders);
                    Logger.LogInformation("File read tracking is on for {Count} folders", state.AuditedFolders.Count);
                }

                // Start from now the first time, not from whatever the Security log already holds.
                if (firstTime)
                    state.LastRecordId = LatestRecordId();
            }
            else if (state.Applied)
            {
                FileReadAudit.Revert(state);
                Logger.LogInformation("File read tracking is off; Windows audit settings were put back");
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or InvalidOperationException or IOException
            or PrivilegeNotHeldException or EventLogException)
        {
            state.LastError = exception.Message;
            Logger.LogWarning("Could not change file read tracking: {Message}", exception.Message);
        }

        state.CheckedAt = DateTime.UtcNow;
        state.PolicyOn = state.Applied && FileReadAudit.IsPolicyOn();
        if (state.Applied)
            await ReadEvents(dataContext, state, rules);

        await state.Save(dataContext);
    }

    private async Task ReadEvents(DataContext dataContext, FileReadAuditState state, FileAreaRules rules)
    {
        var today = DateTime.UtcNow.Date;
        if (state.BackgroundReadsDay != today)
        {
            state.BackgroundReadsDay = today;
            state.BackgroundReadsToday.Clear();
        }

        var xpath = $"*[System[(EventID=4663) and (EventRecordID>{state.LastRecordId})]] and *[EventData[Data[@Name='AccessMask']='0x1']]";
        var query = new EventLogQuery("Security", PathType.LogName, xpath);
        var selector = new EventLogPropertySelector([
            "Event/EventData/Data[@Name='ObjectName']",
            "Event/EventData/Data[@Name='ProcessName']",
            "Event/EventData/Data[@Name='ObjectType']"
        ]);

        var counts = new Dictionary<(long Bucket, string Path, string Program), int>();
        var read = 0;
        using (var reader = new EventLogReader(query))
        {
            for (var record = reader.ReadEvent(); record != null && read < EventsPerPass; record = reader.ReadEvent(), read++)
            {
                using (record)
                {
                    state.LastRecordId = Math.Max(state.LastRecordId, record.RecordId ?? 0);
                    var values = ((EventLogRecord)record).GetPropertyValues(selector);
                    if (values[0] is not string path || values[1] is not string program || values[2] as string != "File")
                        continue;

                    if (BackgroundReaders.Contains(Path.GetFileName(program)))
                    {
                        var name = Path.GetFileName(program);
                        state.BackgroundReadsToday[name] = state.BackgroundReadsToday.GetValueOrDefault(name) + 1;
                        continue;
                    }

                    var occurred = new DateTimeOffset(record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow).ToUnixTimeSeconds();
                    var key = (occurred - occurred % FileChange.BucketSeconds, path, program);
                    counts[key] = counts.GetValueOrDefault(key) + 1;
                }
            }
        }

        await FileChange.Record(dataContext, counts
            .Select(entry => new FileChangeCount(entry.Key.Bucket, entry.Key.Path, FileChangeKind.Read, null, entry.Key.Program, entry.Value, rules.Classify(entry.Key.Path)))
            .ToList());
    }

    private static long LatestRecordId()
    {
        var query = new EventLogQuery("Security", PathType.LogName) { ReverseDirection = true };
        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent();
        return record?.RecordId ?? 0;
    }
}
