using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One physical disk's reads and writes in one minute, from the disk driver's own counters.
/// </summary>
[Table("disk_io_minutes")]
[Index(nameof(BucketStart), nameof(DiskNumber), IsUnique = true)]
public class DiskIoMinute : Repository<DiskIoMinute>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("disk_number")]
    public int DiskNumber { get; set; }

    /// <summary>
    /// The drive letters on this disk, such as "C:, D:".
    /// </summary>
    [Column("drives")]
    [MaxLength(64)]
    public string Drives { get; set; } = string.Empty;

    [Column("read_bytes")]
    public long ReadBytes { get; set; }

    [Column("write_bytes")]
    public long WriteBytes { get; set; }

    [Column("read_count")]
    public long ReadCount { get; set; }

    [Column("write_count")]
    public long WriteCount { get; set; }

    /// <summary>
    /// The share of the minute the disk was doing something, 0 to 100.
    /// </summary>
    [Column("busy_percent")]
    public double BusyPercent { get; set; }

    [Column("queue_depth")]
    public int QueueDepth { get; set; }

    [NotMapped]
    public string DisplayName => string.IsNullOrEmpty(Drives) ? $"Disk {DiskNumber}" : $"Disk {DiskNumber} ({Drives})";

    public static async Task Record(DataContext dataContext, IEnumerable<DiskIoMinute> minutes)
    {
        const string commandText = """
            INSERT INTO disk_io_minutes (bucket_start, disk_number, drives, read_bytes, write_bytes, read_count, write_count, busy_percent, queue_depth)
            VALUES ($bucketStart, $diskNumber, $drives, $readBytes, $writeBytes, $readCount, $writeCount, $busyPercent, $queueDepth)
            ON CONFLICT (bucket_start, disk_number) DO UPDATE SET
                read_bytes = read_bytes + excluded.read_bytes,
                write_bytes = write_bytes + excluded.write_bytes,
                read_count = read_count + excluded.read_count,
                write_count = write_count + excluded.write_count,
                busy_percent = MAX(busy_percent, excluded.busy_percent),
                queue_depth = MAX(queue_depth, excluded.queue_depth),
                drives = excluded.drives;
            """;

        await ExecuteBatch(dataContext, commandText, minutes, (parameters, minute) =>
        {
            parameters.AddWithValue("$bucketStart", minute.BucketStart);
            parameters.AddWithValue("$diskNumber", minute.DiskNumber);
            parameters.AddWithValue("$drives", minute.Drives);
            parameters.AddWithValue("$readBytes", minute.ReadBytes);
            parameters.AddWithValue("$writeBytes", minute.WriteBytes);
            parameters.AddWithValue("$readCount", minute.ReadCount);
            parameters.AddWithValue("$writeCount", minute.WriteCount);
            parameters.AddWithValue("$busyPercent", minute.BusyPercent);
            parameters.AddWithValue("$queueDepth", minute.QueueDepth);
        });
    }

    public static async Task<List<DiskIoPoint>> GetTimeline(DataContext dataContext, long sinceUnixSeconds, int stepSeconds)
    {
        return await Query(dataContext)
            .Where(minute => minute.BucketStart >= sinceUnixSeconds)
            .GroupBy(minute => new { Step = minute.BucketStart / stepSeconds, minute.DiskNumber })
            .Select(group => new DiskIoPoint
            {
                BucketStart = group.Key.Step * stepSeconds,
                DiskNumber = group.Key.DiskNumber,
                Drives = group.Max(minute => minute.Drives) ?? string.Empty,
                ReadBytes = group.Sum(minute => minute.ReadBytes),
                WriteBytes = group.Sum(minute => minute.WriteBytes),
                BusyPercent = group.Average(minute => minute.BusyPercent)
            })
            .OrderBy(point => point.BucketStart)
            .ToListAsync();
    }

    /// <summary>
    /// The most recent minute of every disk, for the "right now" figures.
    /// </summary>
    public static async Task<List<DiskIoMinute>> GetLatest(DataContext dataContext)
    {
        var latestBucket = await Query(dataContext).MaxAsync(minute => (long?)minute.BucketStart);
        return latestBucket == null ? [] : await GetAll(dataContext, minute => minute.BucketStart == latestBucket);
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, minute => minute.BucketStart < cutoffUnixSeconds);
    }
}

public class DiskIoPoint
{
    public long BucketStart { get; set; }
    public int DiskNumber { get; set; }
    public string Drives { get; set; } = string.Empty;
    public long ReadBytes { get; set; }
    public long WriteBytes { get; set; }
    public double BusyPercent { get; set; }

    public string DisplayName => string.IsNullOrEmpty(Drives) ? $"Disk {DiskNumber}" : $"Disk {DiskNumber} ({Drives})";
}

/// <summary>
/// Size and free space of every fixed drive, kept current by the sensor.
/// </summary>
public class DriveSpaceSnapshot
{
    public const string StateKey = "drive_space";

    public DateTime TakenAt { get; set; }
    public List<DriveSpaceEntry> Drives { get; set; } = [];

    public static async Task<DriveSpaceSnapshot> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new DriveSpaceSnapshot();

        try
        {
            return JsonSerializer.Deserialize<DriveSpaceSnapshot>(json) ?? new DriveSpaceSnapshot();
        }
        catch (JsonException)
        {
            return new DriveSpaceSnapshot();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }
}

public class DriveSpaceEntry
{
    public string Name { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public long TotalBytes { get; set; }
    public long FreeBytes { get; set; }

    public double FreeShare => TotalBytes == 0 ? 0 : (double)FreeBytes / TotalBytes;
    public bool IsLow => TotalBytes > 0 && FreeShare < 0.10;
    public string DisplayName => string.IsNullOrWhiteSpace(Label) ? Name : $"{Name} {Label}";
}

public enum FileChangeKind
{
    Created = 1,
    Modified = 2,
    Deleted = 3,
    Renamed = 4,

    /// <summary>
    /// A program read the file (only recorded for the owner's files, when read tracking is on).
    /// </summary>
    Read = 5
}

/// <summary>
/// How often a file was created, changed, deleted or renamed within one minute, from the NTFS change journal.
/// The program is known for creates, deletes and renames (from Kernel-File events), not for plain writes.
/// File names can reveal personal content, so these rows stay on this computer and are kept for a short time.
/// </summary>
[Table("file_changes")]
[Index(nameof(BucketStart), nameof(Path), nameof(Kind), IsUnique = true)]
[Index(nameof(ProcessImageId), nameof(BucketStart))]
[Index(nameof(Folder), nameof(BucketStart))]
[Index(nameof(Area), nameof(BucketStart))]
public class FileChange : Repository<FileChange>
{
    public const int BucketSeconds = 60;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("path")]
    [MaxLength(1024)]
    public string Path { get; set; } = string.Empty;

    [Column("folder")]
    [MaxLength(1024)]
    public string Folder { get; set; } = string.Empty;

    [Column("extension")]
    [MaxLength(32)]
    public string Extension { get; set; } = string.Empty;

    [Column("kind")]
    public FileChangeKind Kind { get; set; }

    /// <summary>
    /// For renames, the name before.
    /// </summary>
    [Column("old_path")]
    [MaxLength(1024)]
    public string? OldPath { get; set; }

    [Column("process_image_id")]
    public long? ProcessImageId { get; set; }

    [Column("change_count")]
    public int ChangeCount { get; set; }

    [Column("area")]
    public FileArea Area { get; set; } = FileArea.Other;

    [NotMapped]
    public ProcessImage? ProcessImage { get; set; }

    [NotMapped]
    public DateTime ChangedAt => DateTimeOffset.FromUnixTimeSeconds(BucketStart).UtcDateTime;

    [NotMapped]
    public bool IsImportant => ImportantFolders.Contains(Path);

    /// <summary>
    /// A rename that changed the extension, the pattern ransomware leaves behind.
    /// </summary>
    [NotMapped]
    public bool ChangedExtension => Kind == FileChangeKind.Renamed && IsExtensionChange(OldPath, Path);

    /// <summary>
    /// What the file holds. For renames, the old name says it better ("report.docx" renamed to "report.docx.locked").
    /// </summary>
    [NotMapped]
    public FileKind FileKind => Kind == FileChangeKind.Renamed && OldPath != null && FileKinds.Classify(OldPath) != FileKind.Other
        ? FileKinds.Classify(OldPath)
        : FileKinds.FromExtension(Extension);

    /// <summary>
    /// One of the owner's documents, photos or other data files was deleted or given a new extension.
    /// </summary>
    [NotMapped]
    public bool NeedsAttention => FileKind == FileKind.Data && (Kind == FileChangeKind.Deleted || ChangedExtension);

    /// <summary>
    /// Extensions that appear in ordinary saves and downloads (Office saves through .tmp, browsers through .crdownload).
    /// </summary>
    public static readonly IReadOnlySet<string> TransientExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "", ".tmp", ".temp", ".crdownload", ".part", ".partial", ".download", ".opdownload", ".bak", ".old", ".lock", ".swp", ".~tmp"
    };

    /// <summary>
    /// Whether a rename really changed what kind of file it is. Editors save by writing "name.ext.tmp.1234.abcd" and
    /// renaming it to "name.ext"; that is an ordinary save. Ransomware does the opposite: "name.docx" becomes
    /// "name.docx.locked", so the old name is a prefix of the new one and the extension is new.
    /// </summary>
    public static bool IsExtensionChange(string? oldPath, string newPath)
    {
        if (oldPath == null)
            return false;

        var oldName = System.IO.Path.GetFileName(oldPath);
        var newName = System.IO.Path.GetFileName(newPath);
        var oldExtension = System.IO.Path.GetExtension(oldName);
        var newExtension = System.IO.Path.GetExtension(newName);
        if (string.Equals(oldExtension, newExtension, StringComparison.OrdinalIgnoreCase))
            return false;

        if (oldName.StartsWith(newName + ".", StringComparison.OrdinalIgnoreCase) || oldName.StartsWith('~') || oldName.EndsWith('~')
            || oldName.Contains(".tmp", StringComparison.OrdinalIgnoreCase))
            return false;

        return !TransientExtensions.Contains(oldExtension) && !TransientExtensions.Contains(newExtension);
    }

    public static async Task Record(DataContext dataContext, IReadOnlyCollection<FileChangeCount> changes)
    {
        if (changes.Count == 0)
            return;

        var imagePaths = changes.Select(change => change.ImagePath).OfType<string>().Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var imageIds = imagePaths.Count == 0 ? [] : await ProcessImage.GetOrCreateIds(dataContext, imagePaths, DateTime.UtcNow);

        const string commandText = """
            INSERT INTO file_changes (bucket_start, path, folder, extension, kind, old_path, process_image_id, change_count, area)
            VALUES ($bucketStart, $path, $folder, $extension, $kind, $oldPath, $processImageId, $count, $area)
            ON CONFLICT (bucket_start, path, kind) DO UPDATE SET
                change_count = change_count + excluded.change_count,
                old_path = COALESCE(excluded.old_path, old_path),
                process_image_id = COALESCE(excluded.process_image_id, process_image_id);
            """;

        await ExecuteBatch(dataContext, commandText, changes, (parameters, change) =>
        {
            parameters.AddWithValue("$bucketStart", change.BucketStart);
            parameters.AddWithValue("$path", Truncate(change.Path, 1024));
            parameters.AddWithValue("$folder", Truncate(System.IO.Path.GetDirectoryName(change.Path) ?? string.Empty, 1024));
            parameters.AddWithValue("$extension", Truncate(System.IO.Path.GetExtension(change.Path).ToLowerInvariant(), 32));
            parameters.AddWithValue("$kind", (int)change.Kind);
            parameters.AddWithValue("$oldPath", DatabaseValue(change.OldPath == null ? null : Truncate(change.OldPath, 1024)));
            parameters.AddWithValue("$processImageId", change.ImagePath != null && imageIds.TryGetValue(change.ImagePath, out var id) ? id : DBNull.Value);
            parameters.AddWithValue("$count", change.Count);
            parameters.AddWithValue("$area", (int)change.Area);
        });
    }

    public static async Task<List<FileChange>> Search(DataContext dataContext, FileChangeFilter filter, long sinceUnixSeconds, int limit)
    {
        var query = Visible(Query(dataContext).Where(change => change.BucketStart >= sinceUnixSeconds), filter.Scope, filter.ShowRoutine);
        // Renames are kept for the moment: "song.mp3" renamed to "song.mp3.locked" is a data file, judged below.
        if (filter.DataOnly)
            query = query.Where(change => FileKinds.DataExtensionList.Contains(change.Extension) || (change.Kind == FileChangeKind.Renamed && change.OldPath != null));
        if (!string.IsNullOrWhiteSpace(filter.Text))
            query = query.Where(change => EF.Functions.Like(change.Path, $"%{filter.Text.Trim()}%"));
        if (filter.Kind.HasValue)
            query = query.Where(change => change.Kind == filter.Kind.Value);
        if (filter.ProcessImageId.HasValue)
            query = query.Where(change => change.ProcessImageId == filter.ProcessImageId.Value);
        if (filter.ImportantOnly)
            query = ImportantFolders.Filter(query);

        var changes = await query
            .OrderByDescending(change => change.BucketStart)
            .ThenBy(change => change.Path)
            .Take(limit)
            .ToListAsync();

        // Deleted and scrambled data files first, then the rest of the owner's data, newest first within each.
        changes = changes
            .Where(change => !filter.DataOnly || change.FileKind == FileKind.Data)
            .OrderByDescending(change => change.NeedsAttention)
            .ThenByDescending(change => change.FileKind == FileKind.Data)
            .ThenByDescending(change => change.BucketStart)
            .ThenBy(change => change.Path)
            .ToList();

        var imageIds = changes.Select(change => change.ProcessImageId).OfType<long>().Distinct().ToList();
        var images = (await ProcessImage.GetAll(dataContext, image => imageIds.Contains(image.Id))).ToDictionary(image => image.Id);
        foreach (var change in changes)
            change.ProcessImage = change.ProcessImageId is long id ? images.GetValueOrDefault(id) : null;

        return changes;
    }

    public static async Task<FileChangeTotals> GetTotals(DataContext dataContext, long sinceUnixSeconds, FileScope scope, bool showRoutine)
    {
        var inRange = InScope(Query(dataContext), scope).Where(change => change.BucketStart >= sinceUnixSeconds);
        var visible = Visible(inRange, FileScope.All, showRoutine);
        var byKind = await visible
            .GroupBy(change => change.Kind)
            .Select(group => new { Kind = group.Key, Count = group.Sum(change => change.ChangeCount), Files = group.Count() })
            .ToListAsync();
        var renamedExtensions = await visible
            .Where(change => change.Kind == FileChangeKind.Renamed && change.OldPath != null)
            .Select(change => new { change.Path, change.OldPath })
            .ToListAsync();
        var dataByKind = await inRange
            .Where(change => change.Kind != FileChangeKind.Read && change.Kind != FileChangeKind.Renamed && FileKinds.DataExtensionList.Contains(change.Extension))
            .GroupBy(change => change.Kind)
            .Select(group => new { Kind = group.Key, Files = group.Count() })
            .ToListAsync();

        // A renamed file counts as data when either name is a data file, so "song.mp3" → "song.mp3.locked" counts.
        var dataRenamed = (await inRange
                .Where(change => change.Kind == FileChangeKind.Renamed)
                .Select(change => new { change.Path, change.OldPath })
                .ToListAsync())
            .Count(row => FileKinds.Classify(row.Path) == FileKind.Data || FileKinds.Classify(row.OldPath) == FileKind.Data);
        var routineHidden = showRoutine ? 0 : await inRange
            .CountAsync(change => change.Kind != FileChangeKind.Read && FileKinds.RoutineExtensionList.Contains(change.Extension));

        return new FileChangeTotals
        {
            Created = byKind.Where(row => row.Kind == FileChangeKind.Created).Sum(row => row.Files),
            Modified = byKind.Where(row => row.Kind == FileChangeKind.Modified).Sum(row => row.Files),
            Deleted = byKind.Where(row => row.Kind == FileChangeKind.Deleted).Sum(row => row.Files),
            Renamed = byKind.Where(row => row.Kind == FileChangeKind.Renamed).Sum(row => row.Files),
            Read = byKind.Where(row => row.Kind == FileChangeKind.Read).Sum(row => row.Files),
            ExtensionChanges = renamedExtensions.Count(row => IsExtensionChange(row.OldPath, row.Path)),
            DataChanged = dataByKind.Sum(row => row.Files) + dataRenamed,
            DataDeleted = dataByKind.Where(row => row.Kind == FileChangeKind.Deleted).Sum(row => row.Files),
            RoutineHidden = routineHidden
        };
    }

    /// <summary>
    /// The folders with the most changed files.
    /// </summary>
    public static async Task<List<FolderActivity>> GetBusiestFolders(DataContext dataContext, long sinceUnixSeconds, int count, FileScope scope, bool showRoutine)
    {
        return await Visible(Query(dataContext), scope, showRoutine)
            .Where(change => change.BucketStart >= sinceUnixSeconds && change.Kind != FileChangeKind.Read)
            .GroupBy(change => change.Folder)
            .Select(group => new FolderActivity
            {
                Folder = group.Key,
                Files = group.Select(change => change.Path).Distinct().Count(),
                Changes = group.Sum(change => change.ChangeCount),
                LastChangedBucket = group.Max(change => change.BucketStart)
            })
            .OrderByDescending(folder => folder.Files)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// Files each program created, deleted or renamed, for the per-program table.
    /// </summary>
    public static async Task<Dictionary<long, (int Created, int Deleted, int Renamed)>> CountByProgram(DataContext dataContext, long sinceUnixSeconds, FileScope scope, bool showRoutine)
    {
        var rows = await Visible(Query(dataContext), scope, showRoutine)
            .Where(change => change.BucketStart >= sinceUnixSeconds && change.ProcessImageId != null)
            .GroupBy(change => new { change.ProcessImageId, change.Kind })
            .Select(group => new { group.Key.ProcessImageId, group.Key.Kind, Files = group.Count() })
            .ToListAsync();

        return rows.GroupBy(row => row.ProcessImageId!.Value).ToDictionary(group => group.Key, group => (
            group.Where(row => row.Kind == FileChangeKind.Created).Sum(row => row.Files),
            group.Where(row => row.Kind == FileChangeKind.Deleted).Sum(row => row.Files),
            group.Where(row => row.Kind == FileChangeKind.Renamed).Sum(row => row.Files)));
    }

    /// <summary>
    /// Which programs read the owner's files: files read, and how many of those reads happened while nobody was
    /// at the computer. Programs that also uploaded while the owner was away come first.
    /// </summary>
    public static async Task<List<FileReaderSummary>> GetReaders(DataContext dataContext, long sinceUnixSeconds, int count)
    {
        var reads = await Query(dataContext)
            .Where(change => change.BucketStart >= sinceUnixSeconds && change.Kind == FileChangeKind.Read && change.ProcessImageId != null)
            .Select(change => new { ProcessImageId = change.ProcessImageId!.Value, change.Path, change.BucketStart })
            .ToListAsync();
        if (reads.Count == 0)
            return [];

        var since = DateTimeOffset.FromUnixTimeSeconds(sinceUnixSeconds).UtcDateTime;
        var awayPeriods = (await PresencePeriod.GetOverlapping(dataContext, since, DateTime.UtcNow))
            .Where(period => period.State == PresenceState.Away)
            .Select(period => (Start: new DateTimeOffset(period.StartedAt).ToUnixTimeSeconds() / 60 * 60, End: new DateTimeOffset(period.EffectiveEnd).ToUnixTimeSeconds()))
            .ToList();
        bool WasAway(long bucket) => awayPeriods.Any(period => bucket >= period.Start && bucket <= period.End);

        var programIds = reads.Select(read => read.ProcessImageId).Distinct().ToList();
        var awayUploads = await dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && programIds.Contains(record.ProcessImageId) && record.Presence == PresenceState.Away)
            .GroupBy(record => record.ProcessImageId)
            .Select(group => new { ProcessImageId = group.Key, Sent = group.Sum(record => record.BytesSent) })
            .ToDictionaryAsync(row => row.ProcessImageId, row => row.Sent);

        var readers = reads
            .GroupBy(read => read.ProcessImageId)
            .Select(group => new FileReaderSummary
            {
                ProcessImageId = group.Key,
                FilesRead = group.Select(read => read.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                FilesReadWhileAway = group.Where(read => WasAway(read.BucketStart)).Select(read => read.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                LastReadBucket = group.Max(read => read.BucketStart),
                UploadedWhileAwayBytes = awayUploads.GetValueOrDefault(group.Key)
            })
            .OrderByDescending(reader => reader.ReadAndUploadedWhileAway)
            .ThenByDescending(reader => reader.FilesReadWhileAway)
            .ThenByDescending(reader => reader.FilesRead)
            .Take(count)
            .ToList();

        var ids = readers.Select(reader => reader.ProcessImageId).ToList();
        var images = (await ProcessImage.GetAll(dataContext, image => ids.Contains(image.Id))).ToDictionary(image => image.Id);
        foreach (var reader in readers)
            reader.ProcessImage = images.GetValueOrDefault(reader.ProcessImageId);

        return readers;
    }

    public static IQueryable<FileChange> InScope(IQueryable<FileChange> query, FileScope scope)
    {
        return scope switch
        {
            FileScope.Mine => query.Where(change => change.Area == FileArea.MyFiles),
            FileScope.System => query.Where(change => change.Area != FileArea.MyFiles),
            _ => query
        };
    }

    /// <summary>
    /// The scope, without routine program and system files (DLLs, executables, logs, installer rollback copies)
    /// unless they were asked for.
    /// </summary>
    public static IQueryable<FileChange> Visible(IQueryable<FileChange> query, FileScope scope, bool showRoutine)
    {
        query = InScope(query, scope);
        return showRoutine ? query : query.Where(change => !FileKinds.RoutineExtensionList.Contains(change.Extension));
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, change => change.BucketStart < cutoffUnixSeconds);
    }

    private static string Truncate(string text, int maximumLength)
    {
        return text.Length <= maximumLength ? text : text[..maximumLength];
    }
}

/// <summary>
/// File changes counted by the sensor for one minute. Not persisted directly.
/// </summary>
public record FileChangeCount(long BucketStart, string Path, FileChangeKind Kind, string? OldPath, string? ImagePath, int Count, FileArea Area);

/// <summary>
/// The I/O page's toggle: the owner's own files, everything else, or all of it.
/// </summary>
public enum FileScope
{
    Mine,
    System,
    All
}

public class FileChangeFilter
{
    public FileScope Scope { get; set; } = FileScope.Mine;
    public string? Text { get; set; }
    public FileChangeKind? Kind { get; set; }
    public long? ProcessImageId { get; set; }
    public bool ImportantOnly { get; set; }

    /// <summary>
    /// Only documents, photos, music and other data files.
    /// </summary>
    public bool DataOnly { get; set; }

    /// <summary>
    /// Include DLLs, executables, logs and other files that installs and updates replace all the time.
    /// </summary>
    public bool ShowRoutine { get; set; }
}

public class FileChangeTotals
{
    public int Created { get; set; }
    public int Modified { get; set; }
    public int Deleted { get; set; }
    public int Renamed { get; set; }
    public int Read { get; set; }
    public int ExtensionChanges { get; set; }

    /// <summary>
    /// Documents, photos, music and other data files created, changed, deleted or renamed (in the scope, never hidden).
    /// </summary>
    public int DataChanged { get; set; }
    public int DataDeleted { get; set; }

    /// <summary>
    /// Changes to routine program and system files left out of everything else.
    /// </summary>
    public int RoutineHidden { get; set; }

    public int Total => Created + Modified + Deleted + Renamed;
}

public class FileReaderSummary
{
    public long ProcessImageId { get; set; }
    public ProcessImage? ProcessImage { get; set; }
    public int FilesRead { get; set; }
    public int FilesReadWhileAway { get; set; }
    public long LastReadBucket { get; set; }
    public long UploadedWhileAwayBytes { get; set; }

    public string Name => ProcessImage?.DisplayName ?? $"Program {ProcessImageId}";
    public bool ReadAndUploadedWhileAway => FilesReadWhileAway > 0 && UploadedWhileAwayBytes > 0;
}

public class FolderActivity
{
    public string Folder { get; set; } = string.Empty;
    public int Files { get; set; }
    public int Changes { get; set; }
    public long LastChangedBucket { get; set; }
}

/// <summary>
/// Folders where a change matters more: personal documents, what starts with Windows, and Windows and program files.
/// </summary>
public static class ImportantFolders
{
    private static readonly string[] Fragments =
    [
        @"\Documents\", @"\Desktop\", @"\Pictures\", @"\Downloads\", @"\Videos\", @"\Music\",
        @"\Start Menu\Programs\Startup\", @"\Windows\System32\Tasks\", @"\Windows\System32\drivers\",
        @"\Windows\System32\", @"\Windows\SysWOW64\", @"\Program Files\", @"\Program Files (x86)\"
    ];

    /// <summary>
    /// Personal folders, used by the mass-change rule.
    /// </summary>
    public static readonly string[] PersonalFragments = [@"\Documents\", @"\Desktop\", @"\Pictures\", @"\Downloads\", @"\Videos\", @"\Music\", @"\OneDrive\"];

    public static bool Contains(string path)
    {
        return Fragments.Any(fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsPersonal(string path)
    {
        return PersonalFragments.Any(fragment => path.Contains(fragment, StringComparison.OrdinalIgnoreCase));
    }

    public static IQueryable<FileChange> Filter(IQueryable<FileChange> query)
    {
        return query.Where(change =>
            EF.Functions.Like(change.Path, @"%\Documents\%") || EF.Functions.Like(change.Path, @"%\Desktop\%")
            || EF.Functions.Like(change.Path, @"%\Pictures\%") || EF.Functions.Like(change.Path, @"%\Downloads\%")
            || EF.Functions.Like(change.Path, @"%\Videos\%") || EF.Functions.Like(change.Path, @"%\Music\%")
            || EF.Functions.Like(change.Path, @"%\Start Menu\Programs\Startup\%") || EF.Functions.Like(change.Path, @"%\Windows\System32\%")
            || EF.Functions.Like(change.Path, @"%\Windows\SysWOW64\%") || EF.Functions.Like(change.Path, @"%\Program Files%"));
    }
}
