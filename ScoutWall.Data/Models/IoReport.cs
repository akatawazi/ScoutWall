using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One program's disk and file activity over the range.
/// </summary>
public class ProgramIoSummary
{
    public long ProcessImageId { get; set; }
    public ProcessImage? ProcessImage { get; set; }
    public long ReadBytes { get; set; }
    public long WriteBytes { get; set; }
    public int FilesCreated { get; set; }
    public int FilesDeleted { get; set; }
    public int FilesRenamed { get; set; }

    /// <summary>
    /// Why the program can't be ended or blocked from running, or null when it can.
    /// </summary>
    public string? EndRefusal { get; set; }
    public string? BlockRefusal { get; set; }

    public string Name => ProcessImage?.DisplayName ?? $"Program {ProcessImageId}";
    public long TotalBytes => ReadBytes + WriteBytes;
}

/// <summary>
/// Everything on the I/O page: drive activity and space, the programs reading and writing the most, and which
/// files were created, changed, deleted or renamed.
/// </summary>
public class IoReport
{
    private const int ProgramCount = 50;
    private const int ChangeLimit = 300;

    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public DriveSpaceSnapshot Space { get; set; } = new();
    public List<DiskIoMinute> LatestDisks { get; set; } = [];
    public List<DiskIoPoint> Timeline { get; set; } = [];
    public List<ProgramIoSummary> Programs { get; set; } = [];
    public FileChangeTotals FileTotals { get; set; } = new();
    public List<FolderActivity> BusiestFolders { get; set; } = [];
    public List<FileChange> Changes { get; set; } = [];
    public FileChangeFilter Filter { get; set; } = new();
    public List<Alert> FileAlerts { get; set; } = [];
    public List<FileReaderSummary> Readers { get; set; } = [];
    public FileTrackingSettings Tracking { get; set; } = new();
    public long TrackingRevision { get; set; }
    public FileReadAuditState ReadAudit { get; set; } = new();
    public FileAreaRules AreaRules { get; set; } = new();

    public bool ChangesTruncated => Changes.Count >= ChangeLimit;
    public long ReadBytesPerSecondNow => LatestDisks.Sum(disk => disk.ReadBytes) / 60;
    public long WriteBytesPerSecondNow => LatestDisks.Sum(disk => disk.WriteBytes) / 60;
    public DiskIoMinute? BusiestDiskNow => LatestDisks.MaxBy(disk => disk.BusyPercent);
    public bool HasDiskData => Timeline.Count > 0;

    public static async Task<IoReport> Build(DataContext dataContext, TimeRange range, FileChangeFilter filter)
    {
        var since = range.SinceUnixSeconds;
        var ioReport = new IoReport
        {
            Range = range,
            Filter = filter,
            Space = await DriveSpaceSnapshot.Load(dataContext),
            LatestDisks = await DiskIoMinute.GetLatest(dataContext),
            Timeline = await DiskIoMinute.GetTimeline(dataContext, since, range.StepSeconds),
            FileTotals = await FileChange.GetTotals(dataContext, since, filter.Scope),
            BusiestFolders = await FileChange.GetBusiestFolders(dataContext, since, 10, filter.Scope),
            Changes = await FileChange.Search(dataContext, filter, since, ChangeLimit),
            Programs = await BuildPrograms(dataContext, since, filter.Scope),
            Readers = await FileChange.GetReaders(dataContext, since, 20),
            Tracking = await Setting.Load<FileTrackingSettings>(dataContext),
            TrackingRevision = await Setting.GetRevision<FileTrackingSettings>(dataContext),
            ReadAudit = await FileReadAuditState.Load(dataContext),
            AreaRules = await FileAreaRules.Load(dataContext)
        };

        var sinceTime = DateTimeOffset.FromUnixTimeSeconds(since).UtcDateTime;
        ioReport.FileAlerts = await Alert.GetAll(dataContext, alert => (alert.RuleName == "FileExtensionRenames" || alert.RuleName == "MassFileChange")
            && alert.Status == AlertStatus.Open && alert.LastSeenAt >= sinceTime);
        return ioReport;
    }

    private static async Task<List<ProgramIoSummary>> BuildPrograms(DataContext dataContext, long since, FileScope scope)
    {
        var io = await dataContext.Set<ProcessResourceSample>().AsNoTracking()
            .Where(sample => sample.BucketStart >= since)
            .GroupBy(sample => sample.ProcessImageId)
            .Select(group => new { ProcessImageId = group.Key, Read = group.Sum(sample => sample.ReadBytes), Write = group.Sum(sample => sample.WriteBytes) })
            .ToListAsync();
        var fileCounts = await FileChange.CountByProgram(dataContext, since, scope);

        var programs = io.Select(row => row.ProcessImageId).Union(fileCounts.Keys)
            .Select(id =>
            {
                var bytes = io.FirstOrDefault(row => row.ProcessImageId == id);
                var files = fileCounts.GetValueOrDefault(id);
                return new ProgramIoSummary
                {
                    ProcessImageId = id,
                    ReadBytes = bytes?.Read ?? 0,
                    WriteBytes = bytes?.Write ?? 0,
                    FilesCreated = files.Created,
                    FilesDeleted = files.Deleted,
                    FilesRenamed = files.Renamed
                };
            })
            .Where(program => program.TotalBytes > 0 || program.FilesCreated + program.FilesDeleted + program.FilesRenamed > 0)
            .OrderByDescending(program => program.TotalBytes)
            .ThenByDescending(program => program.FilesCreated + program.FilesDeleted + program.FilesRenamed)
            .Take(ProgramCount)
            .ToList();

        var ids = programs.Select(program => program.ProcessImageId).ToList();
        var images = (await ProcessImage.GetAll(dataContext, image => ids.Contains(image.Id))).ToDictionary(image => image.Id);
        foreach (var program in programs)
        {
            program.ProcessImage = images.GetValueOrDefault(program.ProcessImageId);
            var path = program.ProcessImage?.ImagePath;
            var rooted = path != null && Path.IsPathRooted(path);
            program.EndRefusal = rooted ? ProtectedPrograms.ReasonNotBlockable(path!) : "ScoutWall doesn't know where this program lives.";
            program.BlockRefusal = rooted ? ProtectedPrograms.ReasonNotBlockableFromRunning(path!) : program.EndRefusal;
        }

        return programs;
    }
}
