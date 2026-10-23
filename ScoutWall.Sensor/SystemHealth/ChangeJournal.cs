using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// One file change read from a volume's change journal.
/// </summary>
public record JournalChange(DateTime ChangedAt, string Path, FileChangeKind Kind, string? OldPath);

/// <summary>
/// Reads the NTFS change journal (USN journal) of one volume: every file created, deleted, renamed or written,
/// recorded by Windows itself at almost no cost, and still there after the sensor was stopped, so it catches up.
/// Needs administrator rights to open the volume. Only records written when a file is closed are used (they carry
/// everything that happened to it while open), plus the "old name" half of renames.
/// </summary>
public sealed class ChangeJournal : IDisposable
{
    private const uint FsctlQueryUsnJournal = 0x000900F4;
    private const uint FsctlReadUsnJournal = 0x000900BB;
    private const int OutputBufferSize = 256 * 1024;

    private const uint ReasonDataOverwrite = 0x00000001;
    private const uint ReasonDataExtend = 0x00000002;
    private const uint ReasonDataTruncation = 0x00000004;
    private const uint ReasonFileCreate = 0x00000100;
    private const uint ReasonFileDelete = 0x00000200;
    private const uint ReasonRenameOldName = 0x00001000;
    private const uint ReasonRenameNewName = 0x00002000;
    private const uint ReasonClose = 0x80000000;
    private const uint DataReasons = ReasonDataOverwrite | ReasonDataExtend | ReasonDataTruncation;
    private const uint WatchedReasons = DataReasons | ReasonFileCreate | ReasonFileDelete | ReasonRenameOldName | ReasonRenameNewName | ReasonClose;

    private const int MaximumCachedFolders = 50_000;

    private readonly SafeFileHandle volume;
    private readonly string driveRoot;
    private readonly Dictionary<long, string?> folderPaths = [];
    private readonly Dictionary<long, string> oldNames = [];

    public string Drive { get; }
    public ulong JournalId { get; private set; }
    public long NextUsn { get; private set; }

    private ChangeJournal(string drive, SafeFileHandle volume)
    {
        Drive = drive;
        driveRoot = drive + @"\";
        this.volume = volume;
    }

    /// <summary>
    /// Opens the journal of a drive such as "C:". Returns null when the drive has no journal or can't be opened.
    /// </summary>
    public static ChangeJournal? Open(string drive)
    {
        var handle = CreateFile($@"\\.\{drive}", GenericRead, FileShareReadWrite, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        if (handle.IsInvalid)
            return null;

        var journal = new ChangeJournal(drive, handle);
        var state = journal.Query();
        if (state == null)
        {
            journal.Dispose();
            return null;
        }

        journal.JournalId = state.Value.JournalId;
        journal.NextUsn = state.Value.NextUsn;
        return journal;
    }

    /// <summary>
    /// Continues from a saved position when it still belongs to this journal and hasn't been overwritten;
    /// otherwise starts from now. Returns whether it resumed.
    /// </summary>
    public bool ResumeFrom(ulong journalId, long usn)
    {
        var state = Query();
        if (state == null || state.Value.JournalId != journalId || usn < state.Value.FirstUsn)
            return false;

        NextUsn = usn;
        return true;
    }

    /// <summary>
    /// Reads up to the given number of records past the current position.
    /// </summary>
    public List<JournalChange> ReadNew(int maximumRecords)
    {
        var changes = new List<JournalChange>();
        var input = Marshal.AllocHGlobal(40);
        var output = Marshal.AllocHGlobal(OutputBufferSize);
        try
        {
            var recordsRead = 0;
            while (recordsRead < maximumRecords)
            {
                // READ_USN_JOURNAL_DATA_V0: StartUsn 0, ReasonMask 8, ReturnOnlyOnClose 12, Timeout 16,
                // BytesToWaitFor 24, UsnJournalID 32. Version 0 returns USN_RECORD_V2 records.
                Marshal.WriteInt64(input, 0, NextUsn);
                Marshal.WriteInt32(input, 8, unchecked((int)WatchedReasons));
                Marshal.WriteInt32(input, 12, 0);
                Marshal.WriteInt64(input, 16, 0);
                Marshal.WriteInt64(input, 24, 0);
                Marshal.WriteInt64(input, 32, unchecked((long)JournalId));

                if (!DeviceIoControl(volume, FsctlReadUsnJournal, input, 40, output, OutputBufferSize, out var bytesReturned, IntPtr.Zero) || bytesReturned <= 8)
                    break;

                var nextUsn = Marshal.ReadInt64(output, 0);
                var offset = 8;
                while (offset < bytesReturned)
                {
                    var recordLength = Marshal.ReadInt32(output, offset);
                    if (recordLength <= 0)
                        break;

                    var change = Interpret(output + offset);
                    if (change != null)
                        changes.Add(change);

                    recordsRead++;
                    offset += recordLength;
                }

                if (nextUsn == NextUsn)
                    break;

                NextUsn = nextUsn;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input);
            Marshal.FreeHGlobal(output);
        }

        if (folderPaths.Count > MaximumCachedFolders)
            folderPaths.Clear();
        if (oldNames.Count > 10_000)
            oldNames.Clear();

        return changes;
    }

    private JournalChange? Interpret(IntPtr record)
    {
        // USN_RECORD_V2: RecordLength 0, MajorVersion 4, MinorVersion 6, FileReferenceNumber 8,
        // ParentFileReferenceNumber 16, Usn 24, TimeStamp 32, Reason 40, SourceInfo 44, SecurityId 48,
        // FileAttributes 52, FileNameLength 56, FileNameOffset 58.
        if (Marshal.ReadInt16(record, 4) != 2)
            return null;

        var fileReference = Marshal.ReadInt64(record, 8);
        var parentReference = Marshal.ReadInt64(record, 16);
        var timeStamp = DateTime.FromFileTimeUtc(Marshal.ReadInt64(record, 32));
        var reason = unchecked((uint)Marshal.ReadInt32(record, 40));
        var nameLength = Marshal.ReadInt16(record, 56);
        var nameOffset = Marshal.ReadInt16(record, 58);
        var name = Marshal.PtrToStringUni(record + nameOffset, nameLength / 2);

        if ((reason & ReasonRenameOldName) != 0 && (reason & ReasonClose) == 0)
        {
            var folder = FolderPath(parentReference);
            if (folder != null)
                oldNames[fileReference] = Path.Combine(folder, name);
            return null;
        }

        if ((reason & ReasonClose) == 0)
            return null;

        var kind = (reason & ReasonFileDelete) != 0 ? FileChangeKind.Deleted
            : (reason & ReasonFileCreate) != 0 ? FileChangeKind.Created
            : (reason & ReasonRenameNewName) != 0 ? FileChangeKind.Renamed
            : (reason & DataReasons) != 0 ? FileChangeKind.Modified
            : (FileChangeKind?)null;
        if (kind == null)
            return null;

        var parentPath = FolderPath(parentReference) ?? Path.Combine(driveRoot, "(unknown folder)");
        string? oldPath = null;
        if (kind == FileChangeKind.Renamed && oldNames.Remove(fileReference, out var previousName))
            oldPath = previousName;

        return new JournalChange(timeStamp, Path.Combine(parentPath, name), kind.Value, oldPath);
    }

    /// <summary>
    /// The full path of a folder from its file reference number, cached. Null when the folder no longer exists.
    /// </summary>
    private string? FolderPath(long folderReference)
    {
        if (folderPaths.TryGetValue(folderReference, out var cached))
            return cached;

        string? path = null;
        var descriptor = new FileIdDescriptor { Size = Marshal.SizeOf<FileIdDescriptor>(), Type = 0, FileId = folderReference };
        using (var handle = OpenFileById(volume, ref descriptor, 0, FileShareReadWrite | FileShareDelete, IntPtr.Zero, FileFlagBackupSemantics))
        {
            if (!handle.IsInvalid)
            {
                var buffer = new StringBuilder(1024);
                var length = GetFinalPathNameByHandle(handle, buffer, buffer.Capacity, 0);
                if (length > 0 && length < buffer.Capacity)
                {
                    path = buffer.ToString();
                    if (path.StartsWith(@"\\?\", StringComparison.Ordinal))
                        path = path[4..];
                }
            }
        }

        folderPaths[folderReference] = path;
        return path;
    }

    private (ulong JournalId, long FirstUsn, long NextUsn)? Query()
    {
        var output = Marshal.AllocHGlobal(80);
        try
        {
            // USN_JOURNAL_DATA_V0: UsnJournalID 0, FirstUsn 8, NextUsn 16, LowestValidUsn 24, MaxUsn 32.
            if (!DeviceIoControl(volume, FsctlQueryUsnJournal, IntPtr.Zero, 0, output, 80, out _, IntPtr.Zero))
                return null;

            return (unchecked((ulong)Marshal.ReadInt64(output, 0)), Marshal.ReadInt64(output, 8), Marshal.ReadInt64(output, 16));
        }
        finally
        {
            Marshal.FreeHGlobal(output);
        }
    }

    public void Dispose()
    {
        volume.Dispose();
    }

    [StructLayout(LayoutKind.Explicit, Size = 24)]
    private struct FileIdDescriptor
    {
        [FieldOffset(0)] public int Size;
        [FieldOffset(4)] public int Type;
        [FieldOffset(8)] public long FileId;
    }

    private const uint GenericRead = 0x80000000;
    private const uint FileShareReadWrite = 0x1 | 0x2;
    private const uint FileShareDelete = 0x4;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint creationDisposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(SafeFileHandle device, uint controlCode, IntPtr inBuffer, int inBufferSize, IntPtr outBuffer, int outBufferSize, out int bytesReturned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle OpenFileById(SafeFileHandle volumeHint, ref FileIdDescriptor fileId, uint desiredAccess, uint shareMode, IntPtr securityAttributes, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int GetFinalPathNameByHandle(SafeFileHandle file, StringBuilder path, int pathLength, uint flags);
}
