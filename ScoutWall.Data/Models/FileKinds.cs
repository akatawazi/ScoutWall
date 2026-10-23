namespace ScoutWall.Data.Models;

/// <summary>
/// What a changed file holds, judged by its extension.
/// </summary>
public enum FileKind
{
    Other,

    /// <summary>
    /// Something a person made or keeps: documents, spreadsheets, photos, music, video, mail, saved games.
    /// Losing or scrambling these is what hurts, so changes to them are shown first and watched most closely.
    /// </summary>
    Data,

    /// <summary>
    /// Program and system files that installers, updates and Windows itself replace all the time: libraries,
    /// executables, drivers, installer rollback copies, logs and caches. Hidden on the I/O page unless asked for.
    /// </summary>
    Routine
}

public static class FileKinds
{
    /// <summary>
    /// Extensions of the files people care about. Kept lowercase with the dot, as stored in file_changes.extension.
    /// </summary>
    public static readonly IReadOnlySet<string> DataExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Documents
        ".doc", ".docx", ".docm", ".dot", ".dotx", ".odt", ".rtf", ".txt", ".md", ".pdf", ".pages", ".wpd", ".tex", ".epub", ".mobi",
        ".one", ".xps",
        // Spreadsheets and presentations
        ".xls", ".xlsx", ".xlsm", ".xlsb", ".csv", ".ods", ".numbers", ".ppt", ".pptx", ".pptm", ".odp", ".key",
        // Photos and pictures
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".heif", ".webp", ".raw", ".cr2", ".cr3", ".nef", ".arw",
        ".dng", ".orf", ".rw2", ".psd", ".ai", ".svg", ".xcf", ".indd",
        // Music and recordings
        ".mp3", ".wav", ".flac", ".m4a", ".aac", ".ogg", ".wma", ".aiff", ".aif", ".opus", ".mid", ".midi",
        // Video
        ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".m4v", ".mpg", ".mpeg", ".3gp", ".webm",
        // Mail, contacts and calendars
        ".pst", ".ost", ".eml", ".msg", ".vcf", ".ics", ".mbox",
        // Archives and backups people make
        ".zip", ".7z", ".rar", ".tar", ".gz",
        // Personal databases, money and passwords
        ".accdb", ".mdb", ".kdbx", ".qbw", ".qbb", ".qdf", ".gnucash",
        // Saved games, drawings and notebooks
        ".sav", ".save", ".dwg", ".dxf", ".sketch", ".fig", ".ipynb"
    };

    /// <summary>
    /// Extensions of files that change as part of installing, updating and running software.
    /// </summary>
    public static readonly IReadOnlySet<string> RoutineExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Program code
        ".dll", ".exe", ".sys", ".drv", ".ocx", ".cpl", ".ax", ".winmd", ".tlb", ".pyd", ".pyc", ".node", ".so",
        // Windows component metadata and resources
        ".mui", ".cat", ".manifest", ".mum", ".pri", ".pdb", ".config",
        // Installers, updates and Windows Installer rollback copies
        ".msi", ".msp", ".msu", ".cab", ".rbf", ".rbs", ".nupkg",
        // Logs, traces, dumps, prefetch and caches
        ".log", ".etl", ".evtx", ".dmp", ".pf", ".cache", ".tmp", ".temp", ".lock",
        // Database working files
        ".db-wal", ".db-shm", ".db-journal", ".sqlite-wal", ".sqlite-shm", ".ldb", ".jfm", ".edb", ".chk"
    };

    /// <summary>
    /// The routine extensions as a list, for "extension IN (...)" queries.
    /// </summary>
    public static readonly string[] RoutineExtensionList = RoutineExtensions.Select(extension => extension.ToLowerInvariant()).ToArray();

    public static readonly string[] DataExtensionList = DataExtensions.Select(extension => extension.ToLowerInvariant()).ToArray();

    public static FileKind Classify(string? path)
    {
        return FromExtension(Path.GetExtension(path ?? string.Empty));
    }

    public static FileKind FromExtension(string? extension)
    {
        if (string.IsNullOrEmpty(extension))
            return FileKind.Other;

        return DataExtensions.Contains(extension) ? FileKind.Data
            : RoutineExtensions.Contains(extension) ? FileKind.Routine
            : FileKind.Other;
    }
}
