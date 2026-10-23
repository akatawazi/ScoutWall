using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ScoutWall.Data.Models;

namespace ScoutWall.Data;

public class DataContext : DbContext
{
    public const string DefaultDatabasePath = @"%ProgramData%\ScoutWall\scoutwall.db";

    public DataContext(DbContextOptions<DataContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<TrafficMinute> TrafficMinutes => Set<TrafficMinute>();
    public DbSet<TrafficHour> TrafficHours => Set<TrafficHour>();
    public DbSet<IpAddressProfile> IpAddressProfiles => Set<IpAddressProfile>();
    public DbSet<DnsRecord> DnsRecords => Set<DnsRecord>();
    public DbSet<TlsSession> TlsSessions => Set<TlsSession>();
    public DbSet<DecryptedRequest> DecryptedRequests => Set<DecryptedRequest>();
    public DbSet<SensorStatus> SensorStatuses => Set<SensorStatus>();
    public DbSet<Setting> Settings => Set<Setting>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();
    public DbSet<CaptureInterface> CaptureInterfaces => Set<CaptureInterface>();
    public DbSet<ResponseAction> ResponseActions => Set<ResponseAction>();
    public DbSet<NotificationDelivery> NotificationDeliveries => Set<NotificationDelivery>();
    public DbSet<UserPresence> UserPresences => Set<UserPresence>();
    public DbSet<PresencePeriod> PresencePeriods => Set<PresencePeriod>();
    public DbSet<DiskIoMinute> DiskIoMinutes => Set<DiskIoMinute>();
    public DbSet<FileChange> FileChanges => Set<FileChange>();
    public DbSet<ProcessImage> ProcessImages => Set<ProcessImage>();
    public DbSet<ProcessTrafficMinute> ProcessTrafficMinutes => Set<ProcessTrafficMinute>();
    public DbSet<FlowVerdict> FlowVerdicts => Set<FlowVerdict>();
    public DbSet<SystemState> SystemStates => Set<SystemState>();
    public DbSet<AnalystAssessment> AnalystAssessments => Set<AnalystAssessment>();
    public DbSet<ChatMessage> ChatMessages => Set<ChatMessage>();
    public DbSet<PendingChange> PendingChanges => Set<PendingChange>();
    public DbSet<SystemResourceMinute> SystemResourceMinutes => Set<SystemResourceMinute>();
    public DbSet<ProcessResourceSample> ProcessResourceSamples => Set<ProcessResourceSample>();
    public DbSet<SystemService> SystemServices => Set<SystemService>();
    public DbSet<SystemEvent> SystemEvents => Set<SystemEvent>();
    public DbSet<ScannerBlock> ScannerBlocks => Set<ScannerBlock>();
    public DbSet<ScanResult> ScanResults => Set<ScanResult>();

    public static DataContext Create(string databasePath)
    {
        var optionsBuilder = new DbContextOptionsBuilder<DataContext>();
        Configure(optionsBuilder, databasePath);
        return new DataContext(optionsBuilder.Options);
    }

    public static void Configure(DbContextOptionsBuilder optionsBuilder, string databasePath)
    {
        optionsBuilder.UseSqlite(BuildConnectionString(databasePath));
        SecretProtector.KeyFolder ??= Path.GetDirectoryName(databasePath);
    }

    public static string ResolveDatabasePath(string? configuredPath)
    {
        var databasePath = string.IsNullOrWhiteSpace(configuredPath) ? DefaultDatabasePath : configuredPath;
        return ScoutWallPaths.Resolve(databasePath);
    }

    public static string BuildConnectionString(string databasePath)
    {
        var connectionStringBuilder = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            DefaultTimeout = 30,
            Pooling = true
        };
        return connectionStringBuilder.ToString();
    }

    /// <summary>
    /// Creates the database directory, applies migrations and switches the database to WAL mode.
    /// Only the web application calls this, so a single process owns the schema.
    /// </summary>
    public static async Task Initialize(string databasePath)
    {
        PrepareDirectory(databasePath);

        await using var dataContext = Create(databasePath);
        await dataContext.Database.MigrateAsync();
        await dataContext.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
    }

    /// <summary>
    /// The web application owns the schema. The sensor uses this to wait until the schema matches its build.
    /// </summary>
    public static async Task<bool> IsSchemaCurrent(string databasePath)
    {
        if (!File.Exists(databasePath))
            return false;

        await using var dataContext = Create(databasePath);
        var pendingMigrations = await dataContext.Database.GetPendingMigrationsAsync();
        return !pendingMigrations.Any();
    }

    /// <summary>
    /// Creates the data folder if needed. Its permissions are set by "scoutwall install" (SYSTEM, Administrators and
    /// the console's service account only), never widened here: the folder holds browsing and file history.
    /// </summary>
    private static void PrepareDirectory(string databasePath)
    {
        var directoryPath = Path.GetDirectoryName(databasePath);
        if (!string.IsNullOrEmpty(directoryPath))
            Directory.CreateDirectory(directoryPath);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<DateTime>().HaveConversion<UtcDateTimeConverter>();
        configurationBuilder.Properties<DateTime?>().HaveConversion<NullableUtcDateTimeConverter>();
    }

    private class UtcDateTimeConverter : ValueConverter<DateTime, DateTime>
    {
        public UtcDateTimeConverter()
            : base(value => value.ToUniversalTime(), value => DateTime.SpecifyKind(value, DateTimeKind.Utc))
        {
        }
    }

    private class NullableUtcDateTimeConverter : ValueConverter<DateTime?, DateTime?>
    {
        public NullableUtcDateTimeConverter()
            : base(
                value => value.HasValue ? value.Value.ToUniversalTime() : value,
                value => value.HasValue ? DateTime.SpecifyKind(value.Value, DateTimeKind.Utc) : value)
        {
        }
    }
}
