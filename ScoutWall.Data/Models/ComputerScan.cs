using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum ScanItemKind
{
    Program = 1,
    Service = 2,
    ScheduledTask = 3,
    StartupEntry = 4
}

/// <summary>
/// What the scan recommends doing about an item. It is only ever a suggestion with a button; nothing is applied
/// without the person pressing it.
/// </summary>
public enum ScanRecommendation
{
    None = 0,
    Watch = 1,
    BlockFromRunning = 2,
    BlockInternet = 3,
    DisableTask = 4,
    RemoveTask = 5,
    StopService = 6
}

/// <summary>
/// One item the "Scan this computer" button found worth a look, with the reasons and the assistant's view.
/// </summary>
[Table("scan_results")]
[Index(nameof(ScanStartedAt))]
public class ScanResult : Repository<ScanResult>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("scan_started_at")]
    public DateTime ScanStartedAt { get; set; }

    [Column("kind")]
    public ScanItemKind Kind { get; set; }

    [Column("name")]
    [MaxLength(512)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// What an action targets: a program path, a scheduled task path or a service name.
    /// </summary>
    [Column("target")]
    [MaxLength(2048)]
    public string Target { get; set; } = string.Empty;

    [Column("program_path")]
    [MaxLength(2048)]
    public string? ProgramPath { get; set; }

    [Column("command")]
    [MaxLength(2048)]
    public string? Command { get; set; }

    [Column("signals")]
    [MaxLength(2048)]
    public string Signals { get; set; } = string.Empty;

    [Column("score")]
    public int Score { get; set; }

    [Column("assistant_verdict")]
    [MaxLength(32)]
    public string? AssistantVerdict { get; set; }

    [Column("assistant_reason")]
    [MaxLength(1024)]
    public string? AssistantReason { get; set; }

    [Column("recommendation")]
    public ScanRecommendation Recommendation { get; set; }

    [NotMapped]
    public string KindLabel => Kind switch
    {
        ScanItemKind.Program => "Program",
        ScanItemKind.Service => "Service",
        ScanItemKind.ScheduledTask => "Scheduled task",
        _ => "Starts with Windows"
    };

    [NotMapped]
    public string RecommendationLabel => Recommendation switch
    {
        ScanRecommendation.Watch => "Keep an eye on it",
        ScanRecommendation.BlockFromRunning => "Block from running",
        ScanRecommendation.BlockInternet => "Block from the internet",
        ScanRecommendation.DisableTask => "Disable the task",
        ScanRecommendation.RemoveTask => "Remove the task",
        ScanRecommendation.StopService => "Stop the service",
        _ => "Looks fine"
    };

    public static async Task<List<ScanResult>> GetLatest(DataContext dataContext)
    {
        var latestScan = await Query(dataContext).MaxAsync(result => (DateTime?)result.ScanStartedAt);
        if (latestScan == null)
            return [];

        return await Query(dataContext)
            .Where(result => result.ScanStartedAt == latestScan)
            .OrderByDescending(result => result.Recommendation != ScanRecommendation.None)
            .ThenByDescending(result => result.Score)
            .ToListAsync();
    }

    /// <summary>
    /// Replaces earlier scans with this one; only the latest is kept.
    /// </summary>
    public static async Task SaveScan(DataContext dataContext, List<ScanResult> results)
    {
        await DeleteWhere(dataContext, _ => true);
        dataContext.ScanResults.AddRange(results);
        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }
}

/// <summary>
/// Where the scan is up to, shared between the console (which asks for a scan) and the sensor (which runs it).
/// </summary>
public class ScanStatus
{
    public const string StateKey = "scan_status";

    public DateTime? RequestedAt { get; set; }
    public string? RequestedBy { get; set; }
    public DateTime? StartedAt { get; set; }
    public DateTime? FinishedAt { get; set; }
    public int ItemsChecked { get; set; }
    public int ItemsFlagged { get; set; }
    public bool AssistantReviewed { get; set; }
    public string? Error { get; set; }

    public bool IsWaitingOrRunning => RequestedAt != null && (FinishedAt == null || FinishedAt < RequestedAt);

    public static async Task<ScanStatus> Load(DataContext dataContext)
    {
        var json = await SystemState.GetValue(dataContext, StateKey);
        if (json == null)
            return new ScanStatus();

        try
        {
            return JsonSerializer.Deserialize<ScanStatus>(json) ?? new ScanStatus();
        }
        catch (JsonException)
        {
            return new ScanStatus();
        }
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }

    public static async Task<string?> Request(DataContext dataContext, string userEmail)
    {
        var scanStatus = await Load(dataContext);
        if (scanStatus.IsWaitingOrRunning && scanStatus.RequestedAt > DateTime.UtcNow.AddMinutes(-10))
            return "A scan is already running.";

        scanStatus.RequestedAt = DateTime.UtcNow;
        scanStatus.RequestedBy = userEmail;
        scanStatus.Error = null;
        await scanStatus.Save(dataContext);
        await AuditEntry.Record(dataContext, userEmail, "Computer scan requested", "System", new { });
        return null;
    }
}
