using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Small facts about the installation itself, such as when monitoring first started.
/// </summary>
[Table("system_state")]
public class SystemState : Repository<SystemState>
{
    public const string MonitoringStartedAtKey = "monitoring_started_at";
    public const string LearningReclassifiedKey = "learning_reclassified";
    public const string BaselineProfileKey = "baseline_profile";
    public const string BaselineProfileWrittenAtKey = "baseline_profile_written_at";
    public const string SetupCompletedKey = "setup_completed_at";

    public static async Task<bool> IsSetupCompleted(DataContext dataContext)
    {
        return await GetValue(dataContext, SetupCompletedKey) != null;
    }

    public static async Task MarkSetupCompleted(DataContext dataContext, string userEmail)
    {
        await SetValue(dataContext, SetupCompletedKey, DateTime.UtcNow.ToString("O"));
        await AuditEntry.Record(dataContext, userEmail, "Setup completed", "ScoutWall");
    }

    [Key]
    [Column("state_key")]
    [MaxLength(64)]
    public string StateKey { get; set; } = string.Empty;

    [Column("state_value")]
    public string StateValue { get; set; } = string.Empty;

    [Column("updated_at")]
    public DateTime UpdatedAt { get; set; }

    public static async Task<string?> GetValue(DataContext dataContext, string stateKey)
    {
        var systemState = await Get(dataContext, item => item.StateKey == stateKey);
        return systemState?.StateValue;
    }

    public static async Task SetValue(DataContext dataContext, string stateKey, string stateValue)
    {
        var existingState = await Get(dataContext, item => item.StateKey == stateKey);
        var systemState = new SystemState { StateKey = stateKey, StateValue = stateValue, UpdatedAt = DateTime.UtcNow };

        if (existingState == null)
            await Insert(dataContext, systemState);
        else
            await Update(dataContext, systemState);

        dataContext.ChangeTracker.Clear();
    }

    /// <summary>
    /// When ScoutWall first started watching this machine. Recorded once; on an existing installation it is
    /// recovered from the oldest stored traffic or verdict.
    /// </summary>
    public static async Task<DateTime> GetMonitoringStartedAt(DataContext dataContext)
    {
        var storedValue = await GetValue(dataContext, MonitoringStartedAtKey);
        if (storedValue != null && DateTime.TryParse(storedValue, null, System.Globalization.DateTimeStyles.RoundtripKind, out var storedTime))
            return storedTime;

        var startedAt = await EstimateFirstActivity(dataContext);
        await SetValue(dataContext, MonitoringStartedAtKey, startedAt.ToString("O"));
        return startedAt;
    }

    private static async Task<DateTime> EstimateFirstActivity(DataContext dataContext)
    {
        var candidates = new List<DateTime> { DateTime.UtcNow };

        var firstBucket = await dataContext.TrafficMinutes.AsNoTracking().MinAsync(record => (long?)record.BucketStart);
        if (firstBucket.HasValue)
            candidates.Add(DateTimeOffset.FromUnixTimeSeconds(firstBucket.Value).UtcDateTime);

        var firstVerdict = await dataContext.FlowVerdicts.AsNoTracking().MinAsync(verdict => (DateTime?)verdict.EvaluatedAt);
        if (firstVerdict.HasValue)
            candidates.Add(firstVerdict.Value);

        return candidates.Min();
    }
}

/// <summary>
/// The first hours after ScoutWall starts watching a machine. Everything is "new" then, so novelty is not a
/// signal: the period is used to learn what normal looks like instead of reporting it as suspicious.
/// </summary>
public record LearningPeriod(DateTime StartedAt, int Hours)
{
    public DateTime EndsAt => StartedAt.AddHours(Hours);

    public bool IsActive => DateTime.UtcNow < EndsAt;

    public TimeSpan Remaining => IsActive ? EndsAt - DateTime.UtcNow : TimeSpan.Zero;

    public static async Task<LearningPeriod> Load(DataContext dataContext)
    {
        var detectionSettings = await Setting.Load<DetectionSettings>(dataContext);
        var startedAt = await SystemState.GetMonitoringStartedAt(dataContext);
        return new LearningPeriod(startedAt, detectionSettings.LearningPeriodHours);
    }
}
