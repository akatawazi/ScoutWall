using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One stretch of time in which someone was at the computer, was away, or ScoutWall couldn't tell. The sensor opens
/// a period when the state changes and keeps confirming the open one, so a period never stretches across time the
/// sensor wasn't running (or the computer was asleep). Kept on this computer only: it shows when the owner is home.
/// </summary>
[Table("presence_periods")]
[Index(nameof(StartedAt))]
[Index(nameof(EndedAt))]
public class PresencePeriod : Repository<PresencePeriod>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("state")]
    public PresenceState State { get; set; }

    /// <summary>
    /// How presence was known: the presence agent, local input, or all sessions locked.
    /// </summary>
    [Column("source")]
    [MaxLength(64)]
    public string Source { get; set; } = string.Empty;

    /// <summary>
    /// When the period really began. For away periods this is the last keyboard or mouse input, which is earlier
    /// than when ScoutWall noticed (after the idle threshold); traffic from that gap is relabelled as away.
    /// </summary>
    [Column("started_at")]
    public DateTime StartedAt { get; set; }

    [Column("noticed_at")]
    public DateTime NoticedAt { get; set; }

    /// <summary>
    /// The last time the sensor confirmed this period was still going.
    /// </summary>
    [Column("confirmed_at")]
    public DateTime ConfirmedAt { get; set; }

    [Column("ended_at")]
    public DateTime? EndedAt { get; set; }

    [NotMapped]
    public bool IsOpen => EndedAt == null;

    /// <summary>
    /// The end for display and sums: the real end, or for the open period the latest confirmation.
    /// </summary>
    [NotMapped]
    public DateTime EffectiveEnd => EndedAt ?? ConfirmedAt;

    [NotMapped]
    public TimeSpan Duration => EffectiveEnd - StartedAt;

    public static async Task<PresencePeriod?> GetOpen(DataContext dataContext)
    {
        return await Query(dataContext).Where(period => period.EndedAt == null).OrderByDescending(period => period.StartedAt).FirstOrDefaultAsync();
    }

    /// <summary>
    /// Closes every open period at the given time (normally its last confirmation).
    /// </summary>
    public static async Task Close(DataContext dataContext, long id, DateTime endedAt)
    {
        await dataContext.PresencePeriods.Where(period => period.Id == id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(period => period.EndedAt, endedAt).SetProperty(period => period.ConfirmedAt, endedAt));
    }

    public static async Task Confirm(DataContext dataContext, long id, DateTime confirmedAt, string source)
    {
        await dataContext.PresencePeriods.Where(period => period.Id == id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(period => period.ConfirmedAt, confirmedAt).SetProperty(period => period.Source, source));
    }

    public static async Task<PresencePeriod> Open(DataContext dataContext, PresenceState state, string source, DateTime startedAt, DateTime noticedAt)
    {
        var period = await Insert(dataContext, new PresencePeriod
        {
            State = state,
            Source = source,
            StartedAt = startedAt,
            NoticedAt = noticedAt,
            ConfirmedAt = noticedAt
        });
        dataContext.ChangeTracker.Clear();
        return period;
    }

    /// <summary>
    /// Periods overlapping the time range, oldest first.
    /// </summary>
    public static async Task<List<PresencePeriod>> GetOverlapping(DataContext dataContext, DateTime since, DateTime until)
    {
        return await Query(dataContext)
            .Where(period => period.StartedAt < until && (period.EndedAt == null || period.EndedAt > since))
            .OrderBy(period => period.StartedAt)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, period => period.EndedAt != null && period.EndedAt < cutoff);
    }
}
