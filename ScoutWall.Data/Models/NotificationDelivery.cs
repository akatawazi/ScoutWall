using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum NotificationChannel
{
    Email = 1,
    Webhook = 2,
    Desktop = 3
}

public enum NotificationStatus
{
    Pending = 1,
    Sent = 2,
    Abandoned = 3
}

/// <summary>
/// An outgoing notification. Queued when an alert is raised and delivered by a separate loop with retries,
/// so a slow mail server never holds up packet processing. Desktop notifications are picked up by the presence agent.
/// </summary>
[Table("notification_deliveries")]
[Index(nameof(Status), nameof(Channel), nameof(NextAttemptAt))]
public class NotificationDelivery : Repository<NotificationDelivery>
{
    private const int MaximumAttempts = 6;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("alert_id")]
    public long? AlertId { get; set; }

    [Column("channel")]
    public NotificationChannel Channel { get; set; }

    [Column("status")]
    public NotificationStatus Status { get; set; } = NotificationStatus.Pending;

    [Column("severity")]
    public AlertSeverity Severity { get; set; }

    [Column("title")]
    [MaxLength(256)]
    public string Title { get; set; } = string.Empty;

    [Column("message")]
    public string Message { get; set; } = string.Empty;

    [Column("attempts")]
    public int Attempts { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("next_attempt_at")]
    public DateTime NextAttemptAt { get; set; }

    [Column("sent_at")]
    public DateTime? SentAt { get; set; }

    [Column("last_error")]
    [MaxLength(1024)]
    public string? LastError { get; set; }

    public static async Task Enqueue(DataContext dataContext, NotificationChannel channel, AlertSeverity severity, string title, string message, long? alertId)
    {
        var notificationDelivery = new NotificationDelivery
        {
            AlertId = alertId,
            Channel = channel,
            Severity = severity,
            Title = title,
            Message = message,
            CreatedAt = DateTime.UtcNow,
            NextAttemptAt = DateTime.UtcNow
        };
        await Insert(dataContext, notificationDelivery);
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<NotificationDelivery>> GetDue(DataContext dataContext, NotificationChannel channel, int count)
    {
        var now = DateTime.UtcNow;
        return await Query(dataContext)
            .Where(delivery => delivery.Status == NotificationStatus.Pending
                && delivery.Channel == channel
                && delivery.NextAttemptAt <= now)
            .OrderBy(delivery => delivery.NextAttemptAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task MarkSent(DataContext dataContext, long id)
    {
        await dataContext.NotificationDeliveries
            .Where(delivery => delivery.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(delivery => delivery.Status, NotificationStatus.Sent)
                .SetProperty(delivery => delivery.SentAt, DateTime.UtcNow)
                .SetProperty(delivery => delivery.Attempts, delivery => delivery.Attempts + 1));
    }

    /// <summary>
    /// Schedules a retry with exponential backoff, giving up after a fixed number of attempts.
    /// </summary>
    public async Task MarkFailed(DataContext dataContext, string error)
    {
        Attempts++;
        LastError = error.Length > 1000 ? error[..1000] : error;
        NextAttemptAt = DateTime.UtcNow.AddMinutes(Math.Pow(2, Attempts));
        Status = Attempts >= MaximumAttempts ? NotificationStatus.Abandoned : NotificationStatus.Pending;
        await Update(dataContext, this);
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<NotificationDelivery>> GetRecent(DataContext dataContext, int count)
    {
        return await Query(dataContext)
            .OrderByDescending(delivery => delivery.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, delivery => delivery.CreatedAt < cutoff && delivery.Status != NotificationStatus.Pending);
    }
}
