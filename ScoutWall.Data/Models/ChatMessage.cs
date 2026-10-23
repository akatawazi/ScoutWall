using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One line of a person's conversation with the ScoutWall assistant.
/// </summary>
[Table("chat_messages")]
[Index(nameof(UserId), nameof(CreatedAt))]
public class ChatMessage : Repository<ChatMessage>
{
    private const int RetentionDays = 30;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("user_id")]
    public long UserId { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("from_user")]
    public bool FromUser { get; set; }

    [Column("text")]
    public string Text { get; set; } = string.Empty;

    [Column("tokens")]
    public long Tokens { get; set; }

    public static async Task Add(DataContext dataContext, long userId, bool fromUser, string text, long tokens = 0)
    {
        await Insert(dataContext, new ChatMessage { UserId = userId, CreatedAt = DateTime.UtcNow, FromUser = fromUser, Text = text, Tokens = tokens });
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<ChatMessage>> GetRecent(DataContext dataContext, long userId, int count)
    {
        var recentMessages = await Query(dataContext)
            .Where(message => message.UserId == userId)
            .OrderByDescending(message => message.CreatedAt)
            .Take(count)
            .ToListAsync();
        recentMessages.Reverse();
        return recentMessages;
    }

    public static async Task<int> Clear(DataContext dataContext, long userId)
    {
        return await DeleteWhere(dataContext, message => message.UserId == userId);
    }

    public static async Task<int> DeleteExpired(DataContext dataContext)
    {
        var cutoff = DateTime.UtcNow.AddDays(-RetentionDays);
        return await DeleteWhere(dataContext, message => message.CreatedAt < cutoff);
    }
}

public enum PendingChangeStatus
{
    Proposed = 1,
    Applied = 2,
    Rejected = 3,
    Expired = 4,
    Failed = 5
}

/// <summary>
/// A change the assistant proposed in chat. Nothing happens until the person who asked presses Confirm.
/// The text on the card comes from <see cref="Summary"/>, which ScoutWall writes from the structured change,
/// never from the assistant's own words.
/// </summary>
[Table("pending_changes")]
[Index(nameof(UserId), nameof(Status))]
public class PendingChange : Repository<PendingChange>
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("user_id")]
    public long UserId { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("expires_at")]
    public DateTime ExpiresAt { get; set; }

    [Column("kind")]
    [MaxLength(64)]
    public string Kind { get; set; } = string.Empty;

    [Column("payload_json")]
    public string PayloadJson { get; set; } = "{}";

    [Column("summary")]
    [MaxLength(1024)]
    public string Summary { get; set; } = string.Empty;

    [Column("consequence")]
    [MaxLength(1024)]
    public string? Consequence { get; set; }

    /// <summary>
    /// The assistant read network-derived data (hostnames, program names) before proposing this. Those values can
    /// be chosen by an attacker, so the card says so.
    /// </summary>
    [Column("based_on_network_data")]
    public bool BasedOnNetworkData { get; set; }

    [Column("status")]
    public PendingChangeStatus Status { get; set; } = PendingChangeStatus.Proposed;

    [Column("resolved_at")]
    public DateTime? ResolvedAt { get; set; }

    [Column("error")]
    [MaxLength(1024)]
    public string? Error { get; set; }

    [NotMapped]
    public bool IsOpen => Status == PendingChangeStatus.Proposed && DateTime.UtcNow < ExpiresAt;

    public static async Task<List<PendingChange>> GetRecent(DataContext dataContext, long userId, int count)
    {
        return await Query(dataContext)
            .Where(change => change.UserId == userId)
            .OrderByDescending(change => change.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> CountSince(DataContext dataContext, long userId, DateTime since)
    {
        return await Count(dataContext, change => change.UserId == userId && change.CreatedAt >= since);
    }

    public static async Task MarkResolved(DataContext dataContext, long id, PendingChangeStatus status, string? error = null)
    {
        await dataContext.PendingChanges.Where(change => change.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(change => change.Status, status)
                .SetProperty(change => change.ResolvedAt, DateTime.UtcNow)
                .SetProperty(change => change.Error, error));
    }
}
