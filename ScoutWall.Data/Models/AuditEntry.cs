using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Who changed what: settings changes, manual blocks and revokes, alert acknowledgements, logins.
/// </summary>
[Table("audit_entries")]
[Index(nameof(OccurredAt))]
public class AuditEntry : Repository<AuditEntry>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("occurred_at")]
    public DateTime OccurredAt { get; set; }

    [Column("user_email")]
    [MaxLength(256)]
    public string UserEmail { get; set; } = string.Empty;

    [Column("action")]
    [MaxLength(128)]
    public string Action { get; set; } = string.Empty;

    [Column("target")]
    [MaxLength(512)]
    public string Target { get; set; } = string.Empty;

    [Column("details")]
    public string? Details { get; set; }

    public static async Task Record(DataContext dataContext, string userEmail, string action, string target, object? details = null)
    {
        var auditEntry = new AuditEntry
        {
            OccurredAt = DateTime.UtcNow,
            UserEmail = userEmail,
            Action = action,
            Target = target,
            Details = details == null ? null : JsonSerializer.Serialize(details)
        };
        await Insert(dataContext, auditEntry);
    }

    public static async Task<List<AuditEntry>> GetRecent(DataContext dataContext, int count)
    {
        return await Query(dataContext)
            .OrderByDescending(auditEntry => auditEntry.OccurredAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, auditEntry => auditEntry.OccurredAt < cutoff);
    }
}
