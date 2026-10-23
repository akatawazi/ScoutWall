using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Last keyboard or mouse input in one interactive Windows session, reported by the presence agent.
/// The sensor usually runs as a service in session 0, where Windows does not expose user input.
/// </summary>
[Table("user_presences")]
public class UserPresence : Repository<UserPresence>
{
    [Key]
    [Column("session_key")]
    [MaxLength(128)]
    public string SessionKey { get; set; } = string.Empty;

    [Column("user_name")]
    [MaxLength(256)]
    public string UserName { get; set; } = string.Empty;

    [Column("session_id")]
    public int SessionId { get; set; }

    [Column("last_input_at")]
    public DateTime LastInputAt { get; set; }

    [Column("reported_at")]
    public DateTime ReportedAt { get; set; }

    public static async Task Report(DataContext dataContext, UserPresence userPresence)
    {
        var existingPresence = await Get(dataContext, presence => presence.SessionKey == userPresence.SessionKey);
        if (existingPresence == null)
            await Insert(dataContext, userPresence);
        else
            await Update(dataContext, userPresence);

        dataContext.ChangeTracker.Clear();
    }

    /// <summary>
    /// Reports from agents that are still running; a stale row means the agent or the session has gone.
    /// </summary>
    public static async Task<List<UserPresence>> GetFresh(DataContext dataContext, TimeSpan maximumAge)
    {
        var reportedAfter = DateTime.UtcNow.Subtract(maximumAge);
        return await GetAll(dataContext, presence => presence.ReportedAt >= reportedAfter);
    }
}
