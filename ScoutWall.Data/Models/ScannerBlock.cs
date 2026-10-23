using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// An internet address that scanned this computer or touched a decoy port. All of them are blocked by one shared
/// firewall rule, so a busy connection with constant scanner traffic never runs out of block slots or churns
/// the firewall with one rule per address.
/// </summary>
[Table("scanner_blocks")]
[Index(nameof(IpAddress), IsUnique = true)]
[Index(nameof(ExpiresAt))]
public class ScannerBlock : Repository<ScannerBlock>
{
    public const string FirewallRuleName = "ScoutWall Scanner Blocklist";

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("ip_address")]
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    [Column("reason")]
    [MaxLength(256)]
    public string Reason { get; set; } = string.Empty;

    [Column("hit_count")]
    public int HitCount { get; set; } = 1;

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [Column("expires_at")]
    public DateTime ExpiresAt { get; set; }

    /// <summary>
    /// Adds the address, or extends its block if it is already listed. Returns true when it is new.
    /// </summary>
    public static async Task<bool> Add(DataContext dataContext, string ipAddress, string reason, TimeSpan duration)
    {
        var now = DateTime.UtcNow;
        var existing = await dataContext.ScannerBlocks.FirstOrDefaultAsync(block => block.IpAddress == ipAddress);
        if (existing != null)
        {
            existing.HitCount++;
            existing.LastSeenAt = now;
            existing.ExpiresAt = now + duration;
            await dataContext.SaveChangesAsync();
            dataContext.ChangeTracker.Clear();
            return false;
        }

        dataContext.ScannerBlocks.Add(new ScannerBlock
        {
            IpAddress = ipAddress,
            Reason = reason.Length <= 256 ? reason : reason[..256],
            FirstSeenAt = now,
            LastSeenAt = now,
            ExpiresAt = now + duration
        });
        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
        return true;
    }

    /// <summary>
    /// The addresses to block now, newest first, capped so the firewall rule stays a reasonable size.
    /// </summary>
    public static async Task<List<string>> GetActiveAddresses(DataContext dataContext, int maximum)
    {
        var now = DateTime.UtcNow;
        return await Query(dataContext)
            .Where(block => block.ExpiresAt > now)
            .OrderByDescending(block => block.LastSeenAt)
            .Take(maximum)
            .Select(block => block.IpAddress)
            .ToListAsync();
    }

    public static async Task<List<ScannerBlock>> GetActive(DataContext dataContext, int count)
    {
        var now = DateTime.UtcNow;
        return await Query(dataContext)
            .Where(block => block.ExpiresAt > now)
            .OrderByDescending(block => block.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> CountActive(DataContext dataContext)
    {
        var now = DateTime.UtcNow;
        return await Count(dataContext, block => block.ExpiresAt > now);
    }

    public static async Task<int> Remove(DataContext dataContext, long? id)
    {
        return id.HasValue
            ? await DeleteWhere(dataContext, block => block.Id == id.Value)
            : await DeleteWhere(dataContext, _ => true);
    }

    public static async Task<int> DeleteExpired(DataContext dataContext)
    {
        var now = DateTime.UtcNow;
        return await DeleteWhere(dataContext, block => block.ExpiresAt <= now);
    }
}
