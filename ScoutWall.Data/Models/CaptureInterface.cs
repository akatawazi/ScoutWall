using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// A network interface the sensor is able to capture on. Published by the sensor so the settings page can list them.
/// </summary>
[Table("capture_interfaces")]
public class CaptureInterface : Repository<CaptureInterface>
{
    [Key]
    [Column("name")]
    [MaxLength(256)]
    public string Name { get; set; } = string.Empty;

    [Column("friendly_name")]
    [MaxLength(256)]
    public string FriendlyName { get; set; } = string.Empty;

    [Column("description")]
    [MaxLength(512)]
    public string Description { get; set; } = string.Empty;

    [Column("addresses")]
    [MaxLength(1024)]
    public string Addresses { get; set; } = string.Empty;

    [Column("mac_address")]
    [MaxLength(32)]
    public string? MacAddress { get; set; }

    [Column("is_loopback")]
    public bool IsLoopback { get; set; }

    [Column("is_capturing")]
    public bool IsCapturing { get; set; }

    /// <summary>
    /// Connected to a network with a gateway; the ones a typical person means by "my internet connection".
    /// </summary>
    [Column("is_recommended")]
    public bool IsRecommended { get; set; }

    [NotMapped]
    public string KindDescription => FriendlyName.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase) || Description.Contains("Wireless", StringComparison.OrdinalIgnoreCase)
        ? "Wi-Fi"
        : Description.Contains("ZeroTier", StringComparison.OrdinalIgnoreCase) || Description.Contains("Tailscale", StringComparison.OrdinalIgnoreCase)
            ? "Private network (VPN)"
            : Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) || Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                ? "Virtual adapter"
                : "Wired network";

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [NotMapped]
    public string DisplayName => string.IsNullOrWhiteSpace(FriendlyName) ? Description : FriendlyName;

    /// <summary>
    /// Replaces the published interface list with what the sensor sees now.
    /// </summary>
    public static async Task Publish(DataContext dataContext, List<CaptureInterface> captureInterfaces)
    {
        await dataContext.CaptureInterfaces.ExecuteDeleteAsync();
        dataContext.CaptureInterfaces.AddRange(captureInterfaces);
        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<CaptureInterface>> GetAllOrdered(DataContext dataContext)
    {
        return await Query(dataContext)
            .OrderBy(captureInterface => captureInterface.IsLoopback)
            .ThenBy(captureInterface => captureInterface.FriendlyName)
            .ToListAsync();
    }
}
