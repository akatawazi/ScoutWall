using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace ScoutWall.Data.Models;

/// <summary>
/// Heartbeat written by the sensor on every flush so the dashboard can tell live data from a stale sensor.
/// </summary>
[Table("sensor_statuses")]
public class SensorStatus : Repository<SensorStatus>
{
    private static readonly TimeSpan OfflineAfter = TimeSpan.FromSeconds(60);

    [Key]
    [Column("sensor_name")]
    [MaxLength(128)]
    public string SensorName { get; set; } = string.Empty;

    [Column("capture_mode")]
    [MaxLength(32)]
    public string CaptureMode { get; set; } = string.Empty;

    [Column("interfaces")]
    [MaxLength(1024)]
    public string Interfaces { get; set; } = string.Empty;

    [Column("started_at")]
    public DateTime StartedAt { get; set; }

    [Column("last_heartbeat_at")]
    public DateTime LastHeartbeatAt { get; set; }

    [Column("packets_captured")]
    public long PacketsCaptured { get; set; }

    [Column("packets_dropped")]
    public long PacketsDropped { get; set; }

    [Column("bytes_captured")]
    public long BytesCaptured { get; set; }

    [Column("packets_per_second")]
    public double PacketsPerSecond { get; set; }

    [Column("bits_per_second")]
    public double BitsPerSecond { get; set; }

    [Column("is_user_idle")]
    public bool? IsUserIdle { get; set; }

    [Column("active_response_mode")]
    [MaxLength(32)]
    public string? ActiveResponseMode { get; set; }

    [Column("configuration_version")]
    public long ConfigurationVersion { get; set; }

    [Column("last_error")]
    [MaxLength(1024)]
    public string? LastError { get; set; }

    [NotMapped]
    public bool IsOnline => LastHeartbeatAt > DateTime.UtcNow.Subtract(OfflineAfter);

    public static async Task Heartbeat(DataContext dataContext, SensorStatus sensorStatus)
    {
        var existingStatus = await Get(dataContext, status => status.SensorName == sensorStatus.SensorName);
        if (existingStatus == null)
            await Insert(dataContext, sensorStatus);
        else
            await Update(dataContext, sensorStatus);

        dataContext.ChangeTracker.Clear();
    }
}
