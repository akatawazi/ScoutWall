using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Shared shape and queries for the per-minute and per-hour traffic aggregates.
/// A row is one conversation between a remote and local address on a service port within a time bucket.
/// "In" always means toward the local address and "out" means toward the remote address.
/// </summary>
public abstract class TrafficRecord<T> : Repository<T> where T : TrafficRecord<T>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    /// <summary>
    /// Bucket start in Unix seconds (UTC).
    /// </summary>
    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("remote_ip")]
    [MaxLength(45)]
    public string RemoteIp { get; set; } = string.Empty;

    [Column("local_ip")]
    [MaxLength(45)]
    public string LocalIp { get; set; } = string.Empty;

    [Column("service_port")]
    public int ServicePort { get; set; }

    [Column("protocol")]
    [MaxLength(16)]
    public string Protocol { get; set; } = string.Empty;

    [Column("direction")]
    public TrafficDirection Direction { get; set; }

    [Column("bytes_in")]
    public long BytesIn { get; set; }

    [Column("bytes_out")]
    public long BytesOut { get; set; }

    [Column("packets_in")]
    public long PacketsIn { get; set; }

    [Column("packets_out")]
    public long PacketsOut { get; set; }

    [Column("connection_count")]
    public long ConnectionCount { get; set; }

    protected static async Task UpsertBatch(DataContext dataContext, string tableName, IEnumerable<TrafficCount> trafficCounts)
    {
        var commandText = $"""
            INSERT INTO {tableName}
                (bucket_start, remote_ip, local_ip, service_port, protocol, direction,
                 bytes_in, bytes_out, packets_in, packets_out, connection_count)
            VALUES
                ($bucketStart, $remoteIp, $localIp, $servicePort, $protocol, $direction,
                 $bytesIn, $bytesOut, $packetsIn, $packetsOut, $connectionCount)
            ON CONFLICT (bucket_start, remote_ip, local_ip, service_port, protocol) DO UPDATE SET
                bytes_in = bytes_in + excluded.bytes_in,
                bytes_out = bytes_out + excluded.bytes_out,
                packets_in = packets_in + excluded.packets_in,
                packets_out = packets_out + excluded.packets_out,
                connection_count = connection_count + excluded.connection_count;
            """;

        await ExecuteBatch(dataContext, commandText, trafficCounts, (parameters, trafficCount) =>
        {
            parameters.AddWithValue("$bucketStart", trafficCount.BucketStart);
            parameters.AddWithValue("$remoteIp", trafficCount.RemoteIp);
            parameters.AddWithValue("$localIp", trafficCount.LocalIp);
            parameters.AddWithValue("$servicePort", trafficCount.ServicePort);
            parameters.AddWithValue("$protocol", trafficCount.Protocol);
            parameters.AddWithValue("$direction", (int)trafficCount.Direction);
            parameters.AddWithValue("$bytesIn", trafficCount.BytesIn);
            parameters.AddWithValue("$bytesOut", trafficCount.BytesOut);
            parameters.AddWithValue("$packetsIn", trafficCount.PacketsIn);
            parameters.AddWithValue("$packetsOut", trafficCount.PacketsOut);
            parameters.AddWithValue("$connectionCount", trafficCount.ConnectionCount);
        });
    }

    public static async Task<TrafficTotals> GetTotals(DataContext dataContext, long sinceUnixSeconds, string? ipAddress = null)
    {
        var records = FilterRecords(dataContext, sinceUnixSeconds, ipAddress);

        var trafficTotals = await records
            .GroupBy(record => 1)
            .Select(group => new TrafficTotals
            {
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                PacketsIn = group.Sum(record => record.PacketsIn),
                PacketsOut = group.Sum(record => record.PacketsOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount)
            })
            .FirstOrDefaultAsync() ?? new TrafficTotals();

        trafficTotals.UniqueRemoteAddresses = await records.Select(record => record.RemoteIp).Distinct().CountAsync();
        trafficTotals.InboundConnectionCount = await records
            .Where(record => record.Direction == TrafficDirection.Inbound)
            .SumAsync(record => record.ConnectionCount);
        return trafficTotals;
    }

    public static async Task<List<TrafficTimelinePoint>> GetTimeline(
        DataContext dataContext,
        long sinceUnixSeconds,
        int stepSeconds,
        string? ipAddress = null)
    {
        return await FilterRecords(dataContext, sinceUnixSeconds, ipAddress)
            .GroupBy(record => record.BucketStart / stepSeconds)
            .Select(group => new TrafficTimelinePoint
            {
                BucketStart = group.Key * stepSeconds,
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount)
            })
            .OrderBy(point => point.BucketStart)
            .ToListAsync();
    }

    public static async Task<List<AddressSummary>> GetTopRemoteAddresses(
        DataContext dataContext,
        long sinceUnixSeconds,
        int count,
        bool orderByIncoming)
    {
        var summaries = Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds)
            .GroupBy(record => record.RemoteIp)
            .Select(group => new AddressSummary
            {
                IpAddress = group.Key,
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                PacketCount = group.Sum(record => record.PacketsIn + record.PacketsOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount),
                ServiceCount = group.Select(record => record.ServicePort).Distinct().Count()
            });

        var orderedSummaries = orderByIncoming
            ? summaries.OrderByDescending(summary => summary.BytesIn)
            : summaries.OrderByDescending(summary => summary.BytesOut);

        return await orderedSummaries.Take(count).ToListAsync();
    }

    public static async Task<List<AddressSummary>> GetTopLocalAddresses(DataContext dataContext, long sinceUnixSeconds, int count)
    {
        return await Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds)
            .GroupBy(record => record.LocalIp)
            .Select(group => new AddressSummary
            {
                IpAddress = group.Key,
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                PacketCount = group.Sum(record => record.PacketsIn + record.PacketsOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount),
                ServiceCount = group.Select(record => record.ServicePort).Distinct().Count()
            })
            .OrderByDescending(summary => summary.BytesIn + summary.BytesOut)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<ServiceSummary>> GetTopServices(
        DataContext dataContext,
        long sinceUnixSeconds,
        int count,
        string? ipAddress = null)
    {
        return await FilterRecords(dataContext, sinceUnixSeconds, ipAddress)
            .GroupBy(record => new { record.ServicePort, record.Protocol, record.Direction })
            .Select(group => new ServiceSummary
            {
                ServicePort = group.Key.ServicePort,
                Protocol = group.Key.Protocol,
                Direction = group.Key.Direction,
                BytesIn = group.Sum(record => record.BytesIn),
                BytesOut = group.Sum(record => record.BytesOut),
                ConnectionCount = group.Sum(record => record.ConnectionCount),
                RemoteAddressCount = group.Select(record => record.RemoteIp).Distinct().Count()
            })
            .OrderByDescending(summary => summary.BytesIn + summary.BytesOut)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<CountrySummary>> GetTopCountries(DataContext dataContext, long sinceUnixSeconds, int count)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        var profiles = dataContext.IpAddressProfiles.AsNoTracking().Where(profile => profile.CountryCode != null);

        return await records
            .Join(profiles, record => record.RemoteIp, profile => profile.IpAddress, (record, profile) => new
            {
                profile.CountryCode,
                profile.CountryName,
                record.RemoteIp,
                record.BytesIn,
                record.BytesOut,
                record.ConnectionCount
            })
            .GroupBy(row => row.CountryCode)
            .Select(group => new CountrySummary
            {
                CountryCode = group.Key!,
                CountryName = group.Max(row => row.CountryName) ?? group.Key!,
                BytesIn = group.Sum(row => row.BytesIn),
                BytesOut = group.Sum(row => row.BytesOut),
                ConnectionCount = group.Sum(row => row.ConnectionCount),
                RemoteAddressCount = group.Select(row => row.RemoteIp).Distinct().Count()
            })
            .OrderByDescending(summary => summary.BytesIn + summary.BytesOut)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// Where traffic went, by approximate place: addresses whose looked-up coordinates fall within about 10 km
    /// of each other become one place, largest first.
    /// </summary>
    public static async Task<List<LocationSummary>> GetLocations(DataContext dataContext, long sinceUnixSeconds, int count)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        var profiles = dataContext.IpAddressProfiles.AsNoTracking()
            .Where(profile => !profile.IsPrivate && profile.Latitude != null && profile.Longitude != null);

        var addresses = await records
            .Join(profiles, record => record.RemoteIp, profile => profile.IpAddress, (record, profile) => new
            {
                record.RemoteIp,
                profile.Latitude,
                profile.Longitude,
                profile.City,
                profile.CountryName,
                record.BytesIn,
                record.BytesOut
            })
            .GroupBy(row => new { row.RemoteIp, row.Latitude, row.Longitude, row.City, row.CountryName })
            .Select(group => new
            {
                group.Key.RemoteIp,
                Latitude = group.Key.Latitude!.Value,
                Longitude = group.Key.Longitude!.Value,
                group.Key.City,
                group.Key.CountryName,
                BytesIn = group.Sum(row => row.BytesIn),
                BytesOut = group.Sum(row => row.BytesOut)
            })
            .ToListAsync();

        return addresses
            .GroupBy(address => (Math.Round(address.Latitude, 1), Math.Round(address.Longitude, 1)))
            .Select(group =>
            {
                var largest = group.MaxBy(address => address.BytesIn + address.BytesOut)!;
                return new LocationSummary
                {
                    Latitude = group.Key.Item1,
                    Longitude = group.Key.Item2,
                    City = largest.City,
                    CountryName = largest.CountryName,
                    BytesIn = group.Sum(address => address.BytesIn),
                    BytesOut = group.Sum(address => address.BytesOut),
                    RemoteAddressCount = group.Count(),
                    LargestAddress = largest.RemoteIp
                };
            })
            .OrderByDescending(location => location.TotalBytes)
            .Take(count)
            .ToList();
    }

    /// <summary>
    /// The addresses the given address talked to, from either side of the conversation.
    /// </summary>
    public static async Task<List<AddressSummary>> GetPeers(DataContext dataContext, long sinceUnixSeconds, string ipAddress, int count)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        var remotePeers = records.Where(record => record.LocalIp == ipAddress).Select(record => new
        {
            PeerIp = record.RemoteIp,
            record.BytesIn,
            record.BytesOut,
            Packets = record.PacketsIn + record.PacketsOut,
            record.ConnectionCount,
            record.ServicePort
        });
        var localPeers = records.Where(record => record.RemoteIp == ipAddress).Select(record => new
        {
            PeerIp = record.LocalIp,
            BytesIn = record.BytesOut,
            BytesOut = record.BytesIn,
            Packets = record.PacketsIn + record.PacketsOut,
            record.ConnectionCount,
            record.ServicePort
        });

        return await remotePeers
            .Concat(localPeers)
            .GroupBy(row => row.PeerIp)
            .Select(group => new AddressSummary
            {
                IpAddress = group.Key,
                BytesIn = group.Sum(row => row.BytesIn),
                BytesOut = group.Sum(row => row.BytesOut),
                PacketCount = group.Sum(row => row.Packets),
                ConnectionCount = group.Sum(row => row.ConnectionCount),
                ServiceCount = group.Select(row => row.ServicePort).Distinct().Count()
            })
            .OrderByDescending(summary => summary.BytesIn + summary.BytesOut)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, record => record.BucketStart < cutoffUnixSeconds);
    }

    private static IQueryable<T> FilterRecords(DataContext dataContext, long sinceUnixSeconds, string? ipAddress)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        if (string.IsNullOrEmpty(ipAddress))
            return records;

        return records.Where(record => record.RemoteIp == ipAddress || record.LocalIp == ipAddress);
    }
}

[Table("traffic_minutes")]
[Index(nameof(BucketStart), nameof(RemoteIp), nameof(LocalIp), nameof(ServicePort), nameof(Protocol), IsUnique = true)]
[Index(nameof(RemoteIp), nameof(BucketStart))]
[Index(nameof(LocalIp), nameof(BucketStart))]
public class TrafficMinute : TrafficRecord<TrafficMinute>
{
    public const int BucketSeconds = 60;

    public static async Task Record(DataContext dataContext, IEnumerable<TrafficCount> trafficCounts)
    {
        await UpsertBatch(dataContext, "traffic_minutes", trafficCounts);
    }
}

[Table("traffic_hours")]
[Index(nameof(BucketStart), nameof(RemoteIp), nameof(LocalIp), nameof(ServicePort), nameof(Protocol), IsUnique = true)]
[Index(nameof(RemoteIp), nameof(BucketStart))]
[Index(nameof(LocalIp), nameof(BucketStart))]
public class TrafficHour : TrafficRecord<TrafficHour>
{
    public const int BucketSeconds = 3600;

    /// <summary>
    /// Rolls minute-level counts up into hour buckets as they are written.
    /// </summary>
    public static async Task Record(DataContext dataContext, IEnumerable<TrafficCount> minuteCounts)
    {
        var hourCounts = minuteCounts.Select(trafficCount => trafficCount.MoveToBucket(BucketSeconds));
        await UpsertBatch(dataContext, "traffic_hours", hourCounts);
    }
}
