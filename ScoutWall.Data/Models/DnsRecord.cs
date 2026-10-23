using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Passive DNS: a hostname that a DNS answer on the wire resolved to an address.
/// Answers "where is this traffic going" far better than reverse DNS.
/// </summary>
[Table("dns_records")]
[Index(nameof(IpAddress), nameof(Hostname), IsUnique = true)]
[Index(nameof(Hostname))]
[Index(nameof(LastSeenAt))]
public class DnsRecord : Repository<DnsRecord>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("ip_address")]
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    [Column("hostname")]
    [MaxLength(256)]
    public string Hostname { get; set; } = string.Empty;

    [Column("record_type")]
    [MaxLength(8)]
    public string RecordType { get; set; } = string.Empty;

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [Column("seen_count")]
    public long SeenCount { get; set; }

    public static async Task RecordObservations(DataContext dataContext, IEnumerable<DnsObservation> dnsObservations)
    {
        const string commandText = """
            INSERT INTO dns_records (ip_address, hostname, record_type, first_seen_at, last_seen_at, seen_count)
            VALUES ($ipAddress, $hostname, $recordType, $observedAt, $observedAt, 1)
            ON CONFLICT (ip_address, hostname) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                seen_count = seen_count + 1;
            """;

        await ExecuteBatch(dataContext, commandText, dnsObservations, (parameters, dnsObservation) =>
        {
            parameters.AddWithValue("$ipAddress", dnsObservation.IpAddress);
            parameters.AddWithValue("$hostname", dnsObservation.Hostname);
            parameters.AddWithValue("$recordType", dnsObservation.RecordType);
            parameters.AddWithValue("$observedAt", dnsObservation.ObservedAt);
        });
    }

    public static async Task<List<DnsRecord>> GetForAddress(DataContext dataContext, string ipAddress, int count)
    {
        return await Query(dataContext)
            .Where(dnsRecord => dnsRecord.IpAddress == ipAddress)
            .OrderByDescending(dnsRecord => dnsRecord.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<Dictionary<string, string>> GetLatestHostnames(DataContext dataContext, IEnumerable<string> ipAddresses)
    {
        var addressList = ipAddresses.Distinct().ToList();
        var dnsRecords = await Query(dataContext)
            .Where(dnsRecord => addressList.Contains(dnsRecord.IpAddress))
            .OrderByDescending(dnsRecord => dnsRecord.LastSeenAt)
            .ToListAsync();

        return dnsRecords
            .GroupBy(dnsRecord => dnsRecord.IpAddress)
            .ToDictionary(group => group.Key, group => group.First().Hostname);
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, dnsRecord => dnsRecord.LastSeenAt < cutoff);
    }
}

public record DnsObservation(string IpAddress, string Hostname, string RecordType, DateTime ObservedAt);
