using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Everything known about one IP address: geolocation, ISP, autonomous system and blocklist state.
/// The sensor inserts a row the first time an address is seen and enriches it in the background.
/// </summary>
[Table("ip_address_profiles")]
[Index(nameof(LookedUpAt))]
[Index(nameof(CountryCode))]
public class IpAddressProfile : Repository<IpAddressProfile>
{
    [Key]
    [Column("ip_address")]
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    [Column("is_private")]
    public bool IsPrivate { get; set; }

    [Column("country_code")]
    [MaxLength(2)]
    public string? CountryCode { get; set; }

    [Column("country_name")]
    [MaxLength(128)]
    public string? CountryName { get; set; }

    [Column("region")]
    [MaxLength(128)]
    public string? Region { get; set; }

    [Column("city")]
    [MaxLength(128)]
    public string? City { get; set; }

    [Column("latitude")]
    public double? Latitude { get; set; }

    [Column("longitude")]
    public double? Longitude { get; set; }

    [Column("isp")]
    [MaxLength(256)]
    public string? Isp { get; set; }

    [Column("organization")]
    [MaxLength(256)]
    public string? Organization { get; set; }

    [Column("autonomous_system_number")]
    public long? AutonomousSystemNumber { get; set; }

    [Column("autonomous_system_organization")]
    [MaxLength(256)]
    public string? AutonomousSystemOrganization { get; set; }

    [Column("reverse_dns")]
    [MaxLength(256)]
    public string? ReverseDns { get; set; }

    [Column("lookup_source")]
    [MaxLength(32)]
    public string? LookupSource { get; set; }

    [Column("lookup_error")]
    [MaxLength(256)]
    public string? LookupError { get; set; }

    [Column("looked_up_at")]
    public DateTime? LookedUpAt { get; set; }

    [Column("is_blocklisted")]
    public bool IsBlocklisted { get; set; }

    [Column("blocklist_source")]
    [MaxLength(128)]
    public string? BlocklistSource { get; set; }

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [NotMapped]
    public string LocationDisplay
    {
        get
        {
            if (IsPrivate)
                return "Private network";

            var locationParts = new[] { City, CountryName }.Where(part => !string.IsNullOrWhiteSpace(part));
            var location = string.Join(", ", locationParts);
            return string.IsNullOrEmpty(location) ? "Unknown" : location;
        }
    }

    [NotMapped]
    public string IspDisplay => Isp ?? AutonomousSystemOrganization ?? Organization ?? (IsPrivate ? "Local" : "Unknown");

    [NotMapped]
    public string AutonomousSystemDisplay =>
        AutonomousSystemNumber.HasValue ? $"AS{AutonomousSystemNumber} {AutonomousSystemOrganization}".Trim() : "Unknown";

    /// <summary>
    /// Records that the addresses were seen. New addresses get a row; existing rows get a fresh last-seen time.
    /// </summary>
    public static async Task RecordSeen(DataContext dataContext, IEnumerable<SeenAddress> seenAddresses)
    {
        const string commandText = """
            INSERT INTO ip_address_profiles (ip_address, is_private, is_blocklisted, blocklist_source, first_seen_at, last_seen_at)
            VALUES ($ipAddress, $isPrivate, $isBlocklisted, $blocklistSource, $seenAt, $seenAt)
            ON CONFLICT (ip_address) DO UPDATE SET
                last_seen_at = excluded.last_seen_at,
                is_blocklisted = excluded.is_blocklisted,
                blocklist_source = excluded.blocklist_source;
            """;

        await ExecuteBatch(dataContext, commandText, seenAddresses, (parameters, seenAddress) =>
        {
            parameters.AddWithValue("$ipAddress", seenAddress.IpAddress);
            parameters.AddWithValue("$isPrivate", seenAddress.IsPrivate);
            parameters.AddWithValue("$isBlocklisted", seenAddress.BlocklistSource != null);
            parameters.AddWithValue("$blocklistSource", DatabaseValue(seenAddress.BlocklistSource));
            parameters.AddWithValue("$seenAt", seenAddress.SeenAt);
        });
    }

    public static async Task<List<IpAddressProfile>> GetPendingLookups(DataContext dataContext, int count, DateTime staleBefore)
    {
        return await Query(dataContext)
            .Where(profile => !profile.IsPrivate && (profile.LookedUpAt == null || profile.LookedUpAt < staleBefore))
            .OrderByDescending(profile => profile.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task SaveLookup(DataContext dataContext, IpAddressProfile lookedUpProfile)
    {
        await dataContext.IpAddressProfiles
            .Where(profile => profile.IpAddress == lookedUpProfile.IpAddress)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(profile => profile.CountryCode, lookedUpProfile.CountryCode)
                .SetProperty(profile => profile.CountryName, lookedUpProfile.CountryName)
                .SetProperty(profile => profile.Region, lookedUpProfile.Region)
                .SetProperty(profile => profile.City, lookedUpProfile.City)
                .SetProperty(profile => profile.Latitude, lookedUpProfile.Latitude)
                .SetProperty(profile => profile.Longitude, lookedUpProfile.Longitude)
                .SetProperty(profile => profile.Isp, lookedUpProfile.Isp)
                .SetProperty(profile => profile.Organization, lookedUpProfile.Organization)
                .SetProperty(profile => profile.AutonomousSystemNumber, lookedUpProfile.AutonomousSystemNumber)
                .SetProperty(profile => profile.AutonomousSystemOrganization, lookedUpProfile.AutonomousSystemOrganization)
                .SetProperty(profile => profile.ReverseDns, lookedUpProfile.ReverseDns)
                .SetProperty(profile => profile.LookupSource, lookedUpProfile.LookupSource)
                .SetProperty(profile => profile.LookupError, lookedUpProfile.LookupError)
                .SetProperty(profile => profile.LookedUpAt, lookedUpProfile.LookedUpAt));
    }

    public static async Task<Dictionary<string, IpAddressProfile>> GetMany(DataContext dataContext, IEnumerable<string> ipAddresses)
    {
        var addressList = ipAddresses.Distinct().ToList();
        var profiles = await GetAll(dataContext, profile => addressList.Contains(profile.IpAddress));
        return profiles.ToDictionary(profile => profile.IpAddress);
    }

    /// <summary>
    /// Attaches profiles and passively observed hostnames to address summaries for display.
    /// </summary>
    public static async Task Enrich(DataContext dataContext, IEnumerable<AddressSummary> addressSummaries)
    {
        var summaryList = addressSummaries.ToList();
        var ipAddresses = summaryList.Select(summary => summary.IpAddress).ToList();
        var profiles = await GetMany(dataContext, ipAddresses);
        var hostnames = await DnsRecord.GetLatestHostnames(dataContext, ipAddresses);

        foreach (var addressSummary in summaryList)
        {
            addressSummary.Profile = profiles.GetValueOrDefault(addressSummary.IpAddress);
            addressSummary.Hostname = hostnames.GetValueOrDefault(addressSummary.IpAddress) ?? addressSummary.Profile?.ReverseDns;
        }
    }
}

/// <summary>
/// An address observed by the sensor during one flush. Not persisted directly.
/// </summary>
public record SeenAddress(string IpAddress, bool IsPrivate, string? BlocklistSource, DateTime SeenAt);
