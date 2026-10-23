using Microsoft.EntityFrameworkCore;
using ScoutWall.Data.Models;

namespace ScoutWall.Data.Querying;

/// <summary>
/// Answers "did we talk to any .gov sites?", "anything in Russia?" or "where does Zoom connect?". Names come from
/// DNS answers, TLS server names and reverse DNS; much traffic (encrypted DNS, QUIC) has no name, so every answer
/// says how much of the traffic in the period had a known name at all.
/// </summary>
public static class DestinationSearch
{
    private const int MaximumCandidates = 2000;

    public const string PatternRules = "Patterns: \".gov\" or \"*.gov\" matches names ending in .gov at a dot (irs.gov, www.ssa.gov; not gov.uk); "
        + "a pattern with * elsewhere is a wildcard (\"*bank*\"); anything else matches part of a name (\"linkedin\").";

    public static async Task<object> Search(DataContext dataContext, string? namePattern, string? country, string? network, string? program, int sinceHours, int limit)
    {
        if (new[] { namePattern, country, network, program }.All(string.IsNullOrWhiteSpace))
            return new { error = "Give at least one of name_pattern, country, network or program." };

        sinceHours = Math.Clamp(sinceHours <= 0 ? 168 : sinceHours, 1, 24 * 90);
        limit = Math.Clamp(limit <= 0 ? 50 : limit, 1, 100);
        var sinceUnixSeconds = DateTimeOffset.UtcNow.AddHours(-sinceHours).ToUnixTimeSeconds();
        var sinceTime = DateTime.UtcNow.AddHours(-sinceHours);

        HashSet<string>? candidates = null;
        void Narrow(IEnumerable<string> addresses)
        {
            var set = addresses.ToHashSet();
            candidates = candidates == null ? set : candidates.Intersect(set).ToHashSet();
        }

        var namesByAddress = new Dictionary<string, HashSet<string>>();
        if (!string.IsNullOrWhiteSpace(namePattern))
        {
            var matcher = NameMatcher(namePattern.Trim().ToLowerInvariant());
            var core = matcher.Core;
            var dnsMatches = await dataContext.DnsRecords.AsNoTracking()
                .Where(record => EF.Functions.Like(record.Hostname, $"%{core}%"))
                .Select(record => new { Address = record.IpAddress, Name = record.Hostname })
                .Take(20_000).ToListAsync();
            var tlsMatches = await dataContext.TlsSessions.AsNoTracking()
                .Where(session => EF.Functions.Like(session.ServerName, $"%{core}%"))
                .Select(session => new { Address = session.ServerIp, Name = session.ServerName })
                .Take(20_000).ToListAsync();
            var reverseMatches = await dataContext.IpAddressProfiles.AsNoTracking()
                .Where(profile => profile.ReverseDns != null && EF.Functions.Like(profile.ReverseDns, $"%{core}%"))
                .Select(profile => new { Address = profile.IpAddress, Name = profile.ReverseDns! })
                .Take(20_000).ToListAsync();

            foreach (var match in dnsMatches.Concat(tlsMatches).Concat(reverseMatches).Where(match => matcher.IsMatch(match.Name.ToLowerInvariant())))
            {
                if (!namesByAddress.TryGetValue(match.Address, out var names))
                    namesByAddress[match.Address] = names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                names.Add(match.Name);
            }

            Narrow(namesByAddress.Keys);
        }

        if (!string.IsNullOrWhiteSpace(country))
        {
            var countryText = country.Trim();
            Narrow(await dataContext.IpAddressProfiles.AsNoTracking()
                .Where(profile => profile.CountryCode == countryText.ToUpper() || EF.Functions.Like(profile.CountryName!, $"%{countryText}%"))
                .Select(profile => profile.IpAddress).ToListAsync());
        }

        if (!string.IsNullOrWhiteSpace(network))
        {
            var networkText = network.Trim();
            Narrow(await dataContext.IpAddressProfiles.AsNoTracking()
                .Where(profile => EF.Functions.Like(profile.Isp!, $"%{networkText}%") || EF.Functions.Like(profile.Organization!, $"%{networkText}%")
                    || EF.Functions.Like(profile.AutonomousSystemOrganization!, $"%{networkText}%"))
                .Select(profile => profile.IpAddress).ToListAsync());
        }

        if (!string.IsNullOrWhiteSpace(program))
        {
            var programText = program.Trim();
            var programIds = await dataContext.ProcessImages.AsNoTracking()
                .Where(image => EF.Functions.Like(image.ImagePath, $"%{programText}%") || EF.Functions.Like(image.FriendlyName!, $"%{programText}%")
                    || EF.Functions.Like(image.ProductName!, $"%{programText}%"))
                .Select(image => image.Id).ToListAsync();
            Narrow(await dataContext.ProcessTrafficMinutes.AsNoTracking()
                .Where(record => record.BucketStart >= sinceUnixSeconds && programIds.Contains(record.ProcessImageId))
                .Select(record => record.RemoteIp).Distinct().ToListAsync());
        }

        var addresses = (candidates ?? []).Take(MaximumCandidates).ToList();
        var coverage = await NamedShare(dataContext, sinceUnixSeconds);

        if (addresses.Count == 0)
            return new { matches = Array.Empty<object>(), period_hours = sinceHours, coverage, pattern_rules = PatternRules };

        // Traffic per address: attributed to programs, and everything the network capture saw.
        var programTraffic = await dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && addresses.Contains(record.RemoteIp))
            .GroupBy(record => new { record.RemoteIp, record.ProcessImageId })
            .Select(group => new
            {
                group.Key.RemoteIp,
                group.Key.ProcessImageId,
                Sent = group.Sum(record => record.BytesSent),
                Received = group.Sum(record => record.BytesReceived),
                AwaySent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                First = group.Min(record => record.BucketStart),
                Last = group.Max(record => record.BucketStart)
            })
            .ToListAsync();
        var networkTraffic = await dataContext.TrafficHours.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && addresses.Contains(record.RemoteIp))
            .GroupBy(record => record.RemoteIp)
            .Select(group => new { RemoteIp = group.Key, Out = group.Sum(record => record.BytesOut), In = group.Sum(record => record.BytesIn), Connections = group.Sum(record => record.ConnectionCount) })
            .ToDictionaryAsync(row => row.RemoteIp);
        var programIdsUsed = programTraffic.Select(row => row.ProcessImageId).Distinct().ToList();
        var programNames = await dataContext.ProcessImages.AsNoTracking()
            .Where(image => programIdsUsed.Contains(image.Id))
            .ToDictionaryAsync(image => image.Id, image => image.ImagePath);
        var profiles = await IpAddressProfile.GetMany(dataContext, addresses);

        if (namesByAddress.Count == 0)
        {
            var hostnames = await DnsRecord.GetLatestHostnames(dataContext, addresses);
            foreach (var (address, hostname) in hostnames)
                namesByAddress[address] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { hostname };
        }

        var trafficByAddress = programTraffic.GroupBy(row => row.RemoteIp).ToDictionary(group => group.Key, group => group.ToList());
        var matches = addresses.Select(address =>
            {
                var rows = trafficByAddress.GetValueOrDefault(address) ?? [];
                var captured = networkTraffic.GetValueOrDefault(address);
                var profile = profiles.GetValueOrDefault(address);
                return new
                {
                    ip = address,
                    names = namesByAddress.GetValueOrDefault(address)?.Take(5).ToList() ?? (profile?.ReverseDns != null ? [profile.ReverseDns] : []),
                    place = profile?.LocationDisplay,
                    network = profile?.IspDisplay,
                    blocklisted = profile?.IsBlocklisted == true,
                    uploaded_bytes = Math.Max(rows.Sum(row => row.Sent), captured?.Out ?? 0),
                    downloaded_bytes = Math.Max(rows.Sum(row => row.Received), captured?.In ?? 0),
                    uploaded_while_away_bytes = rows.Sum(row => row.AwaySent),
                    connections = captured?.Connections ?? 0,
                    first_seen_utc = rows.Count == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(rows.Min(row => row.First)).UtcDateTime,
                    last_seen_utc = rows.Count == 0 ? null : (DateTime?)DateTimeOffset.FromUnixTimeSeconds(rows.Max(row => row.Last)).UtcDateTime,
                    programs = rows.OrderByDescending(row => row.Sent + row.Received).Take(5)
                        .Select(row => new { program = programNames.GetValueOrDefault(row.ProcessImageId), uploaded_bytes = row.Sent, downloaded_bytes = row.Received }),
                    had_traffic_in_period = rows.Count > 0 || captured != null
                };
            })
            .OrderByDescending(match => match.had_traffic_in_period)
            .ThenByDescending(match => match.uploaded_bytes + match.downloaded_bytes)
            .Take(limit)
            .ToList();

        return new
        {
            matches,
            match_count = addresses.Count,
            note = "Addresses with had_traffic_in_period false were looked up by name but no traffic to them was seen in the period.",
            period_hours = sinceHours,
            coverage,
            pattern_rules = PatternRules
        };
    }

    /// <summary>
    /// The share of all captured traffic in the period that went to addresses with any known name.
    /// </summary>
    private static async Task<object> NamedShare(DataContext dataContext, long sinceUnixSeconds)
    {
        var totals = await dataContext.Database.SqlQueryRaw<NamedTotals>("""
            SELECT COALESCE(SUM(bytes_in + bytes_out), 0) AS "Total",
                   COALESCE(SUM(CASE WHEN remote_ip IN (SELECT ip_address FROM dns_records)
                                       OR remote_ip IN (SELECT server_ip FROM tls_sessions)
                                       OR remote_ip IN (SELECT ip_address FROM ip_address_profiles WHERE reverse_dns IS NOT NULL)
                                     THEN bytes_in + bytes_out ELSE 0 END), 0) AS "Named"
            FROM traffic_hours WHERE bucket_start >= {0}
            """, sinceUnixSeconds).FirstAsync();
        var share = totals.Total == 0 ? 0 : (double)totals.Named / totals.Total;
        return new
        {
            named_share_of_bytes = Math.Round(share, 2),
            explanation = "Names are only known for traffic whose DNS answer, TLS server name or reverse DNS was seen. Browsers using encrypted DNS or QUIC often hide names, "
                + "so a search can only say what was seen among named traffic, not that something never happened."
        };
    }

    private sealed record NameMatcherResult(string Core, Func<string, bool> IsMatch);

    private static NameMatcherResult NameMatcher(string pattern)
    {
        if (pattern.StartsWith("*.") || (pattern.StartsWith('.') && !pattern[1..].Contains('*')))
        {
            var suffix = pattern.TrimStart('*').TrimStart('.');
            return new NameMatcherResult(suffix, name => name == suffix || name.EndsWith("." + suffix));
        }

        if (pattern.Contains('*'))
        {
            var regex = new System.Text.RegularExpressions.Regex("^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*") + "$");
            var core = pattern.Split('*', StringSplitOptions.RemoveEmptyEntries).OrderByDescending(part => part.Length).FirstOrDefault() ?? string.Empty;
            return new NameMatcherResult(core, regex.IsMatch);
        }

        return new NameMatcherResult(pattern, name => name.Contains(pattern));
    }

    private sealed class NamedTotals
    {
        public long Total { get; set; }
        public long Named { get; set; }
    }
}
