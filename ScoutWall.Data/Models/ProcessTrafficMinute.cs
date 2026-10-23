using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Bytes a program sent to and received from one remote address within a minute, split by whether someone was at
/// the computer at the time (or whether that was known). Source of the Data Flow view.
/// </summary>
[Table("process_traffic_minutes")]
[Index(nameof(BucketStart), nameof(ProcessImageId), nameof(RemoteIp), nameof(Protocol), nameof(Presence), IsUnique = true)]
[Index(nameof(ProcessImageId), nameof(BucketStart))]
[Index(nameof(RemoteIp), nameof(BucketStart))]
public class ProcessTrafficMinute : Repository<ProcessTrafficMinute>
{
    public const int BucketSeconds = 60;

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("bucket_start")]
    public long BucketStart { get; set; }

    [Column("process_image_id")]
    public long ProcessImageId { get; set; }

    [Column("remote_ip")]
    [MaxLength(45)]
    public string RemoteIp { get; set; } = string.Empty;

    [Column("protocol")]
    [MaxLength(16)]
    public string Protocol { get; set; } = string.Empty;

    [Column("bytes_sent")]
    public long BytesSent { get; set; }

    [Column("bytes_received")]
    public long BytesReceived { get; set; }

    [Column("user_presence")]
    public PresenceState Presence { get; set; }

    public static async Task Record(DataContext dataContext, IReadOnlyCollection<ProcessTrafficCount> processTrafficCounts)
    {
        if (processTrafficCounts.Count == 0)
            return;

        var seenAt = DateTime.UtcNow;
        var imagePaths = processTrafficCounts.Select(count => count.ImagePath).Distinct().ToList();
        var processImageIds = await ProcessImage.GetOrCreateIds(dataContext, imagePaths, seenAt);

        const string commandText = """
            INSERT INTO process_traffic_minutes (bucket_start, process_image_id, remote_ip, protocol, bytes_sent, bytes_received, user_presence)
            VALUES ($bucketStart, $processImageId, $remoteIp, $protocol, $bytesSent, $bytesReceived, $presence)
            ON CONFLICT (bucket_start, process_image_id, remote_ip, protocol, user_presence) DO UPDATE SET
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_received = bytes_received + excluded.bytes_received;
            """;

        await ExecuteBatch(dataContext, commandText, processTrafficCounts, (parameters, processTrafficCount) =>
        {
            parameters.AddWithValue("$bucketStart", processTrafficCount.BucketStart);
            parameters.AddWithValue("$processImageId", processImageIds[processTrafficCount.ImagePath]);
            parameters.AddWithValue("$remoteIp", processTrafficCount.RemoteIp);
            parameters.AddWithValue("$protocol", processTrafficCount.Protocol);
            parameters.AddWithValue("$bytesSent", processTrafficCount.BytesSent);
            parameters.AddWithValue("$bytesReceived", processTrafficCount.BytesReceived);
            parameters.AddWithValue("$presence", (int)processTrafficCount.Presence);
        });
    }

    /// <summary>
    /// Away is only noticed after the idle threshold, so traffic between the last keyboard or mouse input and that
    /// moment was recorded as "here". Moves it to "away", merging into any away row for the same minute.
    /// </summary>
    public static async Task<int> RelabelAsAway(DataContext dataContext, long sinceUnixSeconds)
    {
        var bucketStart = sinceUnixSeconds - sinceUnixSeconds % BucketSeconds;
        var here = (int)PresenceState.Here;
        var away = (int)PresenceState.Away;

        await using var transaction = await dataContext.Database.BeginTransactionAsync();
        await dataContext.Database.ExecuteSqlInterpolatedAsync($"""
            INSERT INTO process_traffic_minutes (bucket_start, process_image_id, remote_ip, protocol, bytes_sent, bytes_received, user_presence)
            SELECT bucket_start, process_image_id, remote_ip, protocol, bytes_sent, bytes_received, {away}
            FROM process_traffic_minutes
            WHERE bucket_start >= {bucketStart} AND user_presence = {here}
            ON CONFLICT (bucket_start, process_image_id, remote_ip, protocol, user_presence) DO UPDATE SET
                bytes_sent = bytes_sent + excluded.bytes_sent,
                bytes_received = bytes_received + excluded.bytes_received;
            """);
        var moved = await dataContext.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM process_traffic_minutes WHERE bucket_start >= {bucketStart} AND user_presence = {here};");
        await transaction.CommitAsync();
        return moved;
    }

    public static async Task<List<ProcessTrafficSummary>> GetSummaries(DataContext dataContext, long sinceUnixSeconds, int count)
    {
        var summaries = await Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds)
            .GroupBy(record => record.ProcessImageId)
            .Select(group => new ProcessTrafficSummary
            {
                ProcessImageId = group.Key,
                BytesSent = group.Sum(record => record.BytesSent),
                BytesReceived = group.Sum(record => record.BytesReceived),
                AwayBytesSent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                AwayBytesReceived = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0),
                UnknownBytesSent = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesSent : 0),
                UnknownBytesReceived = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesReceived : 0),
                RemoteAddressCount = group.Select(record => record.RemoteIp).Distinct().Count()
            })
            .OrderByDescending(summary => summary.BytesSent)
            .Take(count)
            .ToListAsync();

        await AttachProcessImages(dataContext, summaries);
        return summaries;
    }

    public static async Task<List<ProcessTrafficSummary>> GetForAddress(DataContext dataContext, string remoteIp, long sinceUnixSeconds, int count)
    {
        var summaries = await Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds && record.RemoteIp == remoteIp)
            .GroupBy(record => record.ProcessImageId)
            .Select(group => new ProcessTrafficSummary
            {
                ProcessImageId = group.Key,
                BytesSent = group.Sum(record => record.BytesSent),
                BytesReceived = group.Sum(record => record.BytesReceived),
                AwayBytesSent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                AwayBytesReceived = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0),
                UnknownBytesSent = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesSent : 0),
                UnknownBytesReceived = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesReceived : 0),
                RemoteAddressCount = 1
            })
            .OrderByDescending(summary => summary.BytesSent)
            .Take(count)
            .ToListAsync();

        await AttachProcessImages(dataContext, summaries);
        return summaries;
    }

    public static async Task<List<ProcessTimelinePoint>> GetTimeline(DataContext dataContext, long sinceUnixSeconds, int stepSeconds, long? processImageId)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        if (processImageId.HasValue)
            records = records.Where(record => record.ProcessImageId == processImageId.Value);

        return await records
            .GroupBy(record => record.BucketStart / stepSeconds)
            .Select(group => new ProcessTimelinePoint
            {
                BucketStart = group.Key * stepSeconds,
                BytesSent = group.Sum(record => record.BytesSent),
                BytesReceived = group.Sum(record => record.BytesReceived),
                AwayBytesSent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                AwayBytesReceived = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0),
                UnknownBytesSent = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesSent : 0),
                UnknownBytesReceived = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesReceived : 0)
            })
            .OrderBy(point => point.BucketStart)
            .ToListAsync();
    }

    public static async Task<List<AddressSummary>> GetRemoteAddresses(DataContext dataContext, long processImageId, long sinceUnixSeconds, int count)
    {
        var addressSummaries = await Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds && record.ProcessImageId == processImageId)
            .GroupBy(record => record.RemoteIp)
            .Select(group => new AddressSummary
            {
                IpAddress = group.Key,
                BytesIn = group.Sum(record => record.BytesReceived),
                BytesOut = group.Sum(record => record.BytesSent)
            })
            .OrderByDescending(summary => summary.BytesOut)
            .Take(count)
            .ToListAsync();

        await IpAddressProfile.Enrich(dataContext, addressSummaries);
        return addressSummaries;
    }

    /// <summary>
    /// The programs that exchanged the most data with each of the given countries, for the country hover list.
    /// </summary>
    public static async Task<Dictionary<string, List<ProcessTrafficSummary>>> GetTopProgramsByCountry(
        DataContext dataContext, long sinceUnixSeconds, IReadOnlyCollection<string> countryCodes, int perCountry)
    {
        var profiles = dataContext.IpAddressProfiles.AsNoTracking()
            .Where(profile => profile.CountryCode != null && countryCodes.Contains(profile.CountryCode));
        var rows = await Query(dataContext)
            .Where(record => record.BucketStart >= sinceUnixSeconds)
            .Join(profiles, record => record.RemoteIp, profile => profile.IpAddress, (record, profile) => new
            {
                profile.CountryCode,
                record.ProcessImageId,
                record.BytesSent,
                record.BytesReceived,
                record.Presence
            })
            .GroupBy(row => new { row.CountryCode, row.ProcessImageId })
            .Select(group => new
            {
                group.Key.CountryCode,
                group.Key.ProcessImageId,
                BytesSent = group.Sum(row => row.BytesSent),
                BytesReceived = group.Sum(row => row.BytesReceived),
                AwayBytesSent = group.Sum(row => row.Presence == PresenceState.Away ? row.BytesSent : 0),
                AwayBytesReceived = group.Sum(row => row.Presence == PresenceState.Away ? row.BytesReceived : 0)
            })
            .ToListAsync();

        var topByCountry = rows
            .GroupBy(row => row.CountryCode!)
            .ToDictionary(
                group => group.Key,
                group => group
                    .OrderByDescending(row => row.BytesSent + row.BytesReceived)
                    .Take(perCountry)
                    .Select(row => new ProcessTrafficSummary
                    {
                        ProcessImageId = row.ProcessImageId,
                        BytesSent = row.BytesSent,
                        BytesReceived = row.BytesReceived,
                        AwayBytesSent = row.AwayBytesSent,
                        AwayBytesReceived = row.AwayBytesReceived
                    })
                    .ToList());

        var summaries = topByCountry.Values.SelectMany(list => list).ToList();
        var processImageIds = summaries.Select(summary => summary.ProcessImageId).Distinct().ToList();
        var processImagesById = (await ProcessImage.GetAll(dataContext, image => processImageIds.Contains(image.Id))).ToDictionary(image => image.Id);
        foreach (var summary in summaries)
            summary.ProcessImage = processImagesById.GetValueOrDefault(summary.ProcessImageId);

        return topByCountry;
    }

    /// <summary>
    /// Where programs sent data, one row per remote address, most sent first. Local-network addresses are left out
    /// unless asked for, before the top rows are taken, so a busy file share can't crowd out internet destinations.
    /// </summary>
    public static async Task<List<DestinationSummary>> GetDestinations(
        DataContext dataContext, long sinceUnixSeconds, int count, bool includeLocal, long? processImageId = null)
    {
        var records = Query(dataContext).Where(record => record.BucketStart >= sinceUnixSeconds);
        if (processImageId.HasValue)
            records = records.Where(record => record.ProcessImageId == processImageId.Value);

        var allDestinations = await records
            .GroupBy(record => record.RemoteIp)
            .Select(group => new DestinationSummary
            {
                IpAddress = group.Key,
                BytesSent = group.Sum(record => record.BytesSent),
                BytesReceived = group.Sum(record => record.BytesReceived),
                AwayBytesSent = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                AwayBytesReceived = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0),
                UnknownBytesSent = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesSent : 0),
                UnknownBytesReceived = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesReceived : 0),
                ProgramCount = group.Select(record => record.ProcessImageId).Distinct().Count()
            })
            .ToListAsync();

        var destinations = allDestinations
            .Where(destination => System.Net.IPAddress.TryParse(destination.IpAddress, out _))
            .Where(destination => includeLocal || !ResponseAction.IsPrivateAddress(destination.IpAddress))
            .OrderByDescending(destination => destination.BytesSent)
            .ThenByDescending(destination => destination.BytesReceived)
            .Take(count)
            .ToList();

        await DestinationSummary.Enrich(dataContext, destinations, sinceUnixSeconds);
        return destinations;
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, long cutoffUnixSeconds)
    {
        return await DeleteWhere(dataContext, record => record.BucketStart < cutoffUnixSeconds);
    }

    public static async Task AttachProcessImages(DataContext dataContext, List<ProcessTrafficSummary> summaries)
    {
        var processImageIds = summaries.Select(summary => summary.ProcessImageId).ToList();
        var processImages = await ProcessImage.GetAll(dataContext, processImage => processImageIds.Contains(processImage.Id));
        var processImagesById = processImages.ToDictionary(processImage => processImage.Id);

        // One query for every row: which programs are already blocked, so each row can offer Block or Unblock.
        var blocks = await ResponseAction.GetAll(dataContext, action => action.ActionType == ResponseActionType.BlockProgram
            && (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active));
        var blockIdsByPath = blocks
            .GroupBy(action => action.Target, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Id, StringComparer.OrdinalIgnoreCase);
        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);

        foreach (var summary in summaries)
        {
            summary.ProcessImage = processImagesById.GetValueOrDefault(summary.ProcessImageId);
            var imagePath = summary.ProcessImage?.ImagePath ?? string.Empty;
            summary.ActiveBlockId = blockIdsByPath.TryGetValue(imagePath, out var blockId) ? blockId : null;
            summary.IsAllowlisted = Path.IsPathRooted(imagePath) && responseSettings.IsAllowlistedProgram(imagePath);
            summary.CanRemoveFromAllowlist = summary.IsAllowlisted
                && ProtectedPrograms.ReasonNotBlockable(imagePath) == null
                && responseSettings.AllowlistedPrograms.Contains(imagePath, StringComparer.OrdinalIgnoreCase);
            summary.BlockRefusal = summary.IsAllowlisted ? "On the never-block allowlist." : ProtectedPrograms.ReasonNotBlockable(imagePath);
        }
    }
}

/// <summary>
/// Per-program counts produced by the sensor for one minute. Not persisted directly.
/// </summary>
public class ProcessTrafficCount
{
    public long BucketStart { get; set; }
    public string ImagePath { get; set; } = string.Empty;
    public string RemoteIp { get; set; } = string.Empty;
    public string Protocol { get; set; } = string.Empty;
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public PresenceState Presence { get; set; }
}

/// <summary>
/// Whether someone was at the computer when traffic happened. Unknown when no presence source could tell
/// (the presence agent isn't running in any session, for example).
/// </summary>
public enum PresenceState
{
    Here = 0,
    Away = 1,
    Unknown = 2
}

/// <summary>
/// Uploaded and downloaded bytes, each split into while someone was here, while away, and while it wasn't known.
/// </summary>
public class TrafficSplit
{
    public static TrafficSplit Sum(IEnumerable<TrafficSplit> parts)
    {
        var total = new TrafficSplit();
        foreach (var part in parts)
        {
            total.BytesSent += part.BytesSent;
            total.BytesReceived += part.BytesReceived;
            total.AwayBytesSent += part.AwayBytesSent;
            total.AwayBytesReceived += part.AwayBytesReceived;
            total.UnknownBytesSent += part.UnknownBytesSent;
            total.UnknownBytesReceived += part.UnknownBytesReceived;
        }

        return total;
    }

    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public long AwayBytesSent { get; set; }
    public long AwayBytesReceived { get; set; }
    public long UnknownBytesSent { get; set; }
    public long UnknownBytesReceived { get; set; }

    public long HereBytesSent => BytesSent - AwayBytesSent - UnknownBytesSent;
    public long HereBytesReceived => BytesReceived - AwayBytesReceived - UnknownBytesReceived;
    public long TotalBytes => BytesSent + BytesReceived;

    /// <summary>
    /// The part of the uploads that happened while nobody was at the computer.
    /// </summary>
    public double AwayShare => BytesSent == 0 ? 0 : (double)AwayBytesSent / BytesSent;
    public double UnknownShare => TotalBytes == 0 ? 0 : (double)(UnknownBytesSent + UnknownBytesReceived) / TotalBytes;
}

public class ProcessTrafficSummary : TrafficSplit
{
    public long ProcessImageId { get; set; }
    public int RemoteAddressCount { get; set; }
    public ProcessImage? ProcessImage { get; set; }

    /// <summary>
    /// The block in force for this program, if any.
    /// </summary>
    public long? ActiveBlockId { get; set; }

    /// <summary>
    /// Why this program can't be blocked from the table, or null when it can.
    /// </summary>
    public string? BlockRefusal { get; set; }

    /// <summary>
    /// The program's full path is on the never-block allowlist.
    /// </summary>
    public bool IsAllowlisted { get; set; }

    /// <summary>
    /// Allowed by the owner's own "Always allow", as opposed to ScoutWall's built-in protection for Windows itself.
    /// </summary>
    public bool CanRemoveFromAllowlist { get; set; }

    public string Name => ProcessImage?.DisplayName ?? $"Process {ProcessImageId}";
}

/// <summary>
/// Data programs exchanged with one remote address, with what is known about the address: its name, place,
/// network, the program that sent it the most, and whether it is blocked.
/// </summary>
public class DestinationSummary : TrafficSplit
{
    public string IpAddress { get; set; } = string.Empty;
    public int ProgramCount { get; set; }

    public IpAddressProfile? Profile { get; set; }

    /// <summary>
    /// The name programs used for the address: the latest DNS answer, else the TLS server name, else reverse DNS.
    /// </summary>
    public string? Hostname { get; set; }

    /// <summary>
    /// How many other names were seen for the same address. Shared hosting and CDNs serve many sites from one address.
    /// </summary>
    public int OtherNameCount { get; set; }

    public ProcessImage? TopProgram { get; set; }
    public long? ActiveBlockId { get; set; }
    public string? BlockRefusal { get; set; }

    public bool IsLocal => ResponseAction.IsPrivateAddress(IpAddress);

    public string LocationDisplay
    {
        get
        {
            if (IsLocal || Profile?.IsPrivate == true)
                return "Local network";

            if (Profile?.LookedUpAt == null && Profile?.CountryName == null)
                return "Looking up…";

            var region = string.Equals(Profile.Region, Profile.City, StringComparison.OrdinalIgnoreCase) ? null : Profile.Region;
            var parts = new[] { Profile.City, region, Profile.CountryName }.Where(part => !string.IsNullOrWhiteSpace(part));
            return string.Join(", ", parts) is { Length: > 0 } location ? location : "Unknown";
        }
    }

    /// <summary>
    /// Approximate coordinates for the tooltip. Addresses served from many places at once (anycast) only resolve to one of them.
    /// </summary>
    public string? CoordinatesDisplay => Profile is { Latitude: double latitude, Longitude: double longitude }
        ? $"{Math.Abs(latitude).ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)}°{(latitude >= 0 ? "N" : "S")}, "
          + $"{Math.Abs(longitude).ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)}°{(longitude >= 0 ? "E" : "W")} (approximate)"
        : null;

    public static async Task Enrich(DataContext dataContext, List<DestinationSummary> destinations, long sinceUnixSeconds)
    {
        if (destinations.Count == 0)
            return;

        var addresses = destinations.Select(destination => destination.IpAddress).ToList();
        var profiles = await IpAddressProfile.GetMany(dataContext, addresses);

        var dnsNames = (await DnsRecord.GetAll(dataContext, record => addresses.Contains(record.IpAddress)))
            .GroupBy(record => record.IpAddress)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(record => record.LastSeenAt).Select(record => record.Hostname).ToList());
        var serverNames = (await TlsSession.GetAll(dataContext, session => addresses.Contains(session.ServerIp) && session.ServerName != ""))
            .GroupBy(session => session.ServerIp)
            .ToDictionary(group => group.Key, group => group.OrderByDescending(session => session.LastSeenAt).Select(session => session.ServerName).ToList());

        // The program that sent each address the most.
        var programTotals = await dataContext.Set<ProcessTrafficMinute>().AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && addresses.Contains(record.RemoteIp))
            .GroupBy(record => new { record.RemoteIp, record.ProcessImageId })
            .Select(group => new { group.Key.RemoteIp, group.Key.ProcessImageId, Bytes = group.Sum(record => record.BytesSent + record.BytesReceived) })
            .ToListAsync();
        var topProgramIds = programTotals
            .GroupBy(row => row.RemoteIp)
            .ToDictionary(group => group.Key, group => group.MaxBy(row => row.Bytes)!.ProcessImageId);
        var programIds = topProgramIds.Values.Distinct().ToList();
        var programsById = (await ProcessImage.GetAll(dataContext, image => programIds.Contains(image.Id))).ToDictionary(image => image.Id);

        var blocks = await ResponseAction.GetAll(dataContext, action => action.ActionType == ResponseActionType.BlockAddress
            && (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active)
            && addresses.Contains(action.Target));
        var blockIds = blocks.GroupBy(action => action.Target).ToDictionary(group => group.Key, group => group.First().Id);

        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        var protectedAddresses = HostNetwork.ProtectedAddresses();

        foreach (var destination in destinations)
        {
            destination.Profile = profiles.GetValueOrDefault(destination.IpAddress);

            var names = dnsNames.GetValueOrDefault(destination.IpAddress) ?? [];
            var tlsNames = serverNames.GetValueOrDefault(destination.IpAddress) ?? [];
            destination.Hostname = names.FirstOrDefault() ?? tlsNames.FirstOrDefault() ?? destination.Profile?.ReverseDns;
            destination.OtherNameCount = Math.Max(0, names.Concat(tlsNames).Distinct(StringComparer.OrdinalIgnoreCase).Count() - 1);

            if (topProgramIds.TryGetValue(destination.IpAddress, out var programId))
                destination.TopProgram = programsById.GetValueOrDefault(programId);

            destination.ActiveBlockId = blockIds.TryGetValue(destination.IpAddress, out var blockId) ? blockId : null;
            destination.BlockRefusal = RefusalFor(destination.IpAddress, responseSettings, protectedAddresses);
        }
    }

    private static string? RefusalFor(string ipAddress, ResponseSettings responseSettings, HashSet<System.Net.IPAddress> protectedAddresses)
    {
        if (ResponseAction.IsPrivateAddress(ipAddress))
            return "Local addresses can't be blocked from here; it could cut this computer off its own network.";

        var address = System.Net.IPAddress.Parse(ipAddress);
        if (protectedAddresses.Contains(address))
            return "This is the computer's gateway or one of its DNS servers.";

        return responseSettings.AllowlistedAddresses.Any(entry => HostNetwork.RangeContains(entry, address))
            ? "On the never-block allowlist."
            : null;
    }
}

public class ProcessTimelinePoint : TrafficSplit
{
    public long BucketStart { get; set; }
}
