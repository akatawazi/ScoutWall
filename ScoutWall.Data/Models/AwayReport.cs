using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One program sending to one destination while nobody was at the computer.
/// </summary>
public class AwayPair
{
    public ProcessTrafficSummary Program { get; set; } = new();
    public DestinationSummary Destination { get; set; } = new();
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
}

/// <summary>
/// One time the owner was away, with what left the computer during it.
/// </summary>
public class AwayPeriodSummary
{
    public PresencePeriod Period { get; set; } = new();
    public long BytesSent { get; set; }
    public long BytesReceived { get; set; }
    public List<AwayPair> TopPairs { get; set; } = [];
}

/// <summary>
/// A slice of the presence strip. State is null where nothing was recorded (sensor stopped or computer asleep).
/// </summary>
public record PresenceSegment(PresenceState? State, DateTime Start, DateTime End, double LeftPercent, double WidthPercent)
{
    public TimeSpan Duration => End - Start;
}

/// <summary>
/// Where data went while the owner was away: the presence history for the range, the program and destination
/// pairs that uploaded the most while away, and each recent away period with its own top uploaders.
/// </summary>
public class AwayReport
{
    private const int PairCount = 15;
    private const int PeriodCount = 10;
    private const int PairsPerPeriod = 5;

    public DateTime Since { get; set; }
    public DateTime Until { get; set; }
    public List<PresenceSegment> Segments { get; set; } = [];
    public List<AwayPair> Pairs { get; set; } = [];
    public List<AwayPeriodSummary> Periods { get; set; } = [];

    public bool HasHistory => Segments.Any(segment => segment.State != null);
    public TimeSpan AwayTime => Segments.Where(segment => segment.State == PresenceState.Away).Aggregate(TimeSpan.Zero, (total, segment) => total + segment.Duration);
    public TimeSpan UnknownTime => Segments.Where(segment => segment.State == PresenceState.Unknown).Aggregate(TimeSpan.Zero, (total, segment) => total + segment.Duration);
    public TimeSpan RecordedTime => Segments.Where(segment => segment.State != null).Aggregate(TimeSpan.Zero, (total, segment) => total + segment.Duration);

    public static async Task<AwayReport> Build(DataContext dataContext, long sinceUnixSeconds)
    {
        var since = DateTimeOffset.FromUnixTimeSeconds(sinceUnixSeconds).UtcDateTime;
        var until = DateTime.UtcNow;
        var periods = await PresencePeriod.GetOverlapping(dataContext, since, until);
        var awayReport = new AwayReport { Since = since, Until = until, Segments = BuildSegments(periods, since, until) };

        var awayRecords = dataContext.ProcessTrafficMinutes.AsNoTracking()
            .Where(record => record.BucketStart >= sinceUnixSeconds && record.Presence == PresenceState.Away);

        var topPairs = (await awayRecords
                .GroupBy(record => new { record.ProcessImageId, record.RemoteIp })
                .Select(group => new
                {
                    group.Key.ProcessImageId,
                    group.Key.RemoteIp,
                    BytesSent = group.Sum(record => record.BytesSent),
                    BytesReceived = group.Sum(record => record.BytesReceived)
                })
                .OrderByDescending(pair => pair.BytesSent)
                .Take(PairCount * 10)
                .ToListAsync())
            .Where(pair => IsInternet(pair.RemoteIp))
            .Take(PairCount)
            .Select(pair => new PairKey(pair.ProcessImageId, pair.RemoteIp, pair.BytesSent, pair.BytesReceived))
            .ToList();

        // One query for the rows of every listed away period, split up by period in memory.
        var recentAwayPeriods = periods.Where(period => period.State == PresenceState.Away).OrderByDescending(period => period.StartedAt).Take(PeriodCount).ToList();
        var periodRows = new List<(long BucketStart, long ProcessImageId, string RemoteIp, long BytesSent, long BytesReceived)>();
        if (recentAwayPeriods.Count > 0)
        {
            var earliest = Math.Max(sinceUnixSeconds, new DateTimeOffset(recentAwayPeriods.Min(period => period.StartedAt)).ToUnixTimeSeconds());
            earliest -= earliest % ProcessTrafficMinute.BucketSeconds;
            periodRows = (await dataContext.ProcessTrafficMinutes.AsNoTracking()
                    .Where(record => record.BucketStart >= earliest && record.Presence == PresenceState.Away)
                    .Select(record => new { record.BucketStart, record.ProcessImageId, record.RemoteIp, record.BytesSent, record.BytesReceived })
                    .ToListAsync())
                .Select(row => (row.BucketStart, row.ProcessImageId, row.RemoteIp, row.BytesSent, row.BytesReceived))
                .ToList();
        }

        var periodSummaries = recentAwayPeriods.Select(period =>
        {
            var startBucket = new DateTimeOffset(period.StartedAt).ToUnixTimeSeconds();
            startBucket -= startBucket % ProcessTrafficMinute.BucketSeconds;
            var endUnix = new DateTimeOffset(period.EffectiveEnd).ToUnixTimeSeconds();
            var rows = periodRows.Where(row => row.BucketStart >= startBucket && row.BucketStart <= endUnix && IsInternet(row.RemoteIp)).ToList();
            return (Period: period, Rows: rows, Pairs: rows
                .GroupBy(row => (row.ProcessImageId, row.RemoteIp))
                .Select(group => new PairKey(group.Key.ProcessImageId, group.Key.RemoteIp, group.Sum(row => row.BytesSent), group.Sum(row => row.BytesReceived)))
                .Where(pair => pair.BytesSent + pair.BytesReceived > 0)
                .OrderByDescending(pair => pair.BytesSent)
                .Take(PairsPerPeriod)
                .ToList());
        }).ToList();

        // Look up every program and destination shown, once.
        var allPairs = topPairs.Concat(periodSummaries.SelectMany(summary => summary.Pairs)).ToList();
        var programs = allPairs.Select(pair => pair.ProcessImageId).Distinct().Select(id => new ProcessTrafficSummary { ProcessImageId = id }).ToList();
        await ProcessTrafficMinute.AttachProcessImages(dataContext, programs);
        var destinations = allPairs.Select(pair => pair.RemoteIp).Distinct().Select(ip => new DestinationSummary { IpAddress = ip }).ToList();
        await DestinationSummary.Enrich(dataContext, destinations, sinceUnixSeconds);
        var programsById = programs.ToDictionary(program => program.ProcessImageId);
        var destinationsByIp = destinations.ToDictionary(destination => destination.IpAddress);

        AwayPair ToPair(PairKey key) => new()
        {
            Program = programsById[key.ProcessImageId],
            Destination = destinationsByIp[key.RemoteIp],
            BytesSent = key.BytesSent,
            BytesReceived = key.BytesReceived
        };

        awayReport.Pairs = topPairs.Select(ToPair).ToList();
        awayReport.Periods = periodSummaries.Select(summary => new AwayPeriodSummary
        {
            Period = summary.Period,
            BytesSent = summary.Rows.Sum(row => row.BytesSent),
            BytesReceived = summary.Rows.Sum(row => row.BytesReceived),
            TopPairs = summary.Pairs.Select(ToPair).ToList()
        }).ToList();
        return awayReport;
    }

    private static List<PresenceSegment> BuildSegments(List<PresencePeriod> periods, DateTime since, DateTime until)
    {
        var totalSeconds = Math.Max(1, (until - since).TotalSeconds);
        var segments = new List<PresenceSegment>();
        var cursor = since;

        void Add(PresenceState? state, DateTime start, DateTime end)
        {
            if (end <= start)
                return;

            segments.Add(new PresenceSegment(state, start, end, (start - since).TotalSeconds * 100 / totalSeconds, (end - start).TotalSeconds * 100 / totalSeconds));
        }

        foreach (var period in periods)
        {
            var start = period.StartedAt < since ? since : period.StartedAt;
            var end = period.IsOpen ? until : (period.EffectiveEnd > until ? until : period.EffectiveEnd);
            if (start < cursor)
                start = cursor;

            Add(null, cursor, start);
            Add(period.State, start, end);
            if (end > cursor)
                cursor = end;
        }

        Add(null, cursor, until);
        return segments;
    }

    /// <summary>
    /// Only data that left the local network counts here; device discovery and file shares are left out.
    /// </summary>
    private static bool IsInternet(string ipAddress)
    {
        return System.Net.IPAddress.TryParse(ipAddress, out _) && !ResponseAction.IsPrivateAddress(ipAddress);
    }

    private record PairKey(long ProcessImageId, string RemoteIp, long BytesSent, long BytesReceived);
}
