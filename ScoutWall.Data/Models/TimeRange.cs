namespace ScoutWall.Data.Models;

/// <summary>
/// A reporting window selectable in the UI. Decides chart granularity and which traffic table to read.
/// </summary>
public class TimeRange
{
    public const string OneHour = "1h";
    public const string SixHours = "6h";
    public const string OneDay = "24h";
    public const string SevenDays = "7d";
    public const string ThirtyDays = "30d";

    public static readonly IReadOnlyList<TimeRange> All =
    [
        new(OneHour, "Last hour", TimeSpan.FromHours(1), 60),
        new(SixHours, "Last 6 hours", TimeSpan.FromHours(6), 300),
        new(OneDay, "Last 24 hours", TimeSpan.FromHours(24), 900),
        new(SevenDays, "Last 7 days", TimeSpan.FromDays(7), 3600),
        new(ThirtyDays, "Last 30 days", TimeSpan.FromDays(30), 6 * 3600)
    ];

    private TimeRange(string key, string label, TimeSpan duration, int stepSeconds)
    {
        Key = key;
        Label = label;
        Duration = duration;
        StepSeconds = stepSeconds;
    }

    public string Key { get; }
    public string Label { get; }
    public TimeSpan Duration { get; }
    public int StepSeconds { get; }

    /// <summary>
    /// Minute rows are kept for a short period only; longer windows read the hourly rollup.
    /// </summary>
    public bool UsesHourlyData => Duration > TimeSpan.FromHours(24);

    public long SinceUnixSeconds
    {
        get
        {
            var since = DateTimeOffset.UtcNow.Subtract(Duration).ToUnixTimeSeconds();
            return since - since % StepSeconds;
        }
    }

    public static TimeRange Parse(string? key, string defaultKey = OneDay)
    {
        return All.FirstOrDefault(timeRange => timeRange.Key == key)
            ?? All.First(timeRange => timeRange.Key == defaultKey);
    }
}
