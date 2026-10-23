using ScoutWall.Data.Models;

namespace ScoutWall.Models;

/// <summary>
/// The chart payloads read by site.js. Series carry a palette slot, never a raw colour, so light and dark
/// themes stay in the stylesheet.
/// </summary>
public record ChartSeries(string Label, IEnumerable<long> Values, int Slot);

public record ChartData(string Type, IEnumerable<string> Labels, IEnumerable<ChartSeries> Series, bool Stacked, bool Horizontal, bool LabelsAreTimes, string Unit);

public static class Charts
{
    public static ChartData TrafficTimeline(IEnumerable<TrafficTimelinePoint> timelinePoints)
    {
        var points = timelinePoints.ToList();
        return new ChartData(
            "line",
            points.Select(point => point.BucketStart.ToString()),
            [
                new ChartSeries("Incoming", points.Select(point => point.BytesIn), 1),
                new ChartSeries("Outgoing", points.Select(point => point.BytesOut), 2)
            ],
            Stacked: false,
            Horizontal: false,
            LabelsAreTimes: true,
            Unit: "bytes");
    }

    /// <summary>
    /// Uploads over time, stacked by whether someone was at the computer. Colours mean the same thing in the
    /// upload and download charts: here, away, and unknown (shown only when there is any).
    /// </summary>
    public static ChartData UploadTimeline(IEnumerable<ProcessTimelinePoint> timelinePoints)
    {
        var points = timelinePoints.ToList();
        return PresenceTimeline(points, "Uploaded",
            points.Select(point => point.HereBytesSent), points.Select(point => point.AwayBytesSent), points.Select(point => point.UnknownBytesSent));
    }

    public static ChartData DownloadTimeline(IEnumerable<ProcessTimelinePoint> timelinePoints)
    {
        var points = timelinePoints.ToList();
        return PresenceTimeline(points, "Downloaded",
            points.Select(point => point.HereBytesReceived), points.Select(point => point.AwayBytesReceived), points.Select(point => point.UnknownBytesReceived));
    }

    private static ChartData PresenceTimeline(List<ProcessTimelinePoint> points, string verb, IEnumerable<long> here, IEnumerable<long> away, IEnumerable<long> unknown)
    {
        var series = new List<ChartSeries>
        {
            new($"{verb} while you were here", here, 1),
            new($"{verb} while you were away", away, 2)
        };
        var unknownValues = unknown.ToList();
        if (unknownValues.Any(value => value > 0))
            series.Add(new($"{verb}, presence unknown", unknownValues, 0));

        return new ChartData(
            "bar",
            points.Select(point => point.BucketStart.ToString()),
            series,
            Stacked: true,
            Horizontal: false,
            LabelsAreTimes: true,
            Unit: "bytes");
    }

    /// <summary>
    /// One disk's reads and writes over time.
    /// </summary>
    public static ChartData DiskTimeline(IEnumerable<DiskIoPoint> diskPoints)
    {
        var points = diskPoints.ToList();
        return new ChartData(
            "line",
            points.Select(point => point.BucketStart.ToString()),
            [
                new ChartSeries("Read", points.Select(point => point.ReadBytes), 1),
                new ChartSeries("Written", points.Select(point => point.WriteBytes), 2)
            ],
            Stacked: false,
            Horizontal: false,
            LabelsAreTimes: true,
            Unit: "bytes");
    }

    public static ChartData ProcessorUse(IEnumerable<SystemResourcePoint> timelinePoints)
    {
        var points = timelinePoints.ToList();
        return new ChartData(
            "line",
            points.Select(point => point.BucketStart.ToString()),
            [new ChartSeries("Processor use", points.Select(point => (long)Math.Round(point.CpuPercent)), 1)],
            Stacked: false,
            Horizontal: false,
            LabelsAreTimes: true,
            Unit: "percent");
    }

    public static ChartData MemoryUse(IEnumerable<SystemResourcePoint> timelinePoints)
    {
        var points = timelinePoints.ToList();
        return new ChartData(
            "line",
            points.Select(point => point.BucketStart.ToString()),
            [new ChartSeries("Memory in use", points.Select(point => point.MemoryUsedBytes), 2)],
            Stacked: false,
            Horizontal: false,
            LabelsAreTimes: true,
            Unit: "bytes");
    }

    public static ChartData Countries(IEnumerable<CountrySummary> countrySummaries)
    {
        var countries = countrySummaries.ToList();
        return new ChartData(
            "bar",
            countries.Select(country => country.CountryName),
            [new ChartSeries("Traffic", countries.Select(country => country.TotalBytes), 1)],
            Stacked: false,
            Horizontal: true,
            LabelsAreTimes: false,
            Unit: "bytes");
    }
}
