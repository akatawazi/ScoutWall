using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Html;
using ScoutWall.Data.Models;

namespace ScoutWall.Models;

/// <summary>
/// Formatting used by the views, so the views themselves stay free of logic.
/// </summary>
public static class Display
{
    private static readonly string[] ByteUnits = ["B", "KB", "MB", "GB", "TB", "PB"];

    public static string Bytes(long bytes)
    {
        double value = bytes;
        var unitIndex = 0;
        while (value >= 1024 && unitIndex < ByteUnits.Length - 1)
        {
            value /= 1024;
            unitIndex++;
        }

        var format = unitIndex == 0 || value >= 100 ? "0" : "0.0";
        return $"{value.ToString(format, CultureInfo.InvariantCulture)} {ByteUnits[unitIndex]}";
    }

    public static string BitRate(double bitsPerSecond)
    {
        string[] units = ["bps", "Kbps", "Mbps", "Gbps"];
        var unitIndex = 0;
        while (bitsPerSecond >= 1000 && unitIndex < units.Length - 1)
        {
            bitsPerSecond /= 1000;
            unitIndex++;
        }

        return $"{bitsPerSecond.ToString("0.#", CultureInfo.InvariantCulture)} {units[unitIndex]}";
    }

    public static string Number(long value)
    {
        return value.ToString("N0", CultureInfo.InvariantCulture);
    }

    public static string Percent(double fraction)
    {
        return fraction.ToString("0%", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// A length of time in plain words: "45 min", "3 h 20 min", "2 days 4 h".
    /// </summary>
    public static string Duration(TimeSpan duration)
    {
        if (duration.TotalMinutes < 1)
            return "under a minute";
        if (duration.TotalHours < 1)
            return $"{(int)duration.TotalMinutes} min";
        if (duration.TotalDays < 1)
            return duration.Minutes == 0 ? $"{(int)duration.TotalHours} h" : $"{(int)duration.TotalHours} h {duration.Minutes} min";

        var days = (int)duration.TotalDays;
        return $"{days} {(days == 1 ? "day" : "days")}{(duration.Hours > 0 ? $" {duration.Hours} h" : "")}";
    }

    /// <summary>
    /// A UTC time as ISO text, for data attributes that site.js turns into local time.
    /// </summary>
    public static string IsoTime(DateTime utcTime)
    {
        return DateTime.SpecifyKind(utcTime, DateTimeKind.Utc).ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
    }

    /// <summary>
    /// A UTC time that site.js rewrites into the viewer's local time zone.
    /// </summary>
    public static IHtmlContent Time(DateTime? utcTime)
    {
        if (!utcTime.HasValue)
            return new HtmlString("<span class=\"text-body-secondary\">-</span>");

        var utc = DateTime.SpecifyKind(utcTime.Value, DateTimeKind.Utc);
        var isoText = utc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
        var fallbackText = utc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC";
        return new HtmlString($"<time datetime=\"{isoText}\" data-local-time>{fallbackText}</time>");
    }

    /// <summary>
    /// Assistant replies with light formatting: the text is HTML-encoded first, then **bold** becomes strong text.
    /// Nothing else from the model is ever rendered as markup.
    /// </summary>
    public static IHtmlContent ChatText(string text)
    {
        var encoded = System.Net.WebUtility.HtmlEncode(text);
        var formatted = System.Text.RegularExpressions.Regex.Replace(encoded, @"\*\*(.+?)\*\*", "<strong>$1</strong>");
        return new HtmlString(formatted);
    }

    public static string Direction(TrafficDirection direction)
    {
        return direction switch
        {
            TrafficDirection.Inbound => "Incoming",
            TrafficDirection.Outbound => "Outgoing",
            TrafficDirection.Internal => "Internal",
            _ => "Passing through"
        };
    }

    public static string EventCategory(SystemEventCategory category)
    {
        return category switch
        {
            SystemEventCategory.Security => "Security",
            SystemEventCategory.Defender => "Antivirus",
            SystemEventCategory.Service => "Service",
            SystemEventCategory.Account => "Accounts",
            SystemEventCategory.ScheduledTask => "Scheduled task",
            SystemEventCategory.Stability => "Restart",
            SystemEventCategory.Disk => "Disk",
            _ => "App crash"
        };
    }

    public static string SeverityIcon(AlertSeverity severity)
    {
        return severity switch
        {
            AlertSeverity.Critical => "⛔",
            AlertSeverity.High => "▲",
            AlertSeverity.Medium => "◆",
            _ => "●"
        };
    }

    public static string Truncate(string? text, int maximumLength)
    {
        if (string.IsNullOrEmpty(text) || text.Length <= maximumLength)
            return text ?? string.Empty;

        return text[..(maximumLength - 1)] + "…";
    }

    /// <summary>
    /// Serializes chart data for a non-executable &lt;script type="application/json"&gt; block. The encoder
    /// escapes &lt;, &gt; and &amp; so attacker-controlled labels such as hostnames cannot break out of the tag.
    /// </summary>
    public static IHtmlContent ChartData(object chartData)
    {
        var jsonOptions = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.Default,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        return new HtmlString(JsonSerializer.Serialize(chartData, jsonOptions));
    }
}
