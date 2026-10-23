using System.Globalization;
using ScoutWall.Data.Models;

namespace ScoutWall.Models;

/// <summary>
/// Places traffic destinations on wwwroot/img/world-map.svg. The basemap was drawn with the same Natural Earth
/// projection and scale, so a latitude and longitude projected here lands on the right spot of the picture.
/// </summary>
public static class WorldMap
{
    public const double Width = 1000;
    public const double Height = 520;
    private const double HalfWidthRadians = 2.735384723480633;
    private const double HalfHeightRadians = 1.422390506730596;
    private const double Scale = Width / (2 * HalfWidthRadians);
    private const double SmallestRadius = 3;
    private const double LargestRadius = 18;

    public record MapDot(string X, string Y, string Radius, string Label, LocationSummary Location);

    public static string ViewBox => $"0 0 {Width} {Height}";

    /// <summary>
    /// Dots sized by area for the data moved there, largest drawn first so smaller dots stay on top and clickable.
    /// </summary>
    public static List<MapDot> Dots(IEnumerable<LocationSummary> locations)
    {
        var locationList = locations.Where(location => location.TotalBytes > 0).ToList();
        if (locationList.Count == 0)
            return [];

        var largestBytes = Math.Sqrt(locationList.Max(location => location.TotalBytes));
        return locationList
            .OrderByDescending(location => location.TotalBytes)
            .Select(location =>
            {
                var (x, y) = Project(location.Longitude, location.Latitude);
                var radius = SmallestRadius + (LargestRadius - SmallestRadius) * Math.Sqrt(location.TotalBytes) / largestBytes;
                var label = $"{location.PlaceName}: {Display.Bytes(location.BytesOut)} sent, {Display.Bytes(location.BytesIn)} received, "
                    + (location.RemoteAddressCount == 1 ? "1 address" : $"{location.RemoteAddressCount} addresses");
                return new MapDot(Format(x), Format(y), Format(radius), label, location);
            })
            .ToList();
    }

    public static (double X, double Y) Project(double longitude, double latitude)
    {
        var lambda = Math.Clamp(longitude, -180, 180) * Math.PI / 180;
        var phi = Math.Clamp(latitude, -90, 90) * Math.PI / 180;
        var phi2 = phi * phi;
        var phi4 = phi2 * phi2;
        var x = lambda * (0.870700 - 0.131979 * phi2 - 0.013791 * phi4 + phi4 * phi4 * phi2 * (0.003971 - 0.001529 * phi2));
        var y = phi * (1.007226 + phi2 * (0.015085 + phi4 * (-0.044475 + 0.028874 * phi2 - 0.005916 * phi4)));
        return ((x + HalfWidthRadians) * Scale, (HalfHeightRadians - y) * Scale);
    }

    private static string Format(double value)
    {
        return value.ToString("0.#", CultureInfo.InvariantCulture);
    }
}
