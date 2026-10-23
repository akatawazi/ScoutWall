using System.Net.Http.Json;
using System.Text.Json.Serialization;
using MaxMind.GeoIP2;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Enrichment;

/// <summary>
/// Looks up location, ISP and autonomous system for public addresses.
/// MaxMind GeoLite2 databases (offline, free with an account) are preferred; ip-api.com is a fallback that is
/// free for non-commercial use only and limited to 15 batch requests a minute.
/// </summary>
public class GeoIpResolver : IDisposable
{
    private const string IpApiBatchUrl = "http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,query";
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromSeconds(20) };

    private DatabaseReader? cityReader;
    private DatabaseReader? asnReader;
    private string? loadedCityPath;
    private string? loadedAsnPath;

    public bool HasSource(IntegrationSettings integrationSettings)
    {
        LoadDatabases(integrationSettings);
        return cityReader != null || asnReader != null || integrationSettings.UseIpApiFallback;
    }

    public async Task<List<IpAddressProfile>> Lookup(IntegrationSettings integrationSettings, List<string> ipAddresses, CancellationToken cancellationToken)
    {
        LoadDatabases(integrationSettings);
        var lookedUpProfiles = new List<IpAddressProfile>();
        var unresolvedAddresses = new List<string>();

        foreach (var ipAddress in ipAddresses)
        {
            var profile = LookupOffline(ipAddress);
            if (profile != null)
                lookedUpProfiles.Add(profile);
            else
                unresolvedAddresses.Add(ipAddress);
        }

        if (integrationSettings.UseIpApiFallback && unresolvedAddresses.Count > 0)
            lookedUpProfiles.AddRange(await LookupOnline(unresolvedAddresses, cancellationToken));

        return lookedUpProfiles;
    }

    public void Dispose()
    {
        cityReader?.Dispose();
        asnReader?.Dispose();
        GC.SuppressFinalize(this);
    }

    private void LoadDatabases(IntegrationSettings integrationSettings)
    {
        if (integrationSettings.GeoIpCityDatabasePath != loadedCityPath)
        {
            cityReader?.Dispose();
            cityReader = OpenDatabase(integrationSettings.GeoIpCityDatabasePath);
            loadedCityPath = integrationSettings.GeoIpCityDatabasePath;
        }

        if (integrationSettings.GeoIpAsnDatabasePath != loadedAsnPath)
        {
            asnReader?.Dispose();
            asnReader = OpenDatabase(integrationSettings.GeoIpAsnDatabasePath);
            loadedAsnPath = integrationSettings.GeoIpAsnDatabasePath;
        }
    }

    private static DatabaseReader? OpenDatabase(string? databasePath)
    {
        return !string.IsNullOrWhiteSpace(databasePath) && File.Exists(databasePath) ? new DatabaseReader(databasePath) : null;
    }

    private IpAddressProfile? LookupOffline(string ipAddress)
    {
        if (cityReader == null && asnReader == null)
            return null;

        var profile = new IpAddressProfile { IpAddress = ipAddress, LookupSource = "MaxMind", LookedUpAt = DateTime.UtcNow };
        var found = false;

        if (cityReader != null && cityReader.TryCity(ipAddress, out var cityResponse) && cityResponse != null)
        {
            profile.CountryCode = cityResponse.Country.IsoCode;
            profile.CountryName = cityResponse.Country.Name;
            profile.Region = cityResponse.MostSpecificSubdivision.Name;
            profile.City = cityResponse.City.Name;
            profile.Latitude = cityResponse.Location.Latitude;
            profile.Longitude = cityResponse.Location.Longitude;
            found = true;
        }

        if (asnReader != null && asnReader.TryAsn(ipAddress, out var asnResponse) && asnResponse != null)
        {
            profile.AutonomousSystemNumber = asnResponse.AutonomousSystemNumber;
            profile.AutonomousSystemOrganization = asnResponse.AutonomousSystemOrganization;
            profile.Isp = asnResponse.AutonomousSystemOrganization;
            found = true;
        }

        return found ? profile : null;
    }

    private static async Task<List<IpAddressProfile>> LookupOnline(List<string> ipAddresses, CancellationToken cancellationToken)
    {
        using var response = await HttpClient.PostAsJsonAsync(IpApiBatchUrl, ipAddresses.Take(100), cancellationToken);
        response.EnsureSuccessStatusCode();
        var ipApiResults = await response.Content.ReadFromJsonAsync<List<IpApiResult>>(cancellationToken) ?? [];
        return ipApiResults.Select(ToProfile).ToList();
    }

    private static IpAddressProfile ToProfile(IpApiResult ipApiResult)
    {
        var profile = new IpAddressProfile
        {
            IpAddress = ipApiResult.Query,
            LookupSource = "ip-api.com",
            LookedUpAt = DateTime.UtcNow
        };

        if (ipApiResult.Status != "success")
        {
            profile.LookupError = ipApiResult.Message ?? "Lookup failed";
            return profile;
        }

        profile.CountryCode = ipApiResult.CountryCode;
        profile.CountryName = ipApiResult.Country;
        profile.Region = ipApiResult.RegionName;
        profile.City = ipApiResult.City;
        profile.Latitude = ipApiResult.Lat;
        profile.Longitude = ipApiResult.Lon;
        profile.Isp = ipApiResult.Isp;
        profile.Organization = ipApiResult.Org;
        profile.ReverseDns = string.IsNullOrWhiteSpace(ipApiResult.Reverse) ? null : ipApiResult.Reverse;
        (profile.AutonomousSystemNumber, profile.AutonomousSystemOrganization) = ParseAutonomousSystem(ipApiResult.As);
        return profile;
    }

    /// <summary>
    /// ip-api returns the AS as "AS15169 Google LLC".
    /// </summary>
    private static (long? Number, string? Organization) ParseAutonomousSystem(string? autonomousSystem)
    {
        if (string.IsNullOrWhiteSpace(autonomousSystem) || !autonomousSystem.StartsWith("AS", StringComparison.Ordinal))
            return (null, autonomousSystem);

        var parts = autonomousSystem.Split(' ', 2);
        var number = long.TryParse(parts[0][2..], out var parsedNumber) ? parsedNumber : (long?)null;
        return (number, parts.Length > 1 ? parts[1] : null);
    }

    private class IpApiResult
    {
        [JsonPropertyName("query")] public string Query { get; set; } = string.Empty;
        [JsonPropertyName("status")] public string? Status { get; set; }
        [JsonPropertyName("message")] public string? Message { get; set; }
        [JsonPropertyName("country")] public string? Country { get; set; }
        [JsonPropertyName("countryCode")] public string? CountryCode { get; set; }
        [JsonPropertyName("regionName")] public string? RegionName { get; set; }
        [JsonPropertyName("city")] public string? City { get; set; }
        [JsonPropertyName("lat")] public double? Lat { get; set; }
        [JsonPropertyName("lon")] public double? Lon { get; set; }
        [JsonPropertyName("isp")] public string? Isp { get; set; }
        [JsonPropertyName("org")] public string? Org { get; set; }
        [JsonPropertyName("as")] public string? As { get; set; }
        [JsonPropertyName("reverse")] public string? Reverse { get; set; }
    }
}
