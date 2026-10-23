namespace ScoutWall.Data.Models;

/// <summary>
/// Traffic figures for a time range, read from the minute or hour table depending on the range length.
/// </summary>
public class TrafficReport
{
    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public TrafficTotals Totals { get; set; } = new();
    public List<TrafficTimelinePoint> Timeline { get; set; } = [];
    public List<AddressSummary> TopSources { get; set; } = [];
    public List<AddressSummary> TopDestinations { get; set; } = [];
    public List<AddressSummary> TopLocalAddresses { get; set; } = [];
    public List<ServiceSummary> TopServices { get; set; } = [];
    public List<CountrySummary> TopCountries { get; set; } = [];

    public static async Task<TrafficReport> Build(DataContext dataContext, TimeRange range, int count)
    {
        var trafficReport = range.UsesHourlyData
            ? await BuildFrom<TrafficHour>(dataContext, range, count)
            : await BuildFrom<TrafficMinute>(dataContext, range, count);

        await IpAddressProfile.Enrich(dataContext, trafficReport.TopSources);
        await IpAddressProfile.Enrich(dataContext, trafficReport.TopDestinations);
        await IpAddressProfile.Enrich(dataContext, trafficReport.TopLocalAddresses);
        return trafficReport;
    }

    private static async Task<TrafficReport> BuildFrom<T>(DataContext dataContext, TimeRange range, int count) where T : TrafficRecord<T>
    {
        var since = range.SinceUnixSeconds;
        return new TrafficReport
        {
            Range = range,
            Totals = await TrafficRecord<T>.GetTotals(dataContext, since),
            Timeline = await TrafficRecord<T>.GetTimeline(dataContext, since, range.StepSeconds),
            TopSources = await TrafficRecord<T>.GetTopRemoteAddresses(dataContext, since, count, orderByIncoming: true),
            TopDestinations = await TrafficRecord<T>.GetTopRemoteAddresses(dataContext, since, count, orderByIncoming: false),
            TopLocalAddresses = await TrafficRecord<T>.GetTopLocalAddresses(dataContext, since, count),
            TopServices = await TrafficRecord<T>.GetTopServices(dataContext, since, count),
            TopCountries = await TrafficRecord<T>.GetTopCountries(dataContext, since, count)
        };
    }
}

public class DashboardReport
{
    public TrafficReport Traffic { get; set; } = new();
    public List<Alert> RecentAlerts { get; set; } = [];
    public int OpenAlertCount { get; set; }
    public Dictionary<AlertSeverity, int> SeverityCounts { get; set; } = [];
    public List<SensorStatus> Sensors { get; set; } = [];
    public List<ProcessTrafficSummary> TopPrograms { get; set; } = [];
    public int ActiveResponseCount { get; set; }
    public ResponseSettings Response { get; set; } = new();
    public List<AnalystAssessment> AnalystFindings { get; set; } = [];
    public bool AnalystReady { get; set; }
    public LearningPeriod LearningPeriod { get; set; } = new(DateTime.UtcNow, 24);

    public static async Task<DashboardReport> Build(DataContext dataContext, TimeRange range)
    {
        var since = DateTime.UtcNow.Subtract(range.Duration);
        return new DashboardReport
        {
            Traffic = await TrafficReport.Build(dataContext, range, 10),
            RecentAlerts = await Alert.GetRecent(dataContext, 10),
            OpenAlertCount = await Alert.CountOpen(dataContext),
            SeverityCounts = await Alert.GetSeverityCounts(dataContext, since),
            Sensors = await SensorStatus.GetAll(dataContext),
            TopPrograms = await ProcessTrafficMinute.GetSummaries(dataContext, range.SinceUnixSeconds, 8),
            ActiveResponseCount = await ResponseAction.CountActive(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            AnalystFindings = await AnalystAssessment.GetOpenFindings(dataContext, 10),
            AnalystReady = (await Setting.Load<AnalystSettings>(dataContext)).IsReady,
            LearningPeriod = await LearningPeriod.Load(dataContext)
        };
    }
}

public class IpAddressReport
{
    public IpAddressProfile Profile { get; set; } = new();
    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public TrafficTotals Totals { get; set; } = new();
    public List<TrafficTimelinePoint> Timeline { get; set; } = [];
    public List<ServiceSummary> Services { get; set; } = [];
    public List<AddressSummary> Peers { get; set; } = [];
    public List<DnsRecord> Hostnames { get; set; } = [];
    public List<Alert> Alerts { get; set; } = [];
    public List<TlsSession> TlsSessions { get; set; } = [];
    public List<DecryptedRequest> DecryptedRequests { get; set; } = [];
    public List<ProcessTrafficSummary> Programs { get; set; } = [];
    public List<ResponseAction> ResponseActions { get; set; } = [];

    public static async Task<IpAddressReport> Build(DataContext dataContext, string ipAddress, TimeRange range)
    {
        var ipAddressReport = range.UsesHourlyData
            ? await BuildFrom<TrafficHour>(dataContext, ipAddress, range)
            : await BuildFrom<TrafficMinute>(dataContext, ipAddress, range);

        ipAddressReport.Profile = await IpAddressProfile.Get(dataContext, profile => profile.IpAddress == ipAddress)
            ?? new IpAddressProfile { IpAddress = ipAddress };
        ipAddressReport.Hostnames = await DnsRecord.GetForAddress(dataContext, ipAddress, 20);
        ipAddressReport.Alerts = await Alert.GetForAddress(dataContext, ipAddress, 50);
        ipAddressReport.TlsSessions = await TlsSession.GetForAddress(dataContext, ipAddress, 50);
        ipAddressReport.DecryptedRequests = await DecryptedRequest.GetForAddress(dataContext, ipAddress, 50);
        ipAddressReport.Programs = await ProcessTrafficMinute.GetForAddress(dataContext, ipAddress, range.SinceUnixSeconds, 20);
        ipAddressReport.ResponseActions = await ResponseAction.GetAll(dataContext, action => action.Target == ipAddress);
        await IpAddressProfile.Enrich(dataContext, ipAddressReport.Peers);
        return ipAddressReport;
    }

    private static async Task<IpAddressReport> BuildFrom<T>(DataContext dataContext, string ipAddress, TimeRange range) where T : TrafficRecord<T>
    {
        var since = range.SinceUnixSeconds;
        return new IpAddressReport
        {
            Range = range,
            Totals = await TrafficRecord<T>.GetTotals(dataContext, since, ipAddress),
            Timeline = await TrafficRecord<T>.GetTimeline(dataContext, since, range.StepSeconds, ipAddress),
            Services = await TrafficRecord<T>.GetTopServices(dataContext, since, 20, ipAddress),
            Peers = await TrafficRecord<T>.GetPeers(dataContext, since, ipAddress, 20)
        };
    }
}

public class DecryptionReport
{
    public string? Search { get; set; }
    public bool DecryptionEnabled { get; set; }
    public string? KeyLogFilePath { get; set; }
    public List<TlsSession> TlsSessions { get; set; } = [];
    public List<DecryptedRequest> DecryptedRequests { get; set; } = [];

    public static async Task<DecryptionReport> Build(DataContext dataContext, string? search)
    {
        var integrationSettings = await Setting.Load<IntegrationSettings>(dataContext);
        return new DecryptionReport
        {
            Search = search,
            DecryptionEnabled = integrationSettings.DecryptionEnabled,
            KeyLogFilePath = integrationSettings.KeyLogFilePath,
            TlsSessions = await TlsSession.GetRecent(dataContext, search, 200),
            DecryptedRequests = await DecryptedRequest.GetRecent(dataContext, search, 200)
        };
    }
}

public class DataBleedReport
{
    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public List<ProcessTrafficSummary> Programs { get; set; } = [];
    public List<ProcessTimelinePoint> Timeline { get; set; } = [];
    public List<LocationSummary> Locations { get; set; } = [];
    public List<CountrySummary> Countries { get; set; } = [];
    public Dictionary<string, List<ProcessTrafficSummary>> ProgramsByCountry { get; set; } = [];
    public List<DestinationSummary> Destinations { get; set; } = [];
    public bool IncludeLocalDestinations { get; set; }
    public AwayReport Away { get; set; } = new();
    public List<SensorStatus> Sensors { get; set; } = [];
    public ResponseSettings Response { get; set; } = new();
    public DetectionSettings Detection { get; set; } = new();

    /// <summary>
    /// Everything programs on this computer uploaded and downloaded in the range, from the timeline so programs
    /// outside the top of the table count too.
    /// </summary>
    public TrafficSplit Totals => TrafficSplit.Sum(Timeline);

    private const int MapLocationCount = 200;
    private const int CountryCount = 12;
    private const int ProgramsPerCountry = 5;
    private const int DestinationCount = 100;

    public static async Task<DataBleedReport> Build(DataContext dataContext, TimeRange range, bool includeLocalDestinations = false)
    {
        var dataBleedReport = new DataBleedReport
        {
            Range = range,
            Programs = await ProcessTrafficMinute.GetSummaries(dataContext, range.SinceUnixSeconds, 100),
            Destinations = await ProcessTrafficMinute.GetDestinations(dataContext, range.SinceUnixSeconds, DestinationCount, includeLocalDestinations),
            IncludeLocalDestinations = includeLocalDestinations,
            Away = await AwayReport.Build(dataContext, range.SinceUnixSeconds),
            Timeline = await ProcessTrafficMinute.GetTimeline(dataContext, range.SinceUnixSeconds, range.StepSeconds, null),
            Locations = range.UsesHourlyData
                ? await TrafficHour.GetLocations(dataContext, range.SinceUnixSeconds, MapLocationCount)
                : await TrafficMinute.GetLocations(dataContext, range.SinceUnixSeconds, MapLocationCount),
            Countries = range.UsesHourlyData
                ? await TrafficHour.GetTopCountries(dataContext, range.SinceUnixSeconds, CountryCount)
                : await TrafficMinute.GetTopCountries(dataContext, range.SinceUnixSeconds, CountryCount),
            Sensors = await SensorStatus.GetAll(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            Detection = await Setting.Load<DetectionSettings>(dataContext)
        };

        var countryCodes = dataBleedReport.Countries.Select(country => country.CountryCode).ToList();
        dataBleedReport.ProgramsByCountry = await ProcessTrafficMinute.GetTopProgramsByCountry(dataContext, range.SinceUnixSeconds, countryCodes, ProgramsPerCountry);
        return dataBleedReport;
    }
}

public class ProgramReport
{
    public ProcessImage ProcessImage { get; set; } = new();
    public TimeRange Range { get; set; } = TimeRange.Parse(null);
    public List<ProcessTimelinePoint> Timeline { get; set; } = [];
    /// <summary>
    /// Where this program sent data, including devices on the local network.
    /// </summary>
    public List<DestinationSummary> Destinations { get; set; } = [];
    public List<ResponseAction> ResponseActions { get; set; } = [];

    public TrafficSplit Totals => TrafficSplit.Sum(Timeline);

    public static async Task<ProgramReport?> Build(DataContext dataContext, long processImageId, TimeRange range)
    {
        var processImage = await ProcessImage.Get(dataContext, item => item.Id == processImageId);
        if (processImage == null)
            return null;

        return new ProgramReport
        {
            ProcessImage = processImage,
            Range = range,
            Timeline = await ProcessTrafficMinute.GetTimeline(dataContext, range.SinceUnixSeconds, range.StepSeconds, processImageId),
            Destinations = await ProcessTrafficMinute.GetDestinations(dataContext, range.SinceUnixSeconds, 100, includeLocal: true, processImageId),
            ResponseActions = await ResponseAction.GetAll(dataContext, action => action.Target == processImage.ImagePath)
        };
    }
}

public class ResponseOverview
{
    public ResponseSettings Response { get; set; } = new();
    public List<ResponseAction> Actions { get; set; } = [];
    public List<SensorStatus> Sensors { get; set; } = [];
    public List<ScannerBlock> ScannerBlocks { get; set; } = [];
    public int ScannerBlockCount { get; set; }

    public static async Task<ResponseOverview> Build(DataContext dataContext)
    {
        return new ResponseOverview
        {
            ScannerBlocks = await ScannerBlock.GetActive(dataContext, 100),
            ScannerBlockCount = await ScannerBlock.CountActive(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            Actions = await ResponseAction.GetRecent(dataContext, 200),
            Sensors = await SensorStatus.GetAll(dataContext)
        };
    }
}
