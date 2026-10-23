namespace ScoutWall.Data.Models;

/// <summary>
/// Everything the settings page shows: each configuration section with its revision (for conflict
/// detection), the interfaces the sensor can capture on, sensor state and users.
/// </summary>
public class SettingsOverview
{
    public static readonly IReadOnlyList<(string Key, string Label)> Tabs =
    [
        ("capture", "Interfaces & capture"),
        ("response", "Response actions"),
        ("detection", "Detection rules"),
        ("protection", "Protection"),
        ("analyst", "Assistant"),
        ("analysis", "Flow analysis"),
        ("notifications", "Notifications"),
        ("integrations", "Integrations"),
        ("retention", "Data retention"),
        ("users", "Users")
    ];

    public string Tab { get; set; } = "capture";
    public CaptureSettings Capture { get; set; } = new();
    public ResponseSettings Response { get; set; } = new();
    public DetectionSettings Detection { get; set; } = new();
    public NotificationSettings Notification { get; set; } = new();
    public IntegrationSettings Integration { get; set; } = new();
    public VerdictSettings Verdict { get; set; } = new();
    public AnalystSettings Analyst { get; set; } = new();
    public EnforcementSettings Enforcement { get; set; } = new();
    public RetentionSettings Retention { get; set; } = new();
    public Dictionary<string, long> Revisions { get; set; } = [];
    public List<CaptureInterface> Interfaces { get; set; } = [];
    public List<SensorStatus> Sensors { get; set; } = [];
    public List<User> Users { get; set; } = [];

    public long RevisionOf<T>()
    {
        return Revisions.GetValueOrDefault(Setting.SectionNameFor<T>());
    }

    public static async Task<SettingsOverview> Build(DataContext dataContext, string? tab)
    {
        var settings = await Setting.GetAll(dataContext);
        return new SettingsOverview
        {
            Tab = Tabs.Any(item => item.Key == tab) ? tab! : "capture",
            Capture = await Setting.Load<CaptureSettings>(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            Detection = await Setting.Load<DetectionSettings>(dataContext),
            Notification = await Setting.Load<NotificationSettings>(dataContext),
            Integration = await Setting.Load<IntegrationSettings>(dataContext),
            Verdict = await Setting.Load<VerdictSettings>(dataContext),
            Analyst = await Setting.Load<AnalystSettings>(dataContext),
            Enforcement = await Setting.Load<EnforcementSettings>(dataContext),
            Retention = await Setting.Load<RetentionSettings>(dataContext),
            Revisions = settings.ToDictionary(setting => setting.SectionName, setting => setting.Revision),
            Interfaces = await CaptureInterface.GetAllOrdered(dataContext),
            Sensors = await SensorStatus.GetAll(dataContext),
            Users = await User.GetAllOrdered(dataContext)
        };
    }
}
