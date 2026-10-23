using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// One configuration section stored as JSON. The sensor watches the highest revision and reloads on change.
/// </summary>
[Table("settings")]
public class Setting : Repository<Setting>
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };

    [Key]
    [Column("section_name")]
    [MaxLength(64)]
    public string SectionName { get; set; } = string.Empty;

    [Column("value_json")]
    public string ValueJson { get; set; } = "{}";

    [Column("revision")]
    public long Revision { get; set; }

    [Column("updated_at")]
    public DateTime UpdatedAt { get; set; }

    [Column("updated_by")]
    [MaxLength(256)]
    public string UpdatedBy { get; set; } = string.Empty;

    public static string SectionNameFor<T>()
    {
        return typeof(T).Name.Replace("Settings", string.Empty);
    }

    public static async Task<long> GetLatestRevision(DataContext dataContext)
    {
        return await Query(dataContext).MaxAsync(setting => (long?)setting.Revision) ?? 0;
    }

    public static async Task<long> GetRevision<T>(DataContext dataContext)
    {
        var sectionName = SectionNameFor<T>();
        var setting = await Get(dataContext, item => item.SectionName == sectionName);
        return setting?.Revision ?? 0;
    }

    public static async Task<T> Load<T>(DataContext dataContext) where T : new()
    {
        var sectionName = SectionNameFor<T>();
        var setting = await Get(dataContext, item => item.SectionName == sectionName);
        if (setting == null)
            return new T();

        return JsonSerializer.Deserialize<T>(setting.ValueJson, JsonOptions) ?? new T();
    }

    /// <summary>
    /// Validates and stores a section. Returns validation errors, or an empty list on success.
    /// Fails when someone else saved the section after <paramref name="expectedRevision"/> was read.
    /// </summary>
    public static async Task<List<string>> Save<T>(DataContext dataContext, T section, long expectedRevision, string userEmail)
        where T : class, ISettingsSection<T>, new()
    {
        section.PrepareForSave(await Load<T>(dataContext));
        var errors = Validate(section);
        if (errors.Count > 0)
            return errors;

        var sectionName = SectionNameFor<T>();
        var existingSetting = await Get(dataContext, item => item.SectionName == sectionName);
        var currentRevision = existingSetting?.Revision ?? 0;
        if (currentRevision != expectedRevision)
            return ["These settings were changed by someone else. Reload the page and try again."];

        var setting = existingSetting ?? new Setting { SectionName = sectionName };
        var oldJson = setting.ValueJson;
        setting.ValueJson = JsonSerializer.Serialize(section, JsonOptions);
        setting.Revision = await GetLatestRevision(dataContext) + 1;
        setting.UpdatedAt = DateTime.UtcNow;
        setting.UpdatedBy = userEmail;

        if (existingSetting == null)
            await Insert(dataContext, setting);
        else
            await Update(dataContext, setting);

        await AuditEntry.Record(dataContext, userEmail, "Settings changed", sectionName, new
        {
            before = SecretProtector.RedactJson(oldJson),
            after = SecretProtector.RedactJson(setting.ValueJson)
        });
        return [];
    }

    private static List<string> Validate(object section)
    {
        var validationResults = new List<ValidationResult>();
        Validator.TryValidateObject(section, new ValidationContext(section), validationResults, validateAllProperties: true);
        return validationResults.Select(result => result.ErrorMessage ?? "Invalid value.").ToList();
    }
}

/// <summary>
/// The full configuration as one object. Not persisted directly; each section is a <see cref="Setting"/> row.
/// </summary>
public class SensorConfiguration
{
    public long Revision { get; set; }
    public CaptureSettings Capture { get; set; } = new();
    public ResponseSettings Response { get; set; } = new();
    public DetectionSettings Detection { get; set; } = new();
    public NotificationSettings Notification { get; set; } = new();
    public IntegrationSettings Integration { get; set; } = new();
    public RetentionSettings Retention { get; set; } = new();
    public VerdictSettings Verdict { get; set; } = new();
    public AnalystSettings Analyst { get; set; } = new();
    public EnforcementSettings Enforcement { get; set; } = new();
    public FileTrackingSettings FileTracking { get; set; } = new();

    public static async Task<SensorConfiguration> Load(DataContext dataContext)
    {
        return new SensorConfiguration
        {
            Revision = await Setting.GetLatestRevision(dataContext),
            Capture = await Setting.Load<CaptureSettings>(dataContext),
            Response = await Setting.Load<ResponseSettings>(dataContext),
            Detection = await Setting.Load<DetectionSettings>(dataContext),
            Notification = await Setting.Load<NotificationSettings>(dataContext),
            Integration = await Setting.Load<IntegrationSettings>(dataContext),
            Retention = await Setting.Load<RetentionSettings>(dataContext),
            Verdict = await Setting.Load<VerdictSettings>(dataContext),
            Analyst = await Setting.Load<AnalystSettings>(dataContext),
            Enforcement = await Setting.Load<EnforcementSettings>(dataContext),
            FileTracking = await Setting.Load<FileTrackingSettings>(dataContext)
        };
    }
}
