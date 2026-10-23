using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json.Serialization;

namespace ScoutWall.Data.Models;

public enum ResponseMode
{
    WatchAndAlert = 1,
    Block = 2,
    Throttle = 3,
    BlockWhenIdle = 4
}

/// <summary>
/// What gets blocked while nobody is using the machine.
/// </summary>
public enum IdleBlockScope
{
    /// <summary>Only programs that send data out while the machine is idle are blocked.</summary>
    OffendingPrograms = 1,

    /// <summary>All traffic to public internet addresses is blocked except the address allowlist.</summary>
    AllInternet = 2
}

public enum WebhookFormat
{
    Generic = 1,
    Slack = 2,
    Teams = 3,
    Discord = 4
}

/// <summary>
/// A configuration section. PrepareForSave turns form input into the stored shape, for example keeping an
/// existing secret when the field was left blank.
/// </summary>
public interface ISettingsSection<in T>
{
    void PrepareForSave(T existingSection);
}

public class CaptureSettings : ISettingsSection<CaptureSettings>, IValidatableObject
{
    /// <summary>
    /// Capture device names as reported by the sensor (see capture_interfaces). Empty means all active interfaces.
    /// </summary>
    public List<string> InterfaceNames { get; set; } = [];

    public bool Promiscuous { get; set; }

    [MaxLength(512)]
    public string? CaptureFilter { get; set; }

    /// <summary>
    /// Extra networks treated as local in addition to the interface subnets, in CIDR notation.
    /// </summary>
    public List<string> LocalNetworks { get; set; } = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"];

    public bool WritePacketFiles { get; set; } = true;

    [Range(1, 1024)]
    public int PacketFileSizeMegabytes { get; set; } = 64;

    [Range(1, 500)]
    public int PacketFileCount { get; set; } = 20;

    public bool TrackProcesses { get; set; } = true;

    [JsonIgnore]
    public string LocalNetworksText
    {
        get => SettingsText.Join(LocalNetworks);
        set => LocalNetworks = SettingsText.Split(value);
    }

    public void PrepareForSave(CaptureSettings existingSection)
    {
        InterfaceNames = InterfaceNames.Where(name => !string.IsNullOrWhiteSpace(name)).Distinct().ToList();
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        return SettingsText.ValidateNetworks(LocalNetworks, "Local networks");
    }
}

public class ResponseSettings : ISettingsSection<ResponseSettings>, IValidatableObject
{
    public ResponseMode Mode { get; set; } = ResponseMode.WatchAndAlert;

    /// <summary>
    /// Record what would have been done without touching the firewall.
    /// </summary>
    public bool DryRun { get; set; } = true;

    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.High;

    [Range(1, 10080)]
    public int ActionDurationMinutes { get; set; } = 60;

    /// <summary>
    /// Outbound address blocks can break unrelated sites behind shared CDN addresses, so they are opt-in.
    /// </summary>
    public bool BlockOutbound { get; set; }

    [Range(1, 1000)]
    public int MaximumActiveActions { get; set; } = 50;

    [Range(8, 10_000_000)]
    public int ThrottleKilobitsPerSecond { get; set; } = 256;

    [Range(1, 1440)]
    public int IdleMinutes { get; set; } = 10;

    public IdleBlockScope IdleScope { get; set; } = IdleBlockScope.OffendingPrograms;

    /// <summary>
    /// Addresses and ranges that are never blocked or throttled.
    /// </summary>
    public List<string> AllowlistedAddresses { get; set; } = [];

    /// <summary>
    /// Program paths or file names that are never blocked or throttled.
    /// A bare file name only matches programs installed under Windows or Program Files, so a copy named
    /// svchost.exe in a user folder is not protected. Use a full path to allow a program anywhere else.
    /// </summary>
    public List<string> AllowlistedPrograms { get; set; } =
    [
        "System", "svchost.exe", "lsass.exe", "services.exe", "MsMpEng.exe", "TiWorker.exe", "wuauclt.exe", "ScoutWall.Sensor.exe", "scoutwall.exe"
    ];

    /// <summary>
    /// SHA-256 of programs allowed with "Always allow" from outside Windows and Program Files, by full path. If the
    /// file changes, the allowance no longer applies, so overwriting an allowed program does not inherit it.
    /// </summary>
    public Dictionary<string, string> AllowlistedProgramHashes { get; set; } = [];

    /// <summary>
    /// Full-path entries match exactly (and, when pinned, only while the file is unchanged). Bare file names only
    /// match programs under Windows or Program Files, so malware cannot earn an exemption by calling itself svchost.exe.
    /// </summary>
    public bool IsAllowlistedProgram(string imagePath)
    {
        var fileName = Path.GetFileName(imagePath);
        var isInProtectedFolder = TrustedPaths.IsInProtectedFolder(imagePath) || imagePath is "System" or "Idle";
        foreach (var entry in AllowlistedPrograms)
        {
            if (isInProtectedFolder && string.Equals(entry, fileName, StringComparison.OrdinalIgnoreCase))
                return true;

            if (!string.Equals(entry, imagePath, StringComparison.OrdinalIgnoreCase))
                continue;

            var pinnedHash = AllowlistedProgramHashes.FirstOrDefault(pair => string.Equals(pair.Key, imagePath, StringComparison.OrdinalIgnoreCase)).Value;
            return pinnedHash == null || string.Equals(pinnedHash, ProgramFileHash.Compute(imagePath), StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    [JsonIgnore]
    public string AllowlistedAddressesText
    {
        get => SettingsText.Join(AllowlistedAddresses);
        set => AllowlistedAddresses = SettingsText.Split(value);
    }

    [JsonIgnore]
    public string AllowlistedProgramsText
    {
        get => SettingsText.Join(AllowlistedPrograms);
        set => AllowlistedPrograms = SettingsText.Split(value);
    }

    /// <summary>
    /// The settings form does not post the file pins, so they carry over for every path still on the allowlist
    /// and are dropped for paths that were removed.
    /// </summary>
    public void PrepareForSave(ResponseSettings existingSection)
    {
        foreach (var existingPin in existingSection.AllowlistedProgramHashes)
        {
            var alreadyPinned = AllowlistedProgramHashes.Keys.Any(key => string.Equals(key, existingPin.Key, StringComparison.OrdinalIgnoreCase));
            if (!alreadyPinned)
                AllowlistedProgramHashes[existingPin.Key] = existingPin.Value;
        }

        var unlistedPins = AllowlistedProgramHashes.Keys
            .Where(key => !AllowlistedPrograms.Contains(key, StringComparer.OrdinalIgnoreCase))
            .ToList();
        foreach (var unlistedPin in unlistedPins)
            AllowlistedProgramHashes.Remove(unlistedPin);
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        return SettingsText.ValidateNetworks(AllowlistedAddresses, "Allowlisted addresses");
    }
}

public class DetectionSettings : ISettingsSection<DetectionSettings>
{
    public static readonly IReadOnlyDictionary<string, string> AllRules = new Dictionary<string, string>
    {
        ["PortScan"] = "Many distinct ports probed by one source",
        ["SynFlood"] = "Connection attempt flood against one host",
        ["HighVolume"] = "Very high inbound volume from one source",
        ["Blocklisted"] = "Traffic with an address on a threat blocklist",
        ["SensitivePortAccess"] = "Internet hosts reaching RDP, SMB, SSH and similar",
        ["ExcessiveDns"] = "Unusually many DNS queries from one host",
        ["DataBleed"] = "A program sending a large amount of data out",
        ["IdleDataBleed"] = "A program sending data out while nobody uses the computer",
        ["ScoreCard"] = "A flow the ScoreCard rates as problematic",
        ["InternalNameLeak"] = "A company or local name (WPAD, printers) resolving to an internet address",
        ["LogCleared"] = "A Windows event log was cleared",
        ["DefenderDetection"] = "Microsoft Defender found and dealt with a threat",
        ["DefenderActionFailed"] = "Microsoft Defender found a threat but could not remove it",
        ["ProtectionDisabled"] = "Microsoft Defender protection was turned off",
        ["NewService"] = "A new Windows service was installed",
        ["NewScheduledTask"] = "A new scheduled task was created",
        ["FailedSignIns"] = "Many failed sign-in attempts in a short time",
        ["AccountChange"] = "A user account was created or added to a powerful group",
        ["ServiceCrashLoop"] = "A Windows service keeps crashing",
        ["DecoyPortTouched"] = "Something connected to one of ScoutWall's decoy ports",
        ["FileExtensionRenames"] = "Many files renamed to a new extension (how ransomware leaves files)",
        ["MassFileChange"] = "One program changing a large number of personal files in a few minutes"
    };

    /// <summary>
    /// Rule and source pairs a person confirmed as legitimate, written as "Rule|address".
    /// </summary>
    public List<string> SuppressedDetections { get; set; } = [];

    public static string SuppressionEntry(string ruleName, string sourceAddress)
    {
        return $"{ruleName}|{sourceAddress}";
    }

    public bool IsSuppressed(string ruleName, string sourceAddress)
    {
        return SuppressedDetections.Contains(SuppressionEntry(ruleName, sourceAddress), StringComparer.OrdinalIgnoreCase);
    }

    public List<string> DisabledRules { get; set; } = [];

    /// <summary>
    /// Hours after monitoring first starts during which ScoutWall learns what is normal on this machine.
    /// Newness is not treated as suspicious during this time, because everything is new.
    /// </summary>
    [Range(0, 720)]
    public int LearningPeriodHours { get; set; } = 24;

    /// <summary>
    /// Opens a few unused ports that nothing legitimate should ever touch. Off by default, and only reachable on
    /// home and work networks, never on public Wi-Fi.
    /// </summary>
    public bool DecoyPortsEnabled { get; set; }

    /// <summary>
    /// The decoy ports. Empty means ScoutWall picks five unused ones from <see cref="DecoyPortCandidates"/>.
    /// </summary>
    public List<int> DecoyPorts { get; set; } = [];

    /// <summary>
    /// Low, commonly scanned ports that a home computer normally doesn't use. 135, 139 and 445 are never used,
    /// because Windows opens them on demand.
    /// </summary>
    public static readonly int[] DecoyPortCandidates = [21, 23, 110, 143, 1433, 2323, 3306, 5900, 6379, 8081];

    /// <summary>
    /// Internet addresses that scan this computer or touch a decoy port are blocked at once. Local devices are
    /// reported instead, because blocking a device on your own network can break printing, casting and the like.
    /// </summary>
    public bool BlockInternetScanners { get; set; } = true;

    [Range(1, 365)]
    public int ScannerBlockDays { get; set; } = 7;

    [JsonIgnore]
    public string DecoyPortsText
    {
        get => string.Join(", ", DecoyPorts);
        set => DecoyPorts = SettingsText.Split(value)
            .SelectMany(item => item.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(item => int.TryParse(item, out var port) ? port : -1)
            .Where(port => port is > 0 and <= 65535 and not (135 or 139 or 445))
            .Distinct()
            .Take(20)
            .ToList();
    }

    [Range(1, 1440)]
    public int AlertAggregationMinutes { get; set; } = 15;

    [Range(5, 65535)]
    public int PortScanDistinctPorts { get; set; } = 25;

    [Range(5, 3600)]
    public int PortScanWindowSeconds { get; set; } = 60;

    [Range(10, 1_000_000)]
    public int SynFloodPerTenSeconds { get; set; } = 2000;

    [Range(1, 100_000)]
    public int HighVolumeMegabytesPerMinute { get; set; } = 500;

    public List<int> SensitivePorts { get; set; } = [21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379];

    [Range(10, 1_000_000)]
    public int DnsQueriesPerMinute { get; set; } = 600;

    [Range(1, 1_000_000)]
    public int DataBleedMegabytesPerTenMinutes { get; set; } = 500;

    [Range(1, 1_000_000)]
    public int IdleDataBleedMegabytesPerTenMinutes { get; set; } = 25;

    /// <summary>
    /// Posted by the settings form as checkboxes; converted to <see cref="DisabledRules"/> on save.
    /// </summary>
    [JsonIgnore]
    public List<string>? EnabledRules { get; set; }

    [JsonIgnore]
    public string SensitivePortsText
    {
        get => string.Join(", ", SensitivePorts);
        set => SensitivePorts = SettingsText.Split(value)
            .SelectMany(item => item.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(item => int.TryParse(item, out var port) ? port : -1)
            .Where(port => port is > 0 and <= 65535)
            .Distinct()
            .ToList();
    }

    public bool IsEnabled(string ruleName)
    {
        return !DisabledRules.Contains(ruleName, StringComparer.OrdinalIgnoreCase);
    }

    public void PrepareForSave(DetectionSettings existingSection)
    {
        if (EnabledRules == null)
            return;

        DisabledRules = AllRules.Keys.Where(ruleName => !EnabledRules.Contains(ruleName)).ToList();
    }
}

public class NotificationSettings : ISettingsSection<NotificationSettings>
{
    public bool EmailEnabled { get; set; }

    [MaxLength(256)]
    public string? SmtpHost { get; set; }

    [Range(1, 65535)]
    public int SmtpPort { get; set; } = 587;

    public bool SmtpUseTls { get; set; } = true;

    [MaxLength(256)]
    public string? SmtpUsername { get; set; }

    /// <summary>
    /// Stored encrypted with Windows DPAPI (machine scope). Blank on the form means "keep the saved value".
    /// </summary>
    public string? SmtpPassword { get; set; }

    [MaxLength(256)]
    [EmailAddress]
    public string? EmailFrom { get; set; }

    public List<string> EmailTo { get; set; } = [];

    public AlertSeverity EmailMinimumSeverity { get; set; } = AlertSeverity.High;

    public bool WebhookEnabled { get; set; }

    /// <summary>
    /// Stored encrypted with Windows DPAPI (machine scope); webhook URLs usually embed a secret token.
    /// </summary>
    public string? WebhookUrl { get; set; }

    public WebhookFormat WebhookFormat { get; set; } = WebhookFormat.Generic;

    public AlertSeverity WebhookMinimumSeverity { get; set; } = AlertSeverity.Medium;

    /// <summary>
    /// Shown by the presence agent in the notification area of each signed-in user.
    /// </summary>
    public bool DesktopEnabled { get; set; } = true;

    public AlertSeverity DesktopMinimumSeverity { get; set; } = AlertSeverity.High;

    /// <summary>
    /// Minimum time between notifications for the same rule and source.
    /// </summary>
    [Range(0, 1440)]
    public int RepeatMinutes { get; set; } = 30;

    [JsonIgnore]
    public bool ClearSmtpPassword { get; set; }

    [JsonIgnore]
    public bool ClearWebhookUrl { get; set; }

    [JsonIgnore]
    public string EmailToText
    {
        get => SettingsText.Join(EmailTo);
        set => EmailTo = SettingsText.Split(value);
    }

    [JsonIgnore]
    public bool HasSmtpPassword => !string.IsNullOrEmpty(SmtpPassword);

    [JsonIgnore]
    public bool HasWebhookUrl => !string.IsNullOrEmpty(WebhookUrl);

    public void PrepareForSave(NotificationSettings existingSection)
    {
        SmtpPassword = KeepOrReplaceSecret(SmtpPassword, existingSection.SmtpPassword, ClearSmtpPassword);
        WebhookUrl = KeepOrReplaceSecret(WebhookUrl, existingSection.WebhookUrl, ClearWebhookUrl);
    }

    private static string? KeepOrReplaceSecret(string? submittedValue, string? storedValue, bool clear)
    {
        if (clear)
            return null;

        return string.IsNullOrEmpty(submittedValue) ? storedValue : SecretProtector.Protect(submittedValue);
    }
}

public class IntegrationSettings : ISettingsSection<IntegrationSettings>, IValidatableObject
{
    [MaxLength(260)]
    public string? GeoIpCityDatabasePath { get; set; }

    [MaxLength(260)]
    public string? GeoIpAsnDatabasePath { get; set; }

    /// <summary>
    /// ip-api.com is free for non-commercial use only and is queried over plain HTTP, so it is off unless the owner
    /// turns it on.
    /// </summary>
    public bool UseIpApiFallback { get; set; }

    public List<string> BlocklistUrls { get; set; } =
    [
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    ];

    public List<string> StaticBlocklist { get; set; } = [];

    [Range(1, 168)]
    public int BlocklistRefreshHours { get; set; } = 24;

    public bool DecryptionEnabled { get; set; }

    [MaxLength(260)]
    public string? TsharkPath { get; set; } = @"C:\Program Files\Wireshark\tshark.exe";

    [MaxLength(260)]
    public string? KeyLogFilePath { get; set; }

    [JsonIgnore]
    public string BlocklistUrlsText
    {
        get => SettingsText.Join(BlocklistUrls);
        set => BlocklistUrls = SettingsText.Split(value);
    }

    [JsonIgnore]
    public string StaticBlocklistText
    {
        get => SettingsText.Join(StaticBlocklist);
        set => StaticBlocklist = SettingsText.Split(value);
    }

    public void PrepareForSave(IntegrationSettings existingSection)
    {
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        foreach (var blocklistUrl in BlocklistUrls.Where(url => !Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != "https"))
            yield return new ValidationResult($"Blocklist URL '{blocklistUrl}' must be an https address.");

        if (!string.IsNullOrWhiteSpace(TsharkPath) && !TrustedPaths.IsTrustedTshark(TsharkPath))
            yield return new ValidationResult("tshark must be the tshark.exe installed under Program Files (the sensor runs it as an administrator).");

        foreach (var databasePath in new[] { GeoIpCityDatabasePath, GeoIpAsnDatabasePath }.Where(path => !string.IsNullOrWhiteSpace(path)))
        {
            if (!databasePath!.EndsWith(".mmdb", StringComparison.OrdinalIgnoreCase))
                yield return new ValidationResult($"'{databasePath}' is not a MaxMind .mmdb database file.");
        }

        foreach (var validationResult in SettingsText.ValidateNetworks(StaticBlocklist, "Static blocklist"))
            yield return validationResult;
    }
}

/// <summary>
/// The flow verdict pipeline: the deterministic ScoreCard and an optional external engine such as zev.
/// </summary>
public class VerdictSettings : ISettingsSection<VerdictSettings>, IValidatableObject
{
    [Range(10, 3600)]
    public int EvaluationIntervalSeconds { get; set; } = 30;

    [Range(10, 5000)]
    public int MaximumFlowsPerPass { get; set; } = 200;

    public bool ScoreCardEnabled { get; set; } = true;

    [Range(1, 1000)]
    public int ScoreCardSuspiciousScore { get; set; } = 40;

    [Range(1, 1000)]
    public int ScoreCardProblematicScore { get; set; } = 70;

    /// <summary>
    /// Countries (ISO codes) that add risk points. Empty by default; this is a local policy decision.
    /// </summary>
    public List<string> HighRiskCountries { get; set; } = [];

    public bool ZevEnabled { get; set; }

    [MaxLength(512)]
    public string ZevEndpointUrl { get; set; } = "http://127.0.0.1:8080/v1/decisions";

    public ExternalVerdictMode ZevMode { get; set; } = ExternalVerdictMode.Shadow;

    [Range(0.0, 1.0)]
    public double ZevMinimumConfidence { get; set; } = 0.85;

    [Range(1, 6000)]
    public int ZevMaximumRequestsPerMinute { get; set; } = 60;

    [Range(100, 60_000)]
    public int ZevTimeoutMilliseconds { get; set; } = 2000;

    [JsonIgnore]
    public string HighRiskCountriesText
    {
        get => string.Join(", ", HighRiskCountries);
        set => HighRiskCountries = SettingsText.Split(value)
            .SelectMany(item => item.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(item => item.ToUpperInvariant())
            .Where(item => item.Length == 2)
            .Distinct()
            .ToList();
    }

    public void PrepareForSave(VerdictSettings existingSection)
    {
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (ScoreCardProblematicScore <= ScoreCardSuspiciousScore)
            yield return new ValidationResult("The problematic score must be higher than the suspicious score.");

        if (!Uri.TryCreate(ZevEndpointUrl, UriKind.Absolute, out var zevUri) || zevUri.Scheme is not ("http" or "https"))
            yield return new ValidationResult("The zev endpoint must be an http or https address.");
        else if (!zevUri.IsLoopback)
            yield return new ValidationResult("The zev endpoint must be on this machine (localhost); flow details are sent to it.");
    }
}

/// <summary>
/// The analyst agent: Claude reviews what the detectors nominate and decides what the user actually needs to see.
/// Only metadata leaves the machine (addresses, names, program paths, byte counts), never packet contents.
/// </summary>
public enum AnalystProvider
{
    None = 0,
    Claude = 1,
    OpenAi = 2,
    OpenRouter = 3,
    LocalModel = 4
}

public class AnalystSettings : ISettingsSection<AnalystSettings>, IValidatableObject
{
    public static readonly IReadOnlyList<string> Models = ["claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1"];
    public static readonly IReadOnlyList<string> EffortLevels = ["low", "medium", "high", "xhigh"];
    public const string OpenAiEndpoint = "https://api.openai.com/v1";
    public const string OpenRouterEndpoint = "https://openrouter.ai/api/v1";

    public bool Enabled { get; set; }

    public AnalystProvider Provider { get; set; } = AnalystProvider.Claude;

    /// <summary>
    /// Anthropic API key, stored encrypted with Windows DPAPI. Blank on the form keeps the saved key.
    /// </summary>
    public string? ApiKey { get; set; }

    public string Model { get; set; } = "claude-opus-5-5";

    public string? OpenAiApiKey { get; set; }

    public string OpenAiModel { get; set; } = "gpt-5-mini";

    public string? OpenRouterApiKey { get; set; }

    public string OpenRouterModel { get; set; } = "openai/gpt-oss-20b";

    /// <summary>
    /// An OpenAI-compatible endpoint on this computer or the local network, such as Ollama or LM Studio.
    /// </summary>
    public string LocalEndpoint { get; set; } = "http://localhost:11434/v1";

    public string LocalModel { get; set; } = "gpt-oss:20b";

    /// <summary>
    /// Claude conclusions close soft alerts by default. Other models only annotate them unless this is on,
    /// because a smaller model's "benign" should not silently hide an alert.
    /// </summary>
    public bool LetOtherModelsCloseAlerts { get; set; }

    public string Effort { get; set; } = "medium";

    [Range(1, 1000)]
    public int MaximumInvestigationsPerHour { get; set; } = 20;

    [Range(10_000, 100_000_000)]
    public int DailyTokenBudget { get; set; } = 2_000_000;

    /// <summary>
    /// Off by default: a search can land on a page an attacker wrote about their own domain.
    /// </summary>
    public bool WebSearchEnabled { get; set; }

    public List<string> WebSearchDomains { get; set; } =
        ["virustotal.com", "abuseipdb.com", "urlhaus.abuse.ch", "bgp.he.net", "learn.microsoft.com", "support.google.com", "ipinfo.io"];

    [Range(1, AnalystAssessment.MaximumRememberDays)]
    public int RememberDays { get; set; } = 14;

    [Range(1.5, 100)]
    public double ReopenVolumeMultiplier { get; set; } = 3;

    /// <summary>
    /// How long soft alerts wait for the analyst before the response mode may act on them.
    /// </summary>
    [Range(0, 60)]
    public int SoftAlertGraceMinutes { get; set; } = 3;

    [Range(1, 90)]
    public int BaselineRefreshDays { get; set; } = 7;

    public bool NotifyFindings { get; set; } = true;

    [JsonIgnore]
    public bool ClearApiKey { get; set; }

    [JsonIgnore]
    public bool HasApiKey => Provider switch
    {
        AnalystProvider.Claude => !string.IsNullOrEmpty(ApiKey),
        AnalystProvider.OpenAi => !string.IsNullOrEmpty(OpenAiApiKey),
        AnalystProvider.OpenRouter => !string.IsNullOrEmpty(OpenRouterApiKey),
        AnalystProvider.LocalModel => true,
        _ => false
    };

    [JsonIgnore]
    public bool HasClaudeKey => !string.IsNullOrEmpty(ApiKey);

    [JsonIgnore]
    public bool HasOpenAiKey => !string.IsNullOrEmpty(OpenAiApiKey);

    [JsonIgnore]
    public bool HasOpenRouterKey => !string.IsNullOrEmpty(OpenRouterApiKey);

    [JsonIgnore]
    public bool MayCloseAlerts => Provider == AnalystProvider.Claude || LetOtherModelsCloseAlerts;

    [JsonIgnore]
    public string ActiveModel => Provider switch
    {
        AnalystProvider.Claude => Model,
        AnalystProvider.OpenAi => OpenAiModel,
        AnalystProvider.OpenRouter => OpenRouterModel,
        AnalystProvider.LocalModel => LocalModel,
        _ => "none"
    };

    [JsonIgnore]
    public string ProviderDisplayName => Provider switch
    {
        AnalystProvider.Claude => "Claude (Anthropic)",
        AnalystProvider.OpenAi => "ChatGPT (OpenAI)",
        AnalystProvider.OpenRouter => "OpenRouter",
        AnalystProvider.LocalModel => "A model on this computer",
        _ => "None"
    };

    /// <summary>
    /// Whether this provider sends data off the machine.
    /// </summary>
    [JsonIgnore]
    public bool IsCloudProvider => Provider is AnalystProvider.Claude or AnalystProvider.OpenAi or AnalystProvider.OpenRouter;

    [JsonIgnore]
    public string WebSearchDomainsText
    {
        get => SettingsText.Join(WebSearchDomains);
        set => WebSearchDomains = SettingsText.Split(value);
    }

    public bool IsReady => Enabled && Provider != AnalystProvider.None && HasApiKey;

    public void PrepareForSave(AnalystSettings existingSection)
    {
        ApiKey = ClearApiKey ? null : KeepOrProtect(ApiKey, existingSection.ApiKey);
        OpenAiApiKey = KeepOrProtect(OpenAiApiKey, existingSection.OpenAiApiKey);
        OpenRouterApiKey = KeepOrProtect(OpenRouterApiKey, existingSection.OpenRouterApiKey);
    }

    private static string? KeepOrProtect(string? submittedValue, string? storedValue)
    {
        return string.IsNullOrWhiteSpace(submittedValue) ? storedValue : SecretProtector.Protect(submittedValue.Trim());
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!Models.Contains(Model))
            yield return new ValidationResult("Choose one of the listed Claude models.");

        if (Provider == AnalystProvider.LocalModel && !IsLocalEndpoint(LocalEndpoint))
            yield return new ValidationResult("The local model address must be on this computer or your local network (for example http://localhost:11434/v1).");

        if (string.IsNullOrWhiteSpace(ActiveModel))
            yield return new ValidationResult("Enter a model name.");

        if (!EffortLevels.Contains(Effort))
            yield return new ValidationResult("Choose one of the listed effort levels.");

        if (WebSearchEnabled && WebSearchDomains.Count == 0)
            yield return new ValidationResult("Web search needs at least one allowed reputation site.");

        foreach (var domain in WebSearchDomains.Where(domain => domain.Contains('/') || domain.Contains(' ') || !domain.Contains('.')))
            yield return new ValidationResult($"'{domain}' is not a plain domain name.");
    }

    /// <summary>
    /// Plain http is only acceptable on this computer or the local network.
    /// </summary>
    public static bool IsLocalEndpoint(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            return false;

        if (uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            return true;

        return IPAddress.TryParse(uri.Host, out var address) && SettingsText.IsPrivateAddress(address);
    }
}

public enum EnforcementProvider
{
    MonitorOnly = 0,
    WindowsFirewall = 1,
    Webhook = 2
}

/// <summary>
/// Where blocks and throttles are carried out: nowhere (just tell me), Windows Defender Firewall on this
/// computer, or a router or firewall that accepts signed webhook requests.
/// </summary>
public class EnforcementSettings : ISettingsSection<EnforcementSettings>, IValidatableObject
{
    public EnforcementProvider Provider { get; set; } = EnforcementProvider.WindowsFirewall;

    [MaxLength(512)]
    public string? WebhookUrl { get; set; }

    /// <summary>
    /// Shared secret used to sign webhook requests (HMAC-SHA256). Stored encrypted with Windows DPAPI.
    /// </summary>
    public string? WebhookSecret { get; set; }

    [JsonIgnore]
    public bool HasWebhookSecret => !string.IsNullOrEmpty(WebhookSecret);

    public static IReadOnlySet<ResponseActionType> Capabilities(EnforcementProvider provider)
    {
        return provider switch
        {
            EnforcementProvider.WindowsFirewall => new HashSet<ResponseActionType>
            {
                ResponseActionType.BlockAddress, ResponseActionType.BlockProgram, ResponseActionType.ThrottleAddress,
                ResponseActionType.ThrottleProgram, ResponseActionType.IdleLockdown
            },
            EnforcementProvider.Webhook => new HashSet<ResponseActionType> { ResponseActionType.BlockAddress, ResponseActionType.ThrottleAddress },
            _ => new HashSet<ResponseActionType>()
        };
    }

    public bool Supports(ResponseActionType actionType)
    {
        return Capabilities(Provider).Contains(actionType);
    }

    [JsonIgnore]
    public string ProviderDisplayName => Provider switch
    {
        EnforcementProvider.WindowsFirewall => "Windows Defender Firewall on this computer",
        EnforcementProvider.Webhook => "Your router or firewall (webhook)",
        _ => "Nothing is blocked; ScoutWall only tells you"
    };

    public void PrepareForSave(EnforcementSettings existingSection)
    {
        WebhookSecret = string.IsNullOrWhiteSpace(WebhookSecret) ? existingSection.WebhookSecret : SecretProtector.Protect(WebhookSecret.Trim());
    }

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (Provider != EnforcementProvider.Webhook)
            yield break;

        if (!Uri.TryCreate(WebhookUrl, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            yield return new ValidationResult("Enter the address of your router or firewall's webhook.");
        else if (uri.Scheme == "http" && !AnalystSettings.IsLocalEndpoint(WebhookUrl!))
            yield return new ValidationResult("Use https for a webhook outside your local network.");
    }
}

public class RetentionSettings : ISettingsSection<RetentionSettings>
{
    [Range(1, 30)]
    public int MinuteTrafficDays { get; set; } = 2;

    [Range(1, 3650)]
    public int HourTrafficDays { get; set; } = 90;

    [Range(1, 365)]
    public int ProcessTrafficDays { get; set; } = 14;

    [Range(1, 3650)]
    public int ResolvedAlertDays { get; set; } = 180;

    [Range(1, 3650)]
    public int DnsRecordDays { get; set; } = 30;

    [Range(1, 3650)]
    public int TlsSessionDays { get; set; } = 30;

    [Range(1, 3650)]
    public int DecryptedRequestDays { get; set; } = 14;

    [Range(1, 3650)]
    public int FlowVerdictDays { get; set; } = 30;

    [Range(1, 3650)]
    public int AuditDays { get; set; } = 365;

    [Range(1, 90)]
    public int SystemResourceDays { get; set; } = 14;

    [Range(1, 3650)]
    public int SystemEventDays { get; set; } = 30;

    /// <summary>
    /// File names can reveal personal content, so file changes are kept only briefly.
    /// </summary>
    [Range(1, 90)]
    public int FileChangeDays { get; set; } = 7;

    [Range(1, 365)]
    public int DiskActivityDays { get; set; } = 14;

    public void PrepareForSave(RetentionSettings existingSection)
    {
    }
}

/// <summary>
/// Locations the elevated sensor is willing to trust for programs it runs or allowlists by name.
/// </summary>
public static class TrustedPaths
{
    public static IEnumerable<string> ProtectedFolders()
    {
        return new[]
            {
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
            }
            .Where(folder => !string.IsNullOrEmpty(folder))
            .Select(folder => folder.TrimEnd('\\') + "\\");
    }

    public static bool IsInProtectedFolder(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || path.Contains(".."))
            return false;

        var fullPath = Path.GetFullPath(path);
        return ProtectedFolders().Any(folder => fullPath.StartsWith(folder, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsTrustedTshark(string path)
    {
        return IsInProtectedFolder(path) && string.Equals(Path.GetFileName(path), "tshark.exe", StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Converts between stored lists and the one-entry-per-line text areas on the settings page.
/// </summary>
public static class SettingsText
{
    public static string Join(IEnumerable<string> values)
    {
        return string.Join(Environment.NewLine, values);
    }

    public static List<string> Split(string? text)
    {
        return (text ?? string.Empty)
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(line => line.Length > 0)
            .Distinct()
            .ToList();
    }

    public static bool IsAddressOrRange(string text)
    {
        var parts = text.Split('/');
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out var address))
            return false;

        var maximumPrefix = address.GetAddressBytes().Length * 8;
        return parts.Length == 1 || (int.TryParse(parts[1], out var prefix) && prefix >= 0 && prefix <= maximumPrefix);
    }

    public static bool IsPrivateAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal || address.IsIPv6SiteLocal)
            return true;

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4
            && (bytes[0] == 10 || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127));
    }

    public static IEnumerable<ValidationResult> ValidateNetworks(IEnumerable<string> entries, string fieldName)
    {
        return entries
            .Where(entry => !IsAddressOrRange(entry))
            .Select(entry => new ValidationResult($"{fieldName}: '{entry}' is not an IP address or CIDR range."));
    }
}
