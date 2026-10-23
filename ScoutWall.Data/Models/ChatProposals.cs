using System.Net;
using System.Text.Json;

namespace ScoutWall.Data.Models;

/// <summary>
/// The only changes the chat assistant can propose, each validated here and described in ScoutWall's own words.
/// Riskier changes (allowlists, practice mode, firewall choice, API keys, users, rule switches) deliberately have
/// no entry: they can only be made on the Settings pages.
/// </summary>
public static class ChatProposals
{
    public const int MaximumProposalsPerHour = 20;

    public static readonly IReadOnlyDictionary<string, string> Kinds = new Dictionary<string, string>
    {
        ["notifications"] = "Turn email, webhook or desktop notifications on or off, or change how serious an alert must be. Details: {\"channel\": \"email|webhook|desktop\", \"enabled\": true|false, \"minimum_severity\": \"Low|Medium|High|Critical\" (optional)}",
        ["acknowledge_finding"] = "Mark one of the assistant's findings as dealt with. Details: {\"finding_id\": number}",
        ["learning_hours"] = "Change how long ScoutWall spends learning what is normal. Details: {\"hours\": 0-720}",
        ["block"] = "Block an internet address, or stop a program sending data out. Details: {\"what\": \"address|program\", \"target\": \"IP address or full program path\", \"duration_minutes\": 60-10080, or 0 for until removed}",
        ["unblock"] = "Remove a block ScoutWall put in place. Details: {\"block_id\": number}",
        ["protection"] = "Change what ScoutWall does when it finds something bad. Details: {\"choice\": \"just_tell_me|block_automatically|block_while_away|slow_it_down\"}",
        ["watch"] = "Choose which connections to watch. Details: {\"interface_names\": [names from list_interfaces], or [] for automatic}"
    };

    /// <summary>
    /// Validates a proposal and stores it for the person to confirm. Returns the stored change, or an explanation
    /// the assistant can relay when the proposal is not allowed.
    /// </summary>
    public static async Task<(PendingChange? Change, string? Problem)> Propose(DataContext dataContext, long userId, string kind, JsonElement details, bool basedOnNetworkData)
    {
        if (await PendingChange.CountSince(dataContext, userId, DateTime.UtcNow.AddHours(-1)) >= MaximumProposalsPerHour)
            return (null, "Too many changes were proposed in the last hour. Please make further changes on the Settings page.");

        var (summary, consequence, problem) = kind switch
        {
            "notifications" => await DescribeNotifications(dataContext, details),
            "acknowledge_finding" => await DescribeAcknowledge(dataContext, details),
            "learning_hours" => DescribeLearningHours(details),
            "block" => await DescribeBlock(dataContext, details),
            "unblock" => await DescribeUnblock(dataContext, details),
            "protection" => DescribeProtection(details),
            "watch" => await DescribeWatch(dataContext, details),
            _ => (string.Empty, null, "That isn't something that can be changed from chat. Allowlists, practice mode, the firewall choice, API keys and user accounts are changed on the Settings page.")
        };

        if (problem != null)
            return (null, problem);

        var pendingChange = new PendingChange
        {
            UserId = userId,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.Add(PendingChange.Lifetime),
            Kind = kind,
            PayloadJson = details.GetRawText(),
            Summary = summary,
            Consequence = consequence,
            BasedOnNetworkData = basedOnNetworkData
        };
        await PendingChange.Insert(dataContext, pendingChange);
        dataContext.ChangeTracker.Clear();
        return (pendingChange, null);
    }

    /// <summary>
    /// Carries out a confirmed change. Only the person it was proposed to can confirm it, and only before it expires.
    /// </summary>
    public static async Task<string?> Confirm(DataContext dataContext, long id, long userId, string userEmail)
    {
        var pendingChange = await PendingChange.Get(dataContext, change => change.Id == id && change.UserId == userId);
        if (pendingChange == null)
            return "That change was not found.";

        if (!pendingChange.IsOpen)
        {
            if (pendingChange.Status == PendingChangeStatus.Proposed)
                await PendingChange.MarkResolved(dataContext, id, PendingChangeStatus.Expired);
            return "That change has expired or was already handled. Ask again if you still want it.";
        }

        using var document = JsonDocument.Parse(pendingChange.PayloadJson);
        var details = document.RootElement;
        var actor = $"{userEmail} (via chat)";
        var error = pendingChange.Kind switch
        {
            "notifications" => await ApplyNotifications(dataContext, details, actor),
            "acknowledge_finding" => await AnalystAssessment.Acknowledge(dataContext, ReadLong(details, "finding_id"), actor) ? null : "That finding was not found.",
            "learning_hours" => await ApplyLearningHours(dataContext, details, actor),
            "block" => await ApplyBlock(dataContext, details, actor),
            "unblock" => await ResponseAction.Revoke(dataContext, ReadLong(details, "block_id"), actor) ? null : "That block was not found or is no longer active.",
            "protection" => await ApplyProtection(dataContext, details, actor),
            "watch" => Join(await SetupChoices.ChooseInterfaces(dataContext, ReadStrings(details, "interface_names"), actor)),
            _ => "Unknown change."
        };

        await PendingChange.MarkResolved(dataContext, id, error == null ? PendingChangeStatus.Applied : PendingChangeStatus.Failed, error);
        return error;
    }

    public static async Task Reject(DataContext dataContext, long id, long userId)
    {
        var pendingChange = await PendingChange.Get(dataContext, change => change.Id == id && change.UserId == userId);
        if (pendingChange?.Status == PendingChangeStatus.Proposed)
            await PendingChange.MarkResolved(dataContext, id, PendingChangeStatus.Rejected);
    }

    private static async Task<(string, string?, string?)> DescribeNotifications(DataContext dataContext, JsonElement details)
    {
        var channel = ReadString(details, "channel");
        var enabled = ReadBool(details, "enabled");
        var severityText = ReadString(details, "minimum_severity");
        if (channel is not ("email" or "webhook" or "desktop"))
            return (string.Empty, null, "The channel must be email, webhook or desktop.");

        if (severityText.Length > 0 && !Enum.TryParse<AlertSeverity>(severityText, true, out _))
            return (string.Empty, null, "The minimum severity must be Low, Medium, High or Critical.");

        var notificationSettings = await Setting.Load<NotificationSettings>(dataContext);
        if (enabled && channel == "email" && (string.IsNullOrWhiteSpace(notificationSettings.SmtpHost) || notificationSettings.EmailTo.Count == 0))
            return (string.Empty, null, "Email isn't set up yet. The mail server and recipients have to be entered on the Settings page first.");

        if (enabled && channel == "webhook" && !notificationSettings.HasWebhookUrl)
            return (string.Empty, null, "No webhook address is saved yet. It has to be entered on the Settings page first.");

        var severityPart = severityText.Length > 0 ? $" for {severityText} alerts and above" : string.Empty;
        return ($"{(enabled ? "Turn on" : "Turn off")} {channel} notifications{severityPart}.", null, null);
    }

    private static async Task<string?> ApplyNotifications(DataContext dataContext, JsonElement details, string actor)
    {
        var notificationSettings = await Setting.Load<NotificationSettings>(dataContext);
        var enabled = ReadBool(details, "enabled");
        var hasSeverity = Enum.TryParse<AlertSeverity>(ReadString(details, "minimum_severity"), true, out var severity);

        switch (ReadString(details, "channel"))
        {
            case "email":
                notificationSettings.EmailEnabled = enabled;
                if (hasSeverity) notificationSettings.EmailMinimumSeverity = severity;
                break;
            case "webhook":
                notificationSettings.WebhookEnabled = enabled;
                if (hasSeverity) notificationSettings.WebhookMinimumSeverity = severity;
                break;
            default:
                notificationSettings.DesktopEnabled = enabled;
                if (hasSeverity) notificationSettings.DesktopMinimumSeverity = severity;
                break;
        }

        return Join(await Setting.Save(dataContext, notificationSettings, await Setting.GetRevision<NotificationSettings>(dataContext), actor));
    }

    private static async Task<(string, string?, string?)> DescribeAcknowledge(DataContext dataContext, JsonElement details)
    {
        var findingId = ReadLong(details, "finding_id");
        var finding = await AnalystAssessment.Get(dataContext, assessment => assessment.Id == findingId);
        return finding == null
            ? (string.Empty, null, "There is no finding with that number.")
            : ($"Mark the finding \"{finding.Title}\" as dealt with.", null, null);
    }

    private static (string, string?, string?) DescribeLearningHours(JsonElement details)
    {
        var hours = (int)ReadLong(details, "hours");
        return hours is < 0 or > 720
            ? (string.Empty, null, "The learning period must be between 0 and 720 hours.")
            : ($"Set the learning period to {hours} hours after ScoutWall first started.", "During learning, new programs and destinations are not treated as suspicious.", null);
    }

    private static async Task<string?> ApplyLearningHours(DataContext dataContext, JsonElement details, string actor)
    {
        var detectionSettings = await Setting.Load<DetectionSettings>(dataContext);
        detectionSettings.LearningPeriodHours = (int)ReadLong(details, "hours");
        return Join(await Setting.Save(dataContext, detectionSettings, await Setting.GetRevision<DetectionSettings>(dataContext), actor));
    }

    private static async Task<(string, string?, string?)> DescribeBlock(DataContext dataContext, JsonElement details)
    {
        var what = ReadString(details, "what");
        var target = ReadString(details, "target");
        var durationMinutes = (int)ReadLong(details, "duration_minutes");
        var actionType = what == "program" ? ResponseActionType.BlockProgram : ResponseActionType.BlockAddress;

        if (what is not ("address" or "program") || string.IsNullOrWhiteSpace(target))
            return (string.Empty, null, "Say whether to block an address or a program, and which one.");

        if (durationMinutes is < 0 or > 10080 || (durationMinutes > 0 && durationMinutes < 60))
            return (string.Empty, null, "A block lasts between 60 minutes and 7 days, or until removed (0).");

        if (what == "address" && !IPAddress.TryParse(target, out _))
            return (string.Empty, null, "That is not a valid IP address.");

        var enforcementSettings = await Setting.Load<EnforcementSettings>(dataContext);
        if (!enforcementSettings.Supports(actionType))
            return (string.Empty, null, enforcementSettings.Provider == EnforcementProvider.MonitorOnly
                ? "ScoutWall is set to only tell you about problems, so it cannot block anything. That can be changed on the Settings page."
                : $"{enforcementSettings.ProviderDisplayName} cannot do that kind of block.");

        var profile = what == "address" ? await IpAddressProfile.Get(dataContext, item => item.IpAddress == target) : null;
        var description = what == "address"
            ? $"Block the internet address {target}{(profile?.IspDisplay is { } owner ? $" ({owner}, {profile.LocationDisplay})" : string.Empty)}"
            : $"Stop the program {Path.GetFileName(target)} from sending data out (at {target})";
        var duration = durationMinutes == 0 ? "until you remove it" : durationMinutes < 1440 ? $"for {durationMinutes / 60} hours" : $"for {durationMinutes / 1440} days";
        return ($"{description}, {duration}, using {enforcementSettings.ProviderDisplayName}.", "Anything that relies on it will stop working while the block is in place.", null);
    }

    private static async Task<string?> ApplyBlock(DataContext dataContext, JsonElement details, string actor)
    {
        var actionType = ReadString(details, "what") == "program" ? ResponseActionType.BlockProgram : ResponseActionType.BlockAddress;
        return await ResponseAction.RequestManual(dataContext, actionType, ReadString(details, "target"), (int)ReadLong(details, "duration_minutes"), actor, null);
    }

    private static async Task<(string, string?, string?)> DescribeUnblock(DataContext dataContext, JsonElement details)
    {
        var blockId = ReadLong(details, "block_id");
        var responseAction = await ResponseAction.Get(dataContext, action => action.Id == blockId);
        return responseAction == null || !(responseAction.IsDesired || responseAction.Status == ResponseActionStatus.Simulated)
            ? (string.Empty, null, "There is no active block with that number.")
            : ($"Remove the block on {responseAction.Target} ({responseAction.Reason}).", null, null);
    }

    private static (string, string?, string?) DescribeProtection(JsonElement details)
    {
        return ReadString(details, "choice") switch
        {
            "just_tell_me" => ("Change protection to: just tell me. ScoutWall will stop blocking anything on its own.", null, null),
            "block_automatically" => ("Change protection to: block threats automatically.", "Practice mode, if on, stays on until you turn it off in Settings.", null),
            "block_while_away" => ("Change protection to: block programs that send data while you're away.", "Practice mode, if on, stays on until you turn it off in Settings.", null),
            "slow_it_down" => ("Change protection to: slow suspicious uploads down instead of blocking.", null, null),
            _ => (string.Empty, null, "Choose just_tell_me, block_automatically, block_while_away or slow_it_down.")
        };
    }

    private static async Task<string?> ApplyProtection(DataContext dataContext, JsonElement details, string actor)
    {
        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        responseSettings.Mode = ReadString(details, "choice") switch
        {
            "block_automatically" => ResponseMode.Block,
            "block_while_away" => ResponseMode.BlockWhenIdle,
            "slow_it_down" => ResponseMode.Throttle,
            _ => ResponseMode.WatchAndAlert
        };
        return Join(await Setting.Save(dataContext, responseSettings, await Setting.GetRevision<ResponseSettings>(dataContext), actor));
    }

    private static async Task<(string, string?, string?)> DescribeWatch(DataContext dataContext, JsonElement details)
    {
        var interfaceNames = ReadStrings(details, "interface_names");
        if (interfaceNames.Count == 0)
            return ("Watch the connections this computer uses to reach the internet (automatic).", null, null);

        var interfaces = await CaptureInterface.GetAllOrdered(dataContext);
        var unknownNames = interfaceNames.Where(name => interfaces.All(item => item.Name != name)).ToList();
        if (unknownNames.Count > 0)
            return (string.Empty, null, "Some of those connections are not known. Use the names from list_interfaces.");

        var friendlyNames = interfaces.Where(item => interfaceNames.Contains(item.Name)).Select(item => item.DisplayName);
        return ($"Watch only: {string.Join(", ", friendlyNames)}.", "Traffic on other connections will not be seen.", null);
    }

    private static string? Join(List<string> errors)
    {
        return errors.Count == 0 ? null : string.Join(" ", errors);
    }

    private static string ReadString(JsonElement details, string name)
    {
        return details.ValueKind == JsonValueKind.Object && details.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()!.Trim()
            : string.Empty;
    }

    private static long ReadLong(JsonElement details, string name)
    {
        return details.ValueKind == JsonValueKind.Object && details.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number)
            ? number
            : -1;
    }

    private static bool ReadBool(JsonElement details, string name)
    {
        return details.ValueKind == JsonValueKind.Object && details.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.True;
    }

    private static List<string> ReadStrings(JsonElement details, string name)
    {
        return details.ValueKind == JsonValueKind.Object && details.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Array
            ? value.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).ToList()
            : [];
    }
}
