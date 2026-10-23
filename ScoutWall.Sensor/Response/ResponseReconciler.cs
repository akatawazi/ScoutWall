using System.Net;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Workers;

namespace ScoutWall.Sensor.Response;

/// <summary>
/// Makes Windows Firewall and QoS match the response_actions table. Anything in the ScoutWall group that is
/// not desired is removed, and anything desired but missing is added. Because the table is the source of truth,
/// a crash, a manual rule deletion or the web kill switch all converge on the next pass.
/// </summary>
public class ResponseReconciler
{
    private static readonly TimeSpan FullRefreshInterval = TimeSpan.FromSeconds(30);

    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger logger;
    private HashSet<string> firewallRuleNames = [];
    private HashSet<string> qosPolicyNames = [];
    private DateTime lastFullRefresh = DateTime.MinValue;
    private bool qosListingFailed;
    private bool throttleActionsDesired;

    public ResponseReconciler(SensorRuntime sensorRuntime, ILogger logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    private const string ActiveProviderKey = "enforcement_active_provider";

    public async Task Reconcile(DataContext dataContext)
    {
        var enforcementSettings = sensorRuntime.Configuration.Enforcement;
        await HandleProviderSwitch(dataContext, enforcementSettings);
        var desiredActions = await ResponseAction.GetDesired(dataContext);

        switch (enforcementSettings.Provider)
        {
            case EnforcementProvider.MonitorOnly:
                await FailAll(dataContext, desiredActions, "ScoutWall is set to only tell you about problems, so nothing is blocked. Choose a firewall under Settings to enforce blocks.");
                return;
            case EnforcementProvider.Webhook:
                await WebhookEnforcer.Reconcile(dataContext, enforcementSettings, desiredActions, logger);
                return;
            default:
                await ReconcileWindows(dataContext, desiredActions);
                return;
        }
    }

    /// <summary>
    /// When the enforcement point changes, the old one's rules are removed first and everything still wanted is
    /// queued to be applied again on the new one, so no block is left behind on a firewall nobody watches.
    /// </summary>
    private async Task HandleProviderSwitch(DataContext dataContext, EnforcementSettings enforcementSettings)
    {
        var activeProviderText = await SystemState.GetValue(dataContext, ActiveProviderKey);
        var currentProvider = enforcementSettings.Provider.ToString();
        if (activeProviderText == currentProvider)
            return;

        if (Enum.TryParse<EnforcementProvider>(activeProviderText, out var previousProvider))
        {
            var removedCount = await RemoveAllFor(dataContext, previousProvider, enforcementSettings);
            logger.LogWarning("Enforcement moved from {Previous} to {Current}; removed {Count} old rules", previousProvider, currentProvider, removedCount);
            await ResponseAction.QueueForReapply(dataContext);
        }

        await SystemState.SetValue(dataContext, ActiveProviderKey, currentProvider);
    }

    private async Task<int> RemoveAllFor(DataContext dataContext, EnforcementProvider provider, EnforcementSettings enforcementSettings)
    {
        if (provider == EnforcementProvider.Webhook)
            return await WebhookEnforcer.RemoveAll(dataContext, enforcementSettings, logger);

        if (provider != EnforcementProvider.WindowsFirewall || !OperatingSystem.IsWindows() || !WindowsFirewall.IsAdministrator())
            return 0;

        firewallRuleNames.Clear();
        qosPolicyNames.Clear();
        lastFullRefresh = DateTime.MinValue;
        return WindowsFirewall.RemoveAllRules();
    }

    private async Task ReconcileWindows(DataContext dataContext, List<ResponseAction> desiredActions)
    {
        if (!OperatingSystem.IsWindows() || !WindowsFirewall.IsAdministrator())
        {
            await FailAll(dataContext, desiredActions, "The sensor must run as administrator on Windows to change the firewall.");
            return;
        }

        throttleActionsDesired = desiredActions.Any(action => action.ActionType is ResponseActionType.ThrottleAddress or ResponseActionType.ThrottleProgram);
        RefreshExistingNames();
        RemoveUndesired(desiredActions);

        foreach (var responseAction in desiredActions)
            await Apply(dataContext, responseAction);
    }

    private void RefreshExistingNames()
    {
        if (!OperatingSystem.IsWindows() || DateTime.UtcNow - lastFullRefresh < FullRefreshInterval)
            return;

        firewallRuleNames = WindowsFirewall.GetRuleNames();
        qosPolicyNames = qosListingFailed && !HasThrottleActions() ? [] : TryGetQosPolicyNames();
        lastFullRefresh = DateTime.UtcNow;
    }

    private HashSet<string> TryGetQosPolicyNames()
    {
        try
        {
            return OperatingSystem.IsWindows() ? WindowsQualityOfService.GetPolicyNames() : [];
        }
        catch (InvalidOperationException exception)
        {
            if (!qosListingFailed)
                logger.LogWarning("Windows QoS policies cannot be listed, so throttling may not work on this computer: {Message}", exception.Message);

            qosListingFailed = true;
            return [];
        }
    }

    private bool HasThrottleActions()
    {
        return throttleActionsDesired;
    }

    private void RemoveUndesired(List<ResponseAction> desiredActions)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var desiredNames = desiredActions.SelectMany(GetRuleNames).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var ruleName in firewallRuleNames.Where(name => !desiredNames.Contains(name) && !DecoyRules.IsOwnedRule(name)).ToList())
        {
            WindowsFirewall.RemoveRule(ruleName);
            firewallRuleNames.Remove(ruleName);
            logger.LogInformation("Removed firewall rule {RuleName}", ruleName);
        }

        foreach (var policyName in qosPolicyNames.Where(name => !desiredNames.Contains(name)).ToList())
        {
            WindowsQualityOfService.RemovePolicy(policyName);
            qosPolicyNames.Remove(policyName);
            logger.LogInformation("Removed QoS policy {PolicyName}", policyName);
        }
    }

    private async Task Apply(DataContext dataContext, ResponseAction responseAction)
    {
        try
        {
            if (OperatingSystem.IsWindows())
                ApplyOnWindows(responseAction);

            if (responseAction.Status == ResponseActionStatus.Pending)
            {
                await ResponseAction.MarkApplied(dataContext, responseAction.Id);
                logger.LogWarning("Applied {RuleName} against {Target}: {Reason}", responseAction.RuleName, responseAction.Target, responseAction.Reason);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException or ArgumentException)
        {
            logger.LogError(exception, "Could not apply {RuleName}", responseAction.RuleName);
            await ResponseAction.MarkFailed(dataContext, responseAction.Id, exception.Message);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void ApplyOnWindows(ResponseAction responseAction)
    {
        var description = $"Added by ScoutWall: {responseAction.Reason}";
        EnsureTargetIsAllowed(responseAction);
        var throttleBitsPerSecond = sensorRuntime.Configuration.Response.ThrottleKilobitsPerSecond * 1000L;

        switch (responseAction.ActionType)
        {
            case ResponseActionType.BlockAddress:
                if (responseAction.BlockInbound)
                    AddFirewallRule(InboundName(responseAction), description, false, responseAction.Target, null);
                if (responseAction.BlockOutbound)
                    AddFirewallRule(OutboundName(responseAction), description, true, responseAction.Target, null);
                break;

            case ResponseActionType.BlockProgram:
                AddFirewallRule(OutboundName(responseAction), description, true, null, responseAction.Target);
                break;

            case ResponseActionType.IdleLockdown:
                AddFirewallRule(OutboundName(responseAction), description, true, ResponsePlanner.BuildPublicInternetRanges(sensorRuntime), null);
                break;

            case ResponseActionType.ThrottleAddress:
                if (qosPolicyNames.Add(responseAction.RuleName))
                    WindowsQualityOfService.AddAddressThrottle(responseAction.RuleName, IPAddress.Parse(responseAction.Target), throttleBitsPerSecond);
                break;

            case ResponseActionType.ThrottleProgram:
                if (qosPolicyNames.Add(responseAction.RuleName))
                    WindowsQualityOfService.AddProgramThrottle(responseAction.RuleName, responseAction.Target, throttleBitsPerSecond);
                break;
        }
    }

    /// <summary>
    /// Last line of defence for every action, including manual ones and rows written straight into the
    /// database: never block this machine, its networks, gateways, DNS servers or anything allowlisted.
    /// </summary>
    private void EnsureTargetIsAllowed(ResponseAction responseAction)
    {
        var isAddressAction = responseAction.ActionType is ResponseActionType.BlockAddress or ResponseActionType.ThrottleAddress;
        if (isAddressAction && (!IPAddress.TryParse(responseAction.Target, out var address) || ResponsePlanner.IsUntouchable(sensorRuntime, address)))
            throw new InvalidOperationException($"{responseAction.Target} is a local, gateway, DNS or allowlisted address and will not be blocked.");

        var isProgramAction = responseAction.ActionType is ResponseActionType.BlockProgram or ResponseActionType.ThrottleProgram;
        if (isProgramAction && sensorRuntime.IsAllowlistedProgram(responseAction.Target))
            throw new InvalidOperationException($"{responseAction.Target} is on the program allowlist and will not be blocked.");

        var protectedReason = isProgramAction ? ProtectedPrograms.ReasonNotBlockable(responseAction.Target) : null;
        if (protectedReason != null)
            throw new InvalidOperationException($"{responseAction.Target} will not be blocked. {protectedReason}");
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private void AddFirewallRule(string ruleName, string description, bool isOutbound, string? remoteAddresses, string? applicationPath)
    {
        if (firewallRuleNames.Contains(ruleName))
            return;

        WindowsFirewall.AddBlockRule(ruleName, description, isOutbound, remoteAddresses, applicationPath);
        firewallRuleNames.Add(ruleName);
    }

    private static IEnumerable<string> GetRuleNames(ResponseAction responseAction)
    {
        return responseAction.ActionType switch
        {
            ResponseActionType.BlockAddress => new[]
            {
                responseAction.BlockInbound ? InboundName(responseAction) : null,
                responseAction.BlockOutbound ? OutboundName(responseAction) : null
            }.OfType<string>(),
            ResponseActionType.ThrottleAddress or ResponseActionType.ThrottleProgram => [responseAction.RuleName],
            _ => [OutboundName(responseAction)]
        };
    }

    private static string InboundName(ResponseAction responseAction) => $"{responseAction.RuleName} In";

    private static string OutboundName(ResponseAction responseAction) => $"{responseAction.RuleName} Out";

    private static async Task FailAll(DataContext dataContext, List<ResponseAction> desiredActions, string reason)
    {
        foreach (var responseAction in desiredActions.Where(action => action.Status == ResponseActionStatus.Pending))
            await ResponseAction.MarkFailed(dataContext, responseAction.Id, reason);
    }
}
