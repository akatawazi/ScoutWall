using System.Net;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Network;

namespace ScoutWall.Sensor.Response;

/// <summary>
/// Turns an alert into a block or throttle request according to the response mode in settings.
/// Never targets local, private, gateway or DNS addresses, or anything on the allowlists.
/// </summary>
public static class ResponsePlanner
{
    public const string SensorUser = "sensor";
    private static readonly TimeSpan IdleActionSafetyLimit = TimeSpan.FromHours(24);

    public static async Task<ResponseAction?> Plan(DataContext dataContext, SensorRuntime sensorRuntime, Alert alert)
    {
        // Event-log findings have no network target; they are reported, never acted on automatically.
        if (alert.IsHostEvent)
            return null;

        // A scanner that connected to a decoy port completed a real connection, so its address can't be forged:
        // it is blocked at once through the shared scanner blocklist, whatever the protection choice (local
        // devices are only reported). A port scan seen only as connection attempts (SYN packets) can come from a
        // forged address, so blocking it automatically would let anyone make ScoutWall block any address; those
        // are reported with a one-click block instead.
        if (alert.RuleName == "DecoyPortTouched")
        {
            await BlockScanner(dataContext, sensorRuntime, alert);
            return null;
        }

        if (alert.RuleName == "PortScan")
            return null;

        var responseSettings = sensorRuntime.Configuration.Response;
        if (responseSettings.Mode == ResponseMode.WatchAndAlert || alert.Severity < responseSettings.MinimumSeverity)
            return null;

        // External verdict engines are unevaluated; their alerts are for review only and never block.
        if (alert.RuleName == Workers.VerdictWorker.ZevRule)
            return null;

        // An internal name resolving to the internet is a DNS set-up problem. The address it resolves to is usually
        // the organisation's own public website, which must not be blocked for it.
        if (alert.RuleName == "InternalNameLeak")
            return null;

        var isIdleResponse = responseSettings.Mode == ResponseMode.BlockWhenIdle;
        if (isIdleResponse && sensorRuntime.Idle.IsIdle != true)
            return null;

        if (await ResponseAction.CountActive(dataContext) >= responseSettings.MaximumActiveActions)
            return null;

        var requestedAction = alert.ProcessPath != null
            ? PlanForProgram(sensorRuntime, alert, responseSettings)
            : PlanForAddress(sensorRuntime, alert, responseSettings);

        if (requestedAction == null)
            return null;

        // Only plan what the chosen enforcement point can actually do (a router webhook cannot block a program).
        if (!sensorRuntime.Configuration.Enforcement.Supports(requestedAction.ActionType))
            return null;

        requestedAction.AlertId = alert.Id;
        requestedAction.CreatedBy = SensorUser;
        requestedAction.EndsWhenUserReturns = isIdleResponse;
        requestedAction.ExpiresAt = isIdleResponse
            ? DateTime.UtcNow.Add(IdleActionSafetyLimit)
            : DateTime.UtcNow.AddMinutes(responseSettings.ActionDurationMinutes);

        return await ResponseAction.Request(dataContext, requestedAction, responseSettings.DryRun);
    }

    private static ResponseAction? PlanForProgram(SensorRuntime sensorRuntime, Alert alert, ResponseSettings responseSettings)
    {
        var processPath = alert.ProcessPath!;
        if (ProtectedPrograms.ReasonNotBlockable(processPath) != null || sensorRuntime.IsAllowlistedProgram(processPath))
            return null;

        var actionType = responseSettings.Mode == ResponseMode.Throttle ? ResponseActionType.ThrottleProgram : ResponseActionType.BlockProgram;
        return new ResponseAction
        {
            ActionType = actionType,
            Target = processPath,
            BlockOutbound = true,
            Reason = $"{alert.RuleName}: {alert.Title}"
        };
    }

    private static ResponseAction? PlanForAddress(SensorRuntime sensorRuntime, Alert alert, ResponseSettings responseSettings)
    {
        if (!IPAddress.TryParse(alert.SourceIp, out var sourceAddress) || IsUntouchable(sensorRuntime, sourceAddress))
            return null;

        var actionType = responseSettings.Mode == ResponseMode.Throttle ? ResponseActionType.ThrottleAddress : ResponseActionType.BlockAddress;
        return new ResponseAction
        {
            ActionType = actionType,
            Target = sourceAddress.ToString(),
            BlockInbound = true,
            BlockOutbound = responseSettings.BlockOutbound,
            Reason = $"{alert.RuleName}: {alert.Title}"
        };
    }

    public static async Task BlockScanner(DataContext dataContext, SensorRuntime sensorRuntime, Alert alert)
    {
        var detectionSettings = sensorRuntime.Configuration.Detection;
        if (!detectionSettings.BlockInternetScanners
            || !IPAddress.TryParse(alert.SourceIp, out var sourceAddress)
            || ResponseAction.IsPrivateAddress(alert.SourceIp)
            || IsUntouchable(sensorRuntime, sourceAddress))
            return;

        await ScannerBlock.Add(dataContext, sourceAddress.ToString(), $"{alert.RuleName}: {alert.Title}", TimeSpan.FromDays(detectionSettings.ScannerBlockDays));
    }

    public static bool ShouldWaitForAnalyst(SensorRuntime sensorRuntime, Alert alert)
    {
        var analystSettings = sensorRuntime.Configuration.Analyst;
        return analystSettings.IsReady && analystSettings.SoftAlertGraceMinutes > 0 && !alert.IsHardRule;
    }

    /// <summary>
    /// Plans responses for soft alerts whose grace period has passed and that the analyst did not clear.
    /// </summary>
    public static async Task<int> PlanDeferred(DataContext dataContext, SensorRuntime sensorRuntime)
    {
        var graceMinutes = sensorRuntime.Configuration.Analyst.SoftAlertGraceMinutes;
        var dueAlerts = await Alert.GetDueForResponse(dataContext, DateTime.UtcNow.AddMinutes(-graceMinutes));
        var plannedCount = 0;

        foreach (var alert in dueAlerts)
        {
            if (alert.Status == AlertStatus.Open && await Plan(dataContext, sensorRuntime, alert) != null)
                plannedCount++;

            await Alert.MarkResponseConsidered(dataContext, alert.Id);
        }

        return plannedCount;
    }

    public static bool IsUntouchable(SensorRuntime sensorRuntime, IPAddress address)
    {
        return sensorRuntime.NetworkClassifier.IsProtected(address) || sensorRuntime.IsAllowlistedAddress(address);
    }

    /// <summary>
    /// Every public IPv4 range outside the allowlist and protected addresses, as firewall range syntax,
    /// Used for the idle lockdown block rule; IPv4 only.
    /// </summary>
    public static string BuildPublicInternetRanges(SensorRuntime sensorRuntime)
    {
        var excludedRanges = IpNetwork.PrivateRanges
            .Concat(sensorRuntime.Configuration.Response.AllowlistedAddresses
                .Select(text => IpNetwork.TryParse(text, out var ipNetwork) ? ipNetwork : null)
                .OfType<IpNetwork>())
            .Concat(sensorRuntime.NetworkClassifier.ProtectedAddresses.Select(address => new IpNetwork(address, address.GetAddressBytes().Length * 8)))
            .Where(ipNetwork => ipNetwork.NetworkAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            .Select(ToRange)
            .OrderBy(range => range.Start)
            .ToList();

        var publicRanges = new List<string>();
        var nextStart = 0UL;

        foreach (var (start, end) in excludedRanges)
        {
            if (start > nextStart)
                publicRanges.Add($"{ToAddress(nextStart)}-{ToAddress(start - 1)}");

            nextStart = Math.Max(nextStart, end + 1);
        }

        if (nextStart <= uint.MaxValue)
            publicRanges.Add($"{ToAddress(nextStart)}-{ToAddress(uint.MaxValue)}");

        // IPv6 is left open: excluding IPv6 DNS servers and allowlist entries is not implemented yet, and
        // blocking 2000::/3 wholesale would cut off IPv6 name resolution.
        return string.Join(",", publicRanges);
    }

    private static (ulong Start, ulong End) ToRange(IpNetwork ipNetwork)
    {
        var bytes = ipNetwork.NetworkAddress.GetAddressBytes();
        var start = (ulong)((uint)bytes[0] << 24 | (uint)bytes[1] << 16 | (uint)bytes[2] << 8 | bytes[3]);
        var hostBits = 32 - ipNetwork.PrefixLength;
        start &= ~((1UL << hostBits) - 1) & uint.MaxValue;
        return (start, start + (1UL << hostBits) - 1);
    }

    private static string ToAddress(ulong value)
    {
        return new IPAddress([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value]).ToString();
    }
}
