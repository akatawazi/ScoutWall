using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum ResponseActionType
{
    BlockAddress = 1,
    BlockProgram = 2,
    ThrottleAddress = 3,
    ThrottleProgram = 4,
    IdleLockdown = 5,
    DisableScheduledTask = 6,
    DeleteScheduledTask = 7,
    StopService = 8,
    KillProgram = 9,
    BlockExecution = 10
}

public enum ResponseActionStatus
{
    Pending = 1,
    Active = 2,
    Simulated = 3,
    Expired = 4,
    Revoked = 5,
    Failed = 6
}

/// <summary>
/// A firewall block or throttle. This table is the desired state: the sensor reconciles Windows Firewall and
/// QoS policies against it, removing anything in the ScoutWall group that is not Pending or Active here.
/// </summary>
[Table("response_actions")]
[Index(nameof(Status))]
[Index(nameof(ActionType), nameof(Target), nameof(Status))]
public class ResponseAction : Repository<ResponseAction>
{
    public const string RuleGroup = "ScoutWall";
    public const string RuleNamePrefix = "ScoutWall ";

    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("action_type")]
    public ResponseActionType ActionType { get; set; }

    /// <summary>
    /// An IP address or CIDR range, or a full program path.
    /// </summary>
    [Column("target")]
    [MaxLength(512)]
    public string Target { get; set; } = string.Empty;

    [Column("block_inbound")]
    public bool BlockInbound { get; set; }

    [Column("block_outbound")]
    public bool BlockOutbound { get; set; }

    [Column("reason")]
    [MaxLength(512)]
    public string Reason { get; set; } = string.Empty;

    [Column("alert_id")]
    public long? AlertId { get; set; }

    [Column("status")]
    public ResponseActionStatus Status { get; set; }

    [Column("ends_when_user_returns")]
    public bool EndsWhenUserReturns { get; set; }

    [Column("created_at")]
    public DateTime CreatedAt { get; set; }

    [Column("created_by")]
    [MaxLength(256)]
    public string CreatedBy { get; set; } = string.Empty;

    [Column("expires_at")]
    public DateTime? ExpiresAt { get; set; }

    [Column("applied_at")]
    public DateTime? AppliedAt { get; set; }

    [Column("removed_at")]
    public DateTime? RemovedAt { get; set; }

    /// <summary>
    /// For actions on this computer (tasks, services): what is needed to undo them, such as the task's exported
    /// definition or the service's original start type, as JSON.
    /// </summary>
    [Column("host_state")]
    public string? HostState { get; set; }

    /// <summary>
    /// When a revoked or expired task or service action was reversed on the computer.
    /// </summary>
    [Column("undone_at")]
    public DateTime? UndoneAt { get; set; }

    [Column("last_error")]
    [MaxLength(1024)]
    public string? LastError { get; set; }

    [NotMapped]
    public string RuleName => $"{RuleNamePrefix}{Id} {ActionType}";

    [NotMapped]
    public bool IsDesired => Status is ResponseActionStatus.Pending or ResponseActionStatus.Active;

    /// <summary>
    /// Actions on this computer itself (scheduled tasks, services) rather than on network traffic. They are applied
    /// whatever firewall is chosen, and the kill switch leaves them alone, because undoing the removal of a
    /// malicious task would bring it back.
    /// </summary>
    [NotMapped]
    public bool IsHostAction => IsHostActionType(ActionType);

    public static readonly ResponseActionType[] HostActionTypes =
    [
        ResponseActionType.DisableScheduledTask, ResponseActionType.DeleteScheduledTask, ResponseActionType.StopService,
        ResponseActionType.KillProgram, ResponseActionType.BlockExecution
    ];

    public static bool IsHostActionType(ResponseActionType actionType)
    {
        return HostActionTypes.Contains(actionType);
    }

    [NotMapped]
    public string ActionLabel => ActionType switch
    {
        ResponseActionType.BlockAddress => "Block address",
        ResponseActionType.BlockProgram => "Block program",
        ResponseActionType.ThrottleAddress => "Slow address",
        ResponseActionType.ThrottleProgram => "Slow program",
        ResponseActionType.IdleLockdown => "Lock down while away",
        ResponseActionType.DisableScheduledTask => "Disable scheduled task",
        ResponseActionType.DeleteScheduledTask => "Remove scheduled task",
        ResponseActionType.KillProgram => "End program",
        ResponseActionType.BlockExecution => "Block from running",
        _ => "Stop service"
    };

    [NotMapped]
    public string StatusBadgeClass => Status switch
    {
        ResponseActionStatus.Active => "bg-danger",
        ResponseActionStatus.Pending => "bg-warning text-dark",
        ResponseActionStatus.Simulated => "bg-info text-dark",
        ResponseActionStatus.Failed => "bg-dark",
        _ => "bg-secondary"
    };

    /// <summary>
    /// Creates an action, or extends an identical one that is already in force.
    /// In dry-run mode the action is recorded as Simulated and never applied.
    /// </summary>
    public static async Task<ResponseAction> Request(DataContext dataContext, ResponseAction requestedAction, bool dryRun)
    {
        var existingAction = await Get(
            dataContext,
            action => action.ActionType == requestedAction.ActionType
                && action.Target == requestedAction.Target
                && (action.Status == ResponseActionStatus.Pending
                    || action.Status == ResponseActionStatus.Active
                    || action.Status == ResponseActionStatus.Simulated));

        if (existingAction != null)
        {
            existingAction.ExpiresAt = LaterOf(existingAction.ExpiresAt, requestedAction.ExpiresAt);
            existingAction.BlockInbound |= requestedAction.BlockInbound;
            existingAction.BlockOutbound |= requestedAction.BlockOutbound;

            // A real request turns a dry-run record into an action that is actually applied.
            if (!dryRun && existingAction.Status == ResponseActionStatus.Simulated)
            {
                existingAction.Status = ResponseActionStatus.Pending;
                existingAction.CreatedBy = requestedAction.CreatedBy;
                existingAction.Reason = requestedAction.Reason;
            }

            return await Update(dataContext, existingAction);
        }

        requestedAction.Status = dryRun ? ResponseActionStatus.Simulated : ResponseActionStatus.Pending;
        requestedAction.CreatedAt = DateTime.UtcNow;
        return await Insert(dataContext, requestedAction);
    }

    /// <summary>
    /// A block or throttle requested by a person from the web interface. Manual actions are always applied,
    /// even in dry-run mode, because someone explicitly asked for them. Returns an error or null.
    /// </summary>
    public static async Task<string?> RequestManual(
        DataContext dataContext,
        ResponseActionType actionType,
        string? target,
        int durationMinutes,
        string userEmail,
        string? requesterAddress,
        bool inboundOnly = false)
    {
        target ??= string.Empty;
        if (IsHostActionType(actionType))
            return await RequestHostAction(dataContext, actionType, target.Trim(), userEmail);

        var isProgramAction = actionType is ResponseActionType.BlockProgram or ResponseActionType.ThrottleProgram;
        if (isProgramAction)
            target = ProtectedPrograms.Normalize(target) ?? target;

        var validationError = ValidateManualTarget(actionType, target, inboundOnly)
            ?? await ValidateAgainstPolicy(dataContext, actionType, target.Trim(), requesterAddress);
        if (validationError != null)
            return validationError;

        var requestedAction = new ResponseAction
        {
            ActionType = actionType,
            Target = target.Trim(),
            BlockInbound = actionType == ResponseActionType.BlockAddress,
            BlockOutbound = !inboundOnly,
            Reason = inboundOnly ? $"Manual incoming block by {userEmail}" : $"Manual {actionType} by {userEmail}",
            CreatedBy = userEmail,
            ExpiresAt = durationMinutes > 0 ? DateTime.UtcNow.AddMinutes(durationMinutes) : null
        };

        await Request(dataContext, requestedAction, dryRun: false);
        await AuditEntry.Record(dataContext, userEmail, $"Manual {actionType}", requestedAction.Target, new { durationMinutes });
        return null;
    }

    /// <summary>
    /// Disabling or removing a scheduled task, or stopping a service. These work whatever firewall is chosen,
    /// because they act on the computer itself.
    /// </summary>
    private static async Task<string?> RequestHostAction(DataContext dataContext, ResponseActionType actionType, string target, string userEmail)
    {
        string? refusal;
        if (actionType is ResponseActionType.KillProgram or ResponseActionType.BlockExecution)
        {
            target = ProtectedPrograms.Normalize(target) ?? target;
            var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
            refusal = (actionType == ResponseActionType.BlockExecution ? ProtectedPrograms.ReasonNotBlockableFromRunning(target) : ProtectedPrograms.ReasonNotBlockable(target))
                ?? (responseSettings.IsAllowlistedProgram(target) ? "That program is on the never-block allowlist." : null);
        }
        else if (actionType == ResponseActionType.StopService)
        {
            var service = await SystemService.Get(dataContext, item => item.ServiceName == target && item.RemovedAt == null);
            refusal = service == null
                ? "ScoutWall doesn't know a service by that name. It may already be gone."
                : HostTargets.ReasonServiceNotActionable(service.ServiceName, service.BinaryPath);
        }
        else
        {
            refusal = HostTargets.ReasonTaskNotActionable(target, deleting: actionType == ResponseActionType.DeleteScheduledTask);
        }

        if (refusal != null)
            return refusal;

        // Removing a task that is only disabled replaces the disable, so there is one action per task. Ending a
        // program is a one-off and never replaces a block.
        var existing = actionType == ResponseActionType.KillProgram
            ? []
            : await GetAll(dataContext, action => action.Target == target
                && (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active)
                && action.ActionType != ResponseActionType.KillProgram
                && HostActionTypes.Contains(action.ActionType));
        if (existing.Any(action => action.ActionType == actionType))
            return null;

        foreach (var superseded in existing)
            await Revoke(dataContext, superseded.Id, userEmail);

        var requestedAction = new ResponseAction
        {
            ActionType = actionType,
            Target = target,
            Reason = $"Manual {actionType} by {userEmail}",
            CreatedBy = userEmail
        };

        await Request(dataContext, requestedAction, dryRun: false);
        await AuditEntry.Record(dataContext, userEmail, $"Manual {actionType}", target, new { });
        return null;
    }

    public static async Task<List<ResponseAction>> GetHostActionsToApply(DataContext dataContext)
    {
        return await GetAll(dataContext, action => HostActionTypes.Contains(action.ActionType)
            && (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active));
    }

    public static async Task<List<ResponseAction>> GetHostActionsToUndo(DataContext dataContext)
    {
        return await GetAll(dataContext, action => HostActionTypes.Contains(action.ActionType)
            && (action.Status == ResponseActionStatus.Revoked || action.Status == ResponseActionStatus.Expired)
            && action.AppliedAt != null
            && action.UndoneAt == null);
    }

    public static async Task SaveHostState(DataContext dataContext, long id, string hostState)
    {
        await dataContext.ResponseActions.Where(action => action.Id == id)
            .ExecuteUpdateAsync(setters => setters.SetProperty(action => action.HostState, hostState));
    }

    /// <summary>
    /// For one-off actions such as ending a program: done, with nothing left to keep in force or undo.
    /// </summary>
    public static async Task MarkCompleted(DataContext dataContext, long id, string hostState)
    {
        var now = DateTime.UtcNow;
        await dataContext.ResponseActions.Where(action => action.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Expired)
                .SetProperty(action => action.AppliedAt, now)
                .SetProperty(action => action.RemovedAt, now)
                .SetProperty(action => action.UndoneAt, now)
                .SetProperty(action => action.HostState, hostState));
    }

    /// <summary>
    /// Everything ScoutWall is currently blocking, disabling or slowing down, for the blocked-items list.
    /// </summary>
    public static async Task<List<ResponseAction>> GetInForce(DataContext dataContext)
    {
        return await Query(dataContext)
            .Where(action => action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active)
            .OrderByDescending(action => action.CreatedAt)
            .ToListAsync();
    }

    public static async Task MarkUndone(DataContext dataContext, long id, string? error)
    {
        await dataContext.ResponseActions.Where(action => action.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.UndoneAt, DateTime.UtcNow)
                .SetProperty(action => action.LastError, error));
    }

    private static string? ValidateManualTarget(ResponseActionType actionType, string target, bool inboundOnly)
    {
        if (string.IsNullOrWhiteSpace(target))
            return "A target is required.";

        var isAddressAction = actionType is ResponseActionType.BlockAddress or ResponseActionType.ThrottleAddress;
        if (isAddressAction && !System.Net.IPAddress.TryParse(target.Trim(), out _))
            return "Enter a single IP address.";

        // A local device may be kept from reaching this computer (incoming only), never cut off entirely: that could
        // break this computer's own access to the network. The gateway and DNS servers are refused separately.
        var isIncomingOnlyLocalBlock = inboundOnly && actionType == ResponseActionType.BlockAddress;
        if (isAddressAction && IsPrivateAddress(target.Trim()) && !isIncomingOnlyLocalBlock)
            return "Private and local addresses cannot be blocked from here; it could cut this machine off its own network.";

        if (actionType == ResponseActionType.IdleLockdown)
            return "Idle lockdown is controlled by the response mode.";

        return isAddressAction ? null : ProtectedPrograms.ReasonNotBlockable(target);
    }

    private static async Task<string?> ValidateAgainstPolicy(DataContext dataContext, ResponseActionType actionType, string target, string? requesterAddress)
    {
        var enforcementSettings = await Setting.Load<EnforcementSettings>(dataContext);
        if (!enforcementSettings.Supports(actionType))
            return enforcementSettings.Provider == EnforcementProvider.MonitorOnly
                ? "ScoutWall is set to only tell you about problems. Choose a firewall in Settings to block things."
                : $"{enforcementSettings.ProviderDisplayName} cannot do that kind of block.";

        var responseSettings = await Setting.Load<ResponseSettings>(dataContext);
        var isAddressAction = actionType is ResponseActionType.BlockAddress or ResponseActionType.ThrottleAddress;

        if (!isAddressAction)
        {
            return responseSettings.IsAllowlistedProgram(target) ? "That program is on the never-block allowlist." : null;
        }

        var address = System.Net.IPAddress.Parse(target);
        if (requesterAddress != null && System.Net.IPAddress.TryParse(requesterAddress, out var requester) && requester.Equals(address))
            return "That is the address you are connected from; blocking it would lock you out.";

        if (HostNetwork.ProtectedAddresses().Contains(address))
            return "That address is this computer, its gateway or one of its DNS servers.";

        var isAllowlistedAddress = responseSettings.AllowlistedAddresses.Any(entry => HostNetwork.RangeContains(entry, address));
        return isAllowlistedAddress ? "That address is on the never-block allowlist." : null;
    }

    public static bool IsPrivateAddress(string target)
    {
        var address = System.Net.IPAddress.Parse(target);
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        // Multicast never leaves the local network (ff02:: is link-local service discovery, for example).
        if (System.Net.IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal || address.IsIPv6UniqueLocal || address.IsIPv6SiteLocal
            || address.IsIPv6Multicast)
            return true;

        var bytes = address.GetAddressBytes();
        if (bytes.Length != 4)
            return false;

        return bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254)
            || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
            || bytes[0] >= 224;
    }

    /// <summary>
    /// Marks everything in force as pending again, so it is applied on a newly chosen enforcement point.
    /// </summary>
    public static async Task<int> QueueForReapply(DataContext dataContext)
    {
        return await dataContext.ResponseActions
            .Where(action => action.Status == ResponseActionStatus.Active)
            .ExecuteUpdateAsync(setters => setters.SetProperty(action => action.Status, ResponseActionStatus.Pending));
    }

    /// <summary>
    /// Network actions in force or waiting to be applied. Task and service actions are handled separately.
    /// </summary>
    public static async Task<List<ResponseAction>> GetDesired(DataContext dataContext)
    {
        return await GetAll(
            dataContext,
            action => (action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active)
                && !HostActionTypes.Contains(action.ActionType));
    }

    public static async Task<int> CountActive(DataContext dataContext)
    {
        return await Count(
            dataContext,
            action => action.Status == ResponseActionStatus.Pending || action.Status == ResponseActionStatus.Active);
    }

    public static async Task<List<ResponseAction>> GetRecent(DataContext dataContext, int count)
    {
        return await Query(dataContext)
            .OrderBy(action => action.Status == ResponseActionStatus.Active || action.Status == ResponseActionStatus.Pending ? 0 : 1)
            .ThenByDescending(action => action.CreatedAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> ExpireDue(DataContext dataContext, DateTime now)
    {
        return await dataContext.ResponseActions
            .Where(action => (action.Status == ResponseActionStatus.Pending
                    || action.Status == ResponseActionStatus.Active
                    || action.Status == ResponseActionStatus.Simulated)
                && action.ExpiresAt != null
                && action.ExpiresAt <= now)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Expired)
                .SetProperty(action => action.RemovedAt, now));
    }

    /// <summary>
    /// Ends everything that only applies while nobody is at the machine.
    /// </summary>
    public static async Task<int> EndIdleActions(DataContext dataContext, DateTime now)
    {
        return await dataContext.ResponseActions
            .Where(action => action.EndsWhenUserReturns
                && (action.Status == ResponseActionStatus.Pending
                    || action.Status == ResponseActionStatus.Active
                    || action.Status == ResponseActionStatus.Simulated))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Expired)
                .SetProperty(action => action.RemovedAt, now));
    }

    public static async Task MarkApplied(DataContext dataContext, long id)
    {
        await dataContext.ResponseActions
            .Where(action => action.Id == id && action.Status == ResponseActionStatus.Pending)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Active)
                .SetProperty(action => action.AppliedAt, DateTime.UtcNow)
                .SetProperty(action => action.LastError, (string?)null));
    }

    public static async Task MarkFailed(DataContext dataContext, long id, string error)
    {
        var truncatedError = error.Length > 1000 ? error[..1000] : error;
        await dataContext.ResponseActions
            .Where(action => action.Id == id)
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Failed)
                .SetProperty(action => action.LastError, truncatedError));
    }

    public static async Task<bool> Revoke(DataContext dataContext, long id, string userEmail)
    {
        var responseAction = await Get(dataContext, action => action.Id == id);
        if (responseAction == null || !(responseAction.IsDesired || responseAction.Status == ResponseActionStatus.Simulated))
            return false;

        responseAction.Status = ResponseActionStatus.Revoked;
        responseAction.RemovedAt = DateTime.UtcNow;
        await Update(dataContext, responseAction);
        await AuditEntry.Record(dataContext, userEmail, "Response action revoked", responseAction.RuleName, new { responseAction.Target });
        return true;
    }

    /// <summary>
    /// The kill switch. The sensor removes every ScoutWall firewall rule on its next reconcile pass.
    /// </summary>
    public static async Task<int> RevokeAll(DataContext dataContext, string userEmail, bool includeHostActions = false)
    {
        var revokedCount = await dataContext.ResponseActions
            .Where(action => (action.Status == ResponseActionStatus.Pending
                    || action.Status == ResponseActionStatus.Active
                    || action.Status == ResponseActionStatus.Simulated)
                && (includeHostActions || !HostActionTypes.Contains(action.ActionType)))
            .ExecuteUpdateAsync(setters => setters
                .SetProperty(action => action.Status, ResponseActionStatus.Revoked)
                .SetProperty(action => action.RemovedAt, DateTime.UtcNow));

        await AuditEntry.Record(dataContext, userEmail, "All response actions revoked", "Firewall", new { revokedCount });
        return revokedCount;
    }

    private static DateTime? LaterOf(DateTime? first, DateTime? second)
    {
        if (first == null || second == null)
            return null;

        return first > second ? first : second;
    }
}
