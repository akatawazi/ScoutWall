using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

public enum HostTargetKind
{
    ScheduledTask = 1,
    Service = 2,
    Program = 3
}

/// <summary>
/// One scheduled task or service an alert is about, with what can be done to it and what has been done already.
/// </summary>
public class HostActionTarget
{
    public HostTargetKind Kind { get; set; }
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Why nothing can be done, or null when it can.
    /// </summary>
    public string? Refusal { get; set; }

    /// <summary>
    /// Why the task can be disabled but not removed, or null when removing is allowed.
    /// </summary>
    public string? RemoveRefusal { get; set; }

    /// <summary>
    /// The latest action on this target, whatever its state.
    /// </summary>
    public ResponseAction? LatestAction { get; set; }

    public bool IsInForce => LatestAction?.IsDesired == true;
    public bool HasFailed => LatestAction?.Status == ResponseActionStatus.Failed;

    public string ShortName => Kind is HostTargetKind.ScheduledTask or HostTargetKind.Program ? Name[(Name.LastIndexOf('\\') + 1)..] : Name;

    public string StateText => LatestAction switch
    {
        { Status: ResponseActionStatus.Pending } => "Being applied…",
        { ActionType: ResponseActionType.DisableScheduledTask, Status: ResponseActionStatus.Active } => "Disabled",
        { ActionType: ResponseActionType.DeleteScheduledTask, Status: ResponseActionStatus.Active } => "Removed",
        { ActionType: ResponseActionType.StopService, Status: ResponseActionStatus.Active } => "Stopped and disabled",
        { ActionType: ResponseActionType.BlockExecution, Status: ResponseActionStatus.Active } => "Blocked from running",
        { Status: ResponseActionStatus.Failed } action => $"Couldn't do it: {action.LastError}",
        _ => string.Empty
    };
}

/// <summary>
/// The scheduled tasks and services behind an event-log alert, so the alert can offer to disable, remove or stop them.
/// </summary>
public static class HostActionOptions
{
    private const int MaximumTargets = 10;

    public static async Task<List<HostActionTarget>> Build(DataContext dataContext, Alert alert)
    {
        if (!alert.IsHostEvent || string.IsNullOrEmpty(alert.Subject))
            return [];

        var targets = alert.RuleName switch
        {
            "NewScheduledTask" => await TasksFor(dataContext, alert.Subject),
            "NewService" or "ServiceCrashLoop" => await ServiceFor(dataContext, alert.Subject),
            "MassFileChange" or "FileExtensionRenames" => ProgramFor(alert.ProcessPath),
            _ => []
        };

        if (targets.Count == 0)
            return targets;

        var names = targets.Select(target => target.Name).ToList();
        var actions = await ResponseAction.GetAll(dataContext, action => names.Contains(action.Target)
            && (action.ActionType == ResponseActionType.DisableScheduledTask
                || action.ActionType == ResponseActionType.DeleteScheduledTask
                || action.ActionType == ResponseActionType.StopService
                || action.ActionType == ResponseActionType.BlockExecution));
        foreach (var target in targets)
        {
            target.LatestAction = actions.Where(action => action.Target == target.Name)
                .OrderByDescending(action => action.Id)
                .FirstOrDefault(action => action.Status is ResponseActionStatus.Pending or ResponseActionStatus.Active or ResponseActionStatus.Failed);
        }

        return targets;
    }

    /// <summary>
    /// Task alerts cover one task or every task created in the same folder; each task is listed so it can be
    /// handled on its own.
    /// </summary>
    private static async Task<List<HostActionTarget>> TasksFor(DataContext dataContext, string subject)
    {
        var taskNames = await dataContext.SystemEvents
            .Where(systemEvent => systemEvent.EventId == 106 && systemEvent.Subject != null
                && (systemEvent.Subject == subject || systemEvent.Subject.StartsWith(subject)))
            .Select(systemEvent => systemEvent.Subject!)
            .Distinct()
            .Take(MaximumTargets)
            .ToListAsync();

        if (taskNames.Count == 0 && !subject.EndsWith('\\'))
            taskNames.Add(subject);

        return taskNames.Select(taskName => new HostActionTarget
        {
            Kind = HostTargetKind.ScheduledTask,
            Name = taskName,
            Refusal = HostTargets.ReasonTaskNotActionable(taskName, deleting: false),
            RemoveRefusal = HostTargets.ReasonTaskNotActionable(taskName, deleting: true)
        }).ToList();
    }

    /// <summary>
    /// The program behind a file-activity alert: it can be ended now (Refusal) and blocked from running (RemoveRefusal).
    /// </summary>
    private static List<HostActionTarget> ProgramFor(string? programPath)
    {
        if (string.IsNullOrEmpty(programPath) || !Path.IsPathRooted(programPath))
            return [];

        return
        [
            new HostActionTarget
            {
                Kind = HostTargetKind.Program,
                Name = programPath,
                Refusal = ProtectedPrograms.ReasonNotBlockable(programPath),
                RemoveRefusal = ProtectedPrograms.ReasonNotBlockableFromRunning(programPath)
            }
        ];
    }

    private static async Task<List<HostActionTarget>> ServiceFor(DataContext dataContext, string serviceName)
    {
        var service = await SystemService.Get(dataContext, item => item.ServiceName == serviceName);
        return
        [
            new HostActionTarget
            {
                Kind = HostTargetKind.Service,
                Name = serviceName,
                Refusal = service == null || service.RemovedAt != null
                    ? "That service is no longer installed."
                    : HostTargets.ReasonServiceNotActionable(service.ServiceName, service.BinaryPath)
            }
        ];
    }
}
