using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.ServiceProcess;
using System.Text.Json;
using Microsoft.Win32;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Response;

/// <summary>
/// Applies and reverses actions on this computer itself: disabling or removing scheduled tasks and stopping
/// services. New and revoked actions are handled on the next pass; actions in force are checked once a minute and
/// put back if something re-enabled the task, recreated it under the same name, or restarted the service.
/// </summary>
public class HostActionReconciler
{
    private static readonly TimeSpan DriftCheckInterval = TimeSpan.FromMinutes(1);
    private const int TaskCreateOrUpdate = 6;
    private const int TaskLogonNone = 0;
    private const int FileNotFound = unchecked((int)0x80070002);

    private readonly ILogger logger;
    private DateTime lastDriftCheck = DateTime.MinValue;

    public HostActionReconciler(ILogger logger)
    {
        this.logger = logger;
    }

    private record HostState(string? Backup, bool WasEnabled, string? StartType, bool Delayed, bool WasRunning, int Reenforced);

    public async Task Reconcile(DataContext dataContext)
    {
        if (!OperatingSystem.IsWindows())
            return;

        foreach (var responseAction in await ResponseAction.GetHostActionsToUndo(dataContext))
            await Undo(dataContext, responseAction);

        var checkDrift = DateTime.UtcNow - lastDriftCheck >= DriftCheckInterval;
        if (checkDrift)
            lastDriftCheck = DateTime.UtcNow;

        var actionsToApply = await ResponseAction.GetHostActionsToApply(dataContext);
        SystemHealth.ExecutionGuard.SetBlocked(actionsToApply
            .Where(action => action.ActionType == ResponseActionType.BlockExecution)
            .GroupBy(action => action.Target, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First().Id, StringComparer.OrdinalIgnoreCase));

        foreach (var responseAction in actionsToApply)
        {
            if (responseAction.ActionType == ResponseActionType.KillProgram)
            {
                await EndProgram(dataContext, responseAction);
                continue;
            }

            if (responseAction.Status == ResponseActionStatus.Pending || checkDrift)
                await Enforce(dataContext, responseAction);
        }
    }

    [SupportedOSPlatform("windows")]
    private async Task Enforce(DataContext dataContext, ResponseAction responseAction)
    {
        var isFirstApply = responseAction.Status == ResponseActionStatus.Pending;
        var state = Read(responseAction.HostState);
        try
        {
            var (changed, newState) = responseAction.ActionType switch
            {
                ResponseActionType.DisableScheduledTask => DisableTask(responseAction, state, isFirstApply),
                ResponseActionType.DeleteScheduledTask => DeleteTask(responseAction, state, isFirstApply),
                ResponseActionType.BlockExecution => BlockExecution(responseAction, state, isFirstApply),
                _ => StopService(responseAction, state, isFirstApply)
            };

            if (!isFirstApply && changed)
            {
                newState = newState with { Reenforced = newState.Reenforced + 1 };
                logger.LogWarning("{Action} on {Target} was undone by something else and has been applied again ({Count} times)",
                    responseAction.ActionLabel, responseAction.Target, newState.Reenforced);
            }

            if (isFirstApply || changed)
                await ResponseAction.SaveHostState(dataContext, responseAction.Id, JsonSerializer.Serialize(newState));

            if (isFirstApply)
            {
                await ResponseAction.MarkApplied(dataContext, responseAction.Id);
                logger.LogWarning("{Action}: {Target}", responseAction.ActionLabel, responseAction.Target);
            }
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or IOException)
        {
            logger.LogError(exception, "Could not apply {Action} on {Target}", responseAction.ActionLabel, responseAction.Target);
            if (isFirstApply)
                await ResponseAction.MarkFailed(dataContext, responseAction.Id, FriendlyError(exception));
        }
    }

    [SupportedOSPlatform("windows")]
    private async Task Undo(DataContext dataContext, ResponseAction responseAction)
    {
        var state = Read(responseAction.HostState);
        string? error = null;
        try
        {
            switch (responseAction.ActionType)
            {
                case ResponseActionType.DisableScheduledTask:
                    var task = FindTask(responseAction.Target);
                    if (task != null && state.WasEnabled)
                        task.Enabled = true;
                    break;

                case ResponseActionType.BlockExecution:
                    if (state.Backup == "deny-execute")
                        SystemHealth.ExecutionGuard.AllowExecute(responseAction.Target);
                    break;

                case ResponseActionType.DeleteScheduledTask:
                    if (state.Backup != null && File.Exists(state.Backup) && FindTask(responseAction.Target) == null)
                    {
                        dynamic scheduler = ConnectScheduler();
                        dynamic rootFolder = scheduler.GetFolder(@"\");
                        rootFolder.RegisterTask(responseAction.Target, File.ReadAllText(state.Backup), TaskCreateOrUpdate, null, null, TaskLogonNone, null);
                    }
                    else if (state.Backup == null)
                    {
                        error = "The task was already gone when it was removed, so there is nothing to restore.";
                    }
                    break;

                default:
                    RestoreService(responseAction.Target, state);
                    break;
            }

            logger.LogWarning("Undid {Action} on {Target}", responseAction.ActionLabel, responseAction.Target);
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception or IOException)
        {
            error = $"Could not undo: {FriendlyError(exception)}";
            logger.LogError(exception, "Could not undo {Action} on {Target}", responseAction.ActionLabel, responseAction.Target);
        }

        await ResponseAction.MarkUndone(dataContext, responseAction.Id, error);
    }

    /// <summary>
    /// Ending a program is a one-off: every running copy is ended and the action is complete.
    /// </summary>
    private async Task EndProgram(DataContext dataContext, ResponseAction responseAction)
    {
        var endedCount = SystemHealth.ExecutionGuard.EndAll(responseAction.Target);
        await ResponseAction.MarkCompleted(dataContext, responseAction.Id, JsonSerializer.Serialize(new { Ended = endedCount }));
        logger.LogWarning("Ended {Count} running copies of {Target}", endedCount, responseAction.Target);
    }

    /// <summary>
    /// Denies "execute" on the file to everyone, so Windows refuses to start it, and ends copies already running.
    /// The permission is checked every minute and put back if someone removed it.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static (bool Changed, HostState State) BlockExecution(ResponseAction responseAction, HostState state, bool isFirstApply)
    {
        if (!File.Exists(responseAction.Target))
        {
            if (isFirstApply)
                throw new InvalidOperationException("That program's file no longer exists.");

            return (false, state);
        }

        var changed = false;
        if (!SystemHealth.ExecutionGuard.HasDenyExecute(responseAction.Target))
        {
            SystemHealth.ExecutionGuard.DenyExecute(responseAction.Target);
            changed = true;
        }

        var endedCount = SystemHealth.ExecutionGuard.EndAll(responseAction.Target);
        return (changed || endedCount > 0, state with { Backup = "deny-execute" });
    }

    [SupportedOSPlatform("windows")]
    private static (bool Changed, HostState State) DisableTask(ResponseAction responseAction, HostState state, bool isFirstApply)
    {
        var task = FindTask(responseAction.Target)
            ?? (isFirstApply ? throw new InvalidOperationException("That scheduled task no longer exists.") : null);
        if (task == null)
            return (false, state);

        bool isEnabled = task.Enabled;
        var newState = isFirstApply ? state with { WasEnabled = isEnabled } : state;
        if (!isEnabled)
            return (false, newState);

        task.Enabled = false;
        return (true, newState);
    }

    /// <summary>
    /// Saves the task's definition so it can be put back, then deletes it. Only the exact same task path is removed
    /// again later; similar names are never touched.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static (bool Changed, HostState State) DeleteTask(ResponseAction responseAction, HostState state, bool isFirstApply)
    {
        var task = FindTask(responseAction.Target);
        if (task == null)
            return (false, state);

        var newState = state;
        if (isFirstApply)
        {
            var backupDirectory = Path.Combine(ScoutWall.Data.ScoutWallPaths.DataFolder, "backups", "tasks");
            Directory.CreateDirectory(backupDirectory);
            var backupPath = Path.Combine(backupDirectory, $"{responseAction.Id}.xml");
            File.WriteAllText(backupPath, (string)task.Xml);
            newState = state with { Backup = backupPath, WasEnabled = (bool)task.Enabled };
        }

        var (folderPath, taskName) = SplitTaskPath(responseAction.Target);
        dynamic scheduler = ConnectScheduler();
        dynamic folder = scheduler.GetFolder(folderPath);
        folder.DeleteTask(taskName, 0);
        return (true, newState);
    }

    [SupportedOSPlatform("windows")]
    private static (bool Changed, HostState State) StopService(ResponseAction responseAction, HostState state, bool isFirstApply)
    {
        using var service = new ServiceController(responseAction.Target);
        var newState = state;
        if (isFirstApply)
        {
            using var serviceKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{responseAction.Target}");
            newState = state with
            {
                StartType = service.StartType.ToString(),
                Delayed = serviceKey?.GetValue("DelayedAutostart") is int delayed && delayed == 1,
                WasRunning = service.Status is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending
            };
        }

        var changed = false;
        if (service.StartType != ServiceStartMode.Disabled)
        {
            RunServiceControl("config", responseAction.Target, "start=", "disabled");
            changed = true;
        }

        if (service.Status is not (ServiceControllerStatus.Stopped or ServiceControllerStatus.StopPending))
        {
            // Stops the services that depend on this one first, otherwise Windows refuses.
            service.Stop(stopDependentServices: true);
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
            changed = true;
        }

        return (changed, newState);
    }

    [SupportedOSPlatform("windows")]
    private static void RestoreService(string serviceName, HostState state)
    {
        var startType = state.StartType switch
        {
            nameof(ServiceStartMode.Automatic) => state.Delayed ? "delayed-auto" : "auto",
            nameof(ServiceStartMode.Disabled) => "disabled",
            nameof(ServiceStartMode.Boot) or nameof(ServiceStartMode.System) => null,
            _ => "demand"
        };

        if (startType != null)
            RunServiceControl("config", serviceName, "start=", startType);

        if (state.WasRunning)
        {
            using var service = new ServiceController(serviceName);
            if (service.Status == ServiceControllerStatus.Stopped)
                service.Start();
        }
    }

    /// <summary>
    /// Runs sc.exe with each argument passed separately, never through a shell.
    /// </summary>
    private static void RunServiceControl(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("sc.exe could not be started.");
        var output = process.StandardOutput.ReadToEnd();
        if (!process.WaitForExit(30_000))
            throw new InvalidOperationException("sc.exe did not finish in time.");

        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Windows refused the change (sc.exe {process.ExitCode}): {output.Trim()}");
    }

    [SupportedOSPlatform("windows")]
    private static dynamic ConnectScheduler()
    {
        var schedulerType = Type.GetTypeFromProgID("Schedule.Service") ?? throw new InvalidOperationException("The Task Scheduler is not available.");
        dynamic scheduler = Activator.CreateInstance(schedulerType)!;
        scheduler.Connect();
        return scheduler;
    }

    [SupportedOSPlatform("windows")]
    private static dynamic? FindTask(string taskPath)
    {
        try
        {
            var (folderPath, taskName) = SplitTaskPath(taskPath);
            dynamic scheduler = ConnectScheduler();
            dynamic folder = scheduler.GetFolder(folderPath);
            return folder.GetTask(taskName);
        }
        // The COM binder turns "not found" into FileNotFoundException or DirectoryNotFoundException, not COMException.
        catch (Exception exception) when (exception.HResult == FileNotFound || exception.HResult == unchecked((int)0x80070003))
        {
            return null;
        }
    }

    public static (string FolderPath, string TaskName) SplitTaskPath(string taskPath)
    {
        var lastSeparator = taskPath.LastIndexOf('\\');
        return lastSeparator <= 0 ? (@"\", taskPath.TrimStart('\\')) : (taskPath[..lastSeparator], taskPath[(lastSeparator + 1)..]);
    }

    private static HostState Read(string? json)
    {
        if (string.IsNullOrEmpty(json))
            return new HostState(null, true, null, false, false, 0);

        try
        {
            return JsonSerializer.Deserialize<HostState>(json) ?? new HostState(null, true, null, false, false, 0);
        }
        catch (JsonException)
        {
            return new HostState(null, true, null, false, false, 0);
        }
    }

    private static string FriendlyError(Exception exception)
    {
        return exception is UnauthorizedAccessException || exception.HResult == unchecked((int)0x80070005)
            ? "Windows denied access. The sensor must run as its installed service."
            : exception.Message;
    }
}
