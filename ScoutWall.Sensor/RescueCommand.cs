using Microsoft.Extensions.Configuration;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Response;

namespace ScoutWall.Sensor;

/// <summary>
/// "scoutwall rescue": removes every ScoutWall firewall rule and QoS policy, revokes the actions in the database so
/// they are not re-applied, and puts back the Windows audit settings read tracking changed. Works when the sensor
/// is stopped or broken. Run it from an elevated prompt.
/// "rescue --undo-host-actions" also reverses disabled or removed scheduled tasks and stopped services.
/// "rescue --at-boot" is what the boot-time task runs: it only clears firewall rules a crashed sensor may have left,
/// and leaves the database alone so the sensor re-applies the blocks that are still wanted when it starts.
/// </summary>
public static class RescueCommand
{
    public static async Task<int> Run(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Rescue only applies to Windows Firewall.");
            return 1;
        }

        if (!WindowsFirewall.IsAdministrator())
        {
            Console.Error.WriteLine("Run this from an elevated (administrator) prompt.");
            return 1;
        }

        var removedRules = WindowsFirewall.RemoveAllRules();
        Console.WriteLine($"Removed {removedRules} ScoutWall firewall rules.");

        try
        {
            var removedPolicies = WindowsQualityOfService.RemoveAllPolicies();
            Console.WriteLine($"Removed {removedPolicies} ScoutWall QoS policies.");
        }
        catch (InvalidOperationException exception)
        {
            Console.Error.WriteLine($"Could not clean QoS policies: {exception.Message}");
        }

        if (args.Contains("--at-boot", StringComparer.OrdinalIgnoreCase))
            return 0;

        await RevokeInDatabase(args);
        return 0;
    }

    private static async Task RevokeInDatabase(string[] args)
    {
        try
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddJsonFile("appsettings.json", optional: true)
                .AddCommandLine(args)
                .Build();

            var databasePath = DataContext.ResolveDatabasePath(configuration["Database:Path"]);
            if (!File.Exists(databasePath))
                return;

            await using var dataContext = DataContext.Create(databasePath);
            var enforcementSettings = await Setting.Load<EnforcementSettings>(dataContext);
            if (enforcementSettings.Provider == EnforcementProvider.Webhook)
            {
                var removedWebhookCount = await Response.WebhookEnforcer.RemoveAll(dataContext, enforcementSettings, null);
                Console.WriteLine($"Asked the router or firewall webhook to remove {removedWebhookCount} blocks.");
            }

            // Disabled or removed tasks and stopped services stay that way unless asked, because restoring them
            // could bring back malware. The sensor reverses them on its next pass once they are revoked here.
            var undoHostActions = args.Contains("--undo-host-actions", StringComparer.OrdinalIgnoreCase);
            var revokedCount = await ResponseAction.RevokeAll(dataContext, "rescue command", undoHostActions);
            Console.WriteLine($"Revoked {revokedCount} response actions in the database.");
            if (!undoHostActions)
                Console.WriteLine("Scheduled task and service actions were kept. Add --undo-host-actions to reverse them as well.");

            await UndoReadTracking(dataContext);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Firewall is clean, but the database could not be updated: {exception.Message}");
        }
    }

    /// <summary>
    /// Puts back the Windows audit settings read tracking changed, and switches the feature off so the sensor
    /// doesn't apply them again.
    /// </summary>
    private static async Task UndoReadTracking(DataContext dataContext)
    {
        var state = await FileReadAuditState.Load(dataContext);
        if (!state.Applied)
            return;

        SystemHealth.FileReadAudit.Revert(state);
        await state.Save(dataContext);

        var tracking = await Setting.Load<FileTrackingSettings>(dataContext);
        tracking.ReadTrackingEnabled = false;
        await Setting.Save(dataContext, tracking, await Setting.GetRevision<FileTrackingSettings>(dataContext), "rescue command");
        Console.WriteLine(state.LastError == null
            ? "Turned file read tracking off and put back the Windows audit settings."
            : $"Turned file read tracking off; some folders could not be put back: {state.LastError}");
    }
}
