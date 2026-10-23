using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Response;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Saves alerts from the detection rules, queues notifications and asks the response planner for an action.
/// </summary>
public class AlertWorker : BackgroundService
{
    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<AlertWorker> logger;
    private readonly Dictionary<(string Rule, string Source, string? Process), DateTime> lastNotified = [];

    public AlertWorker(SensorRuntime sensorRuntime, ILogger<AlertWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await sensorRuntime.WaitUntilReady(stoppingToken);

        try
        {
            await foreach (var alert in sensorRuntime.AlertQueue.Reader.ReadAllAsync(stoppingToken))
                await Handle(alert);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private async Task Handle(Alert alert)
    {
        try
        {
            await using var dataContext = sensorRuntime.CreateDataContext();
            var aggregationWindow = TimeSpan.FromMinutes(sensorRuntime.Configuration.Detection.AlertAggregationMinutes);
            var savedAlert = await Alert.Raise(dataContext, alert, aggregationWindow);
            dataContext.ChangeTracker.Clear();

            if (savedAlert.OccurrenceCount == 1)
                logger.LogWarning("[{Severity}] {Title}", savedAlert.Severity, savedAlert.Title);

            await QueueNotifications(dataContext, savedAlert);

            // Soft alerts wait for the analyst (see ResponseWorker) so a false positive is cleared before anything is blocked.
            if (!ResponsePlanner.ShouldWaitForAnalyst(sensorRuntime, savedAlert))
            {
                var responseAction = await ResponsePlanner.Plan(dataContext, sensorRuntime, savedAlert);
                await Alert.MarkResponseConsidered(dataContext, savedAlert.Id);
                // Repeated alerts refresh the same action; only a newly planned one is worth a log entry.
                if (responseAction != null && responseAction.CreatedAt >= DateTime.UtcNow.AddSeconds(-10))
                    logger.LogWarning("Response {ActionType} on {Target} is {Status}", responseAction.ActionType, responseAction.Target, responseAction.Status);
            }
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Handling alert {Title} failed", alert.Title);
        }
    }

    private async Task QueueNotifications(DataContext dataContext, Alert alert)
    {
        var notificationSettings = sensorRuntime.Configuration.Notification;
        var notifiedKey = (alert.RuleName, alert.SourceIp, alert.ProcessPath);
        var repeatWindow = TimeSpan.FromMinutes(notificationSettings.RepeatMinutes);
        if (lastNotified.TryGetValue(notifiedKey, out var lastTime) && DateTime.UtcNow - lastTime < repeatWindow)
            return;

        lastNotified[notifiedKey] = DateTime.UtcNow;
        var message = BuildMessage(alert);

        if (notificationSettings.EmailEnabled && alert.Severity >= notificationSettings.EmailMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Email, alert.Severity, alert.Title, message, alert.Id);

        if (notificationSettings.WebhookEnabled && alert.Severity >= notificationSettings.WebhookMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Webhook, alert.Severity, alert.Title, message, alert.Id);

        if (notificationSettings.DesktopEnabled && alert.Severity >= notificationSettings.DesktopMinimumSeverity)
            await NotificationDelivery.Enqueue(dataContext, NotificationChannel.Desktop, alert.Severity, alert.Title, alert.Description, alert.Id);
    }

    private string BuildMessage(Alert alert)
    {
        var lines = new List<string>
        {
            alert.Description,
            string.Empty,
            $"Rule: {alert.RuleName}",
            $"Source: {alert.SourceIp}",
            $"Destination: {alert.DestinationIp}{(alert.DestinationPort.HasValue ? ":" + alert.DestinationPort : string.Empty)}",
            $"Time (UTC): {alert.LastSeenAt:yyyy-MM-dd HH:mm:ss}",
            $"Sensor: {sensorRuntime.StartupOptions.SensorName}"
        };

        if (alert.ProcessPath != null)
            lines.Insert(3, $"Program: {alert.ProcessPath}");

        return string.Join(Environment.NewLine, lines);
    }
}
