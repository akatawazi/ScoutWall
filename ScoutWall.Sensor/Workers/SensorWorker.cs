namespace ScoutWall.Sensor.Workers;

/// <summary>
/// A background loop that waits for the database and configuration, then runs every <see cref="Interval"/>.
/// A failed pass is logged and retried on the next tick rather than stopping the sensor.
/// </summary>
public abstract class SensorWorker : BackgroundService
{
    protected SensorWorker(SensorRuntime sensorRuntime, ILogger logger)
    {
        SensorRuntime = sensorRuntime;
        Logger = logger;
    }

    protected SensorRuntime SensorRuntime { get; }
    protected ILogger Logger { get; }
    protected abstract TimeSpan Interval { get; }

    protected abstract Task RunOnce(CancellationToken cancellationToken);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await SensorRuntime.WaitUntilReady(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            await RunSafely(stoppingToken);
            if (!await DelayQuietly(Interval, stoppingToken))
                break;
        }
    }

    private async Task RunSafely(CancellationToken stoppingToken)
    {
        try
        {
            await RunOnce(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            Logger.LogError(exception, "{Worker} pass failed", GetType().Name);
            SensorRuntime.LastError = $"{GetType().Name}: {exception.Message}";
        }
    }

    /// <summary>
    /// Returns false when cancelled.
    /// </summary>
    public static async Task<bool> DelayQuietly(TimeSpan delay, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(delay, cancellationToken);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }
}
