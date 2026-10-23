using ScoutWall.Data.Models;
using ScoutWall.Sensor.Processes;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Collects per-program traffic from ETW (or the synthetic generator) and flushes it every ten seconds.
/// </summary>
public class ProcessTrafficWorker : BackgroundService
{
    private static readonly TimeSpan FlushInterval = TimeSpan.FromSeconds(10);

    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<ProcessTrafficWorker> logger;

    public ProcessTrafficWorker(SensorRuntime sensorRuntime, ILogger<ProcessTrafficWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await sensorRuntime.WaitUntilReady(stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, sensorRuntime.CaptureRestartToken);
            if (!sensorRuntime.Configuration.Capture.TrackProcesses)
            {
                await SensorWorker.DelayQuietly(Timeout.InfiniteTimeSpan, runCancellation.Token);
                continue;
            }

            await RunTracking(runCancellation.Token);
        }
    }

    private async Task RunTracking(CancellationToken cancellationToken)
    {
        var processTrafficAggregator = new ProcessTrafficAggregator(sensorRuntime);
        IProcessTrafficSource processTrafficSource = sensorRuntime.StartupOptions.CaptureMode == CaptureMode.Synthetic
            ? new SyntheticProcessTrafficSource()
            : new EtwProcessTrafficSource(sensorRuntime.NetworkClassifier);

        var sourceTask = RunSource(processTrafficSource, processTrafficAggregator, cancellationToken);

        while (await SensorWorker.DelayQuietly(FlushInterval, cancellationToken))
            await Flush(processTrafficAggregator);

        await sourceTask;
        await Flush(processTrafficAggregator);
    }

    private async Task RunSource(IProcessTrafficSource processTrafficSource, ProcessTrafficAggregator processTrafficAggregator, CancellationToken cancellationToken)
    {
        try
        {
            logger.LogInformation("Per-program traffic tracking started with {Source}", processTrafficSource.GetType().Name);
            await processTrafficSource.Run(processTrafficAggregator.Add, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            logger.LogError("Per-program traffic tracking unavailable: {Message}", exception.Message);
            sensorRuntime.LastError = $"Per-program tracking: {exception.Message}";
        }
    }

    /// <summary>
    /// Reads names and publishers from executables (the sensor runs elevated and can open them), so the console
    /// and the analyst can say "Google Chrome by Google LLC" instead of a path.
    /// </summary>
    private static async Task ReadProgramIdentities(ScoutWall.Data.DataContext dataContext)
    {
        foreach (var processImage in await ProcessImage.GetMissingIdentity(dataContext, 20))
        {
            var programFileInfo = Analyst.ProgramIdentity.Read(processImage.ImagePath);
            await ProcessImage.SaveIdentity(dataContext, processImage.Id, programFileInfo?.Description, programFileInfo?.Publisher,
                programFileInfo?.Company, programFileInfo?.Product, programFileInfo?.Version);
        }
    }

    private async Task Flush(ProcessTrafficAggregator processTrafficAggregator)
    {
        var processTrafficCounts = processTrafficAggregator.Drain();
        if (processTrafficCounts.Count == 0)
            return;

        try
        {
            await using var dataContext = sensorRuntime.CreateDataContext();
            await ProcessTrafficMinute.Record(dataContext, processTrafficCounts);
            await ReadProgramIdentities(dataContext);
        }
        catch (Exception exception)
        {
            logger.LogError(exception, "Writing per-program traffic failed");
        }
    }
}
