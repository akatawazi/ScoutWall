using ScoutWall.Sensor.Workers;

namespace ScoutWall.Sensor;

/// <summary>
/// "scoutwall sensor": capture, detection, enrichment, the analyst, notifications and (on Windows) per-program
/// tracking, firewall responses and the system, I/O and presence features. Runs as a Windows service (LocalSystem)
/// or a systemd service (with network capture capabilities).
/// </summary>
public static class SensorHost
{
    public const string ServiceName = "ScoutWall Sensor";

    public static async Task<int> RunAsync(string[] args)
    {
        // Settings files live beside the program and are read once: watching for changes is pointless for a service
        // and, with a service's working folder at the root of the disk, would try to watch the whole disk.
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = args,
            ContentRootPath = AppContext.BaseDirectory,
            Configuration = new ConfigurationManager { ["hostBuilder:reloadConfigOnChange"] = "false" }
        });
        builder.Services.AddWindowsService(options => options.ServiceName = ServiceName);

        // One failing part (logged as an error) must not stop capture, detection and everything else with it.
        builder.Services.Configure<HostOptions>(options => options.BackgroundServiceExceptionBehavior = BackgroundServiceExceptionBehavior.Ignore);
        builder.Services.AddSystemd();

        // Log to the event source registered for the service. The default source (the assembly name) is not
        // registered, and a failed event log write would otherwise stop the host.
        if (OperatingSystem.IsWindows())
            UseServiceEventSource(builder.Services);

        var startupOptions = builder.Configuration.GetSection("Sensor").Get<SensorStartupOptions>() ?? new SensorStartupOptions();
        startupOptions.DatabasePath ??= builder.Configuration["Database:Path"];
        builder.Services.AddSingleton(new SensorRuntime(startupOptions));

        builder.Services.AddHostedService<ConfigurationWorker>();
        builder.Services.AddHostedService<PresenceWorker>();
        builder.Services.AddHostedService<CaptureWorker>();
        builder.Services.AddHostedService<AlertWorker>();
        builder.Services.AddHostedService<VerdictWorker>();
        builder.Services.AddHostedService<AnalystWorker>();
        builder.Services.AddHostedService<NotificationWorker>();
        builder.Services.AddHostedService<EnrichmentWorker>();
        builder.Services.AddHostedService<DecryptionWorker>();
        builder.Services.AddHostedService<MaintenanceWorker>();
        builder.Services.AddHostedService<DecoyPortWorker>();
        builder.Services.AddHostedService<UpdateCheckWorker>();

        // Per-program traffic, firewall responses and the System, I/O and presence features use Windows-only
        // interfaces (ETW, Windows Firewall, event logs, the NTFS change journal).
        if (OperatingSystem.IsWindows())
        {
            builder.Services.AddHostedService<PresencePipeWorker>();
            builder.Services.AddHostedService<ProcessTrafficWorker>();
            builder.Services.AddHostedService<ResponseWorker>();
            builder.Services.AddHostedService<SystemResourceWorker>();
            builder.Services.AddHostedService<EventLogWorker>();
            builder.Services.AddHostedService<ExecutionGuardWorker>();
            builder.Services.AddHostedService<ScanWorker>();
            builder.Services.AddHostedService<DiskActivityWorker>();
            builder.Services.AddHostedService<FileActivityWorker>();
            builder.Services.AddHostedService<FileReadWorker>();
        }

        var host = builder.Build();
        await host.RunAsync();
        return 0;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static void UseServiceEventSource(IServiceCollection services)
    {
        services.Configure<Microsoft.Extensions.Logging.EventLog.EventLogSettings>(settings => settings.SourceName = ServiceName);
    }
}
