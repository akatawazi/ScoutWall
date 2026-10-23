using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Sensor.Response;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Names of the firewall rules the decoy worker owns, so the response reconciler leaves them alone.
/// </summary>
public static class DecoyRules
{
    public const string AllowRuleName = "ScoutWall Decoy Ports";

    public static bool IsOwnedRule(string ruleName)
    {
        return ruleName == AllowRuleName || ruleName == ScannerBlock.FirewallRuleName;
    }
}

/// <summary>
/// Listens on a few decoy ports that nothing legitimate uses. Any connection is accepted and closed at once (no
/// data is read or sent) and reported; internet addresses go on the scanner blocklist. Also keeps the shared
/// scanner-blocklist firewall rule in line with the table, recreating it if the kill switch or rescue removed it.
/// </summary>
public class DecoyPortWorker : SensorWorker
{
    private const int ChosenPortCount = 5;
    private const int MaximumBlockedAddresses = 1000;
    private const string ChosenPortsKey = "decoy_ports";
    private readonly Dictionary<int, TcpListener> listeners = [];
    private CancellationTokenSource? listenerCancellation;

    public DecoyPortWorker(SensorRuntime sensorRuntime, ILogger<DecoyPortWorker> logger) : base(sensorRuntime, logger)
    {
    }

    protected override TimeSpan Interval => TimeSpan.FromSeconds(30);

    protected override async Task RunOnce(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !WindowsFirewall.IsAdministrator())
            return;

        await using var dataContext = SensorRuntime.CreateDataContext();
        var detectionSettings = SensorRuntime.Configuration.Detection;

        if (detectionSettings.DecoyPortsEnabled)
            await OpenDecoys(dataContext, detectionSettings, cancellationToken);
        else
            CloseDecoys();

        await SynchronizeScannerRule(dataContext);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        CloseDecoys();
        await base.StopAsync(cancellationToken);
    }

    private async Task OpenDecoys(DataContext dataContext, DetectionSettings detectionSettings, CancellationToken cancellationToken)
    {
        var ports = detectionSettings.DecoyPorts.Count > 0 ? detectionSettings.DecoyPorts : await ChoosePorts(dataContext);
        var wanted = ports.ToHashSet();

        foreach (var port in listeners.Keys.Where(port => !wanted.Contains(port)).ToList())
            StopListener(port);

        listenerCancellation ??= CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        foreach (var port in wanted.Where(port => !listeners.ContainsKey(port)))
        {
            try
            {
                var listener = new TcpListener(IPAddress.IPv6Any, port);
                listener.Server.DualMode = true;
                listener.Start(16);
                listeners[port] = listener;
                _ = AcceptLoop(listener, port, listenerCancellation.Token);
                Logger.LogInformation("Decoy port {Port} is open", port);
            }
            catch (SocketException exception)
            {
                Logger.LogWarning("Decoy port {Port} could not be opened: {Message}", port, exception.Message);
            }
        }

        EnsureAllowRule(listeners.Keys.Order().ToList());
    }

    /// <summary>
    /// Picks unused ports once and remembers them, so the decoys stay put across restarts.
    /// </summary>
    private static async Task<List<int>> ChoosePorts(DataContext dataContext)
    {
        var remembered = await SystemState.GetValue(dataContext, ChosenPortsKey);
        if (remembered != null && JsonSerializer.Deserialize<List<int>>(remembered) is { Count: > 0 } rememberedPorts)
            return rememberedPorts;

        var listening = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(endpoint => endpoint.Port).ToHashSet();
        var chosen = DetectionSettings.DecoyPortCandidates
            .Where(port => !listening.Contains(port))
            .OrderBy(_ => Random.Shared.Next())
            .Take(ChosenPortCount)
            .Order()
            .ToList();

        await SystemState.SetValue(dataContext, ChosenPortsKey, JsonSerializer.Serialize(chosen));
        return chosen;
    }

    private async Task AcceptLoop(TcpListener listener, int port, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptSocketAsync(cancellationToken);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            var remoteEndPoint = socket.RemoteEndPoint as IPEndPoint;
            socket.Close(0);
            if (remoteEndPoint != null)
                await Report(remoteEndPoint.Address, port);
        }
    }

    private async Task Report(IPAddress remoteAddress, int port)
    {
        if (remoteAddress.IsIPv4MappedToIPv6)
            remoteAddress = remoteAddress.MapToIPv4();

        if (IPAddress.IsLoopback(remoteAddress) || SensorRuntime.NetworkClassifier.IsHostAddress(remoteAddress))
            return;

        var source = remoteAddress.ToString();
        var isLocal = ResponseAction.IsPrivateAddress(source);
        var description = isLocal
            ? $"A device on your network ({source}) connected to decoy port {port}. Nothing legitimate uses that port here, so the device may be scanning for weaknesses or be infected. It was not blocked; you can block it from reaching this computer."
            : $"{source} on the internet connected to decoy port {port}. Nothing legitimate uses that port, so this is a scanner or an attack. It has been added to the scanner blocklist.";

        var now = DateTime.UtcNow;
        await SensorRuntime.AlertQueue.Writer.WriteAsync(new Alert
        {
            RuleName = "DecoyPortTouched",
            Severity = isLocal ? AlertSeverity.High : AlertSeverity.Medium,
            Status = AlertStatus.Open,
            Title = isLocal ? $"A device on your network probed this computer ({source})" : $"Internet scanner {source} touched a decoy port",
            Description = description,
            SourceIp = source,
            DestinationPort = port,
            Protocol = "TCP",
            Details = JsonSerializer.Serialize(new { decoy_port = port, local_network = isLocal }),
            CreatedAt = now,
            LastSeenAt = now
        });
    }

    private void EnsureAllowRule(List<int> openPorts)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var wantedPorts = string.Join(",", openPorts);
        var existing = WindowsFirewall.ReadRule(DecoyRules.AllowRuleName);
        if (existing?.LocalPorts == wantedPorts)
            return;

        if (existing != null)
            WindowsFirewall.RemoveRule(DecoyRules.AllowRuleName);

        if (openPorts.Count > 0 && Environment.ProcessPath != null)
            WindowsFirewall.AddDecoyAllowRule(DecoyRules.AllowRuleName, "Lets ScoutWall's decoy ports be reached from home and work networks.", openPorts, Environment.ProcessPath);
    }

    private void CloseDecoys()
    {
        foreach (var port in listeners.Keys.ToList())
            StopListener(port);

        listenerCancellation?.Cancel();
        listenerCancellation = null;

        if (OperatingSystem.IsWindows() && WindowsFirewall.ReadRule(DecoyRules.AllowRuleName) != null)
            WindowsFirewall.RemoveRule(DecoyRules.AllowRuleName);
    }

    private void StopListener(int port)
    {
        if (listeners.Remove(port, out var listener))
            listener.Stop();
    }

    /// <summary>
    /// One firewall rule blocks every listed scanner. In practice mode the list is kept but not enforced.
    /// </summary>
    private async Task SynchronizeScannerRule(DataContext dataContext)
    {
        if (!OperatingSystem.IsWindows())
            return;

        var addresses = SensorRuntime.Configuration.Response.DryRun || SensorRuntime.Configuration.Enforcement.Provider != EnforcementProvider.WindowsFirewall
            ? []
            : await ScannerBlock.GetActiveAddresses(dataContext, MaximumBlockedAddresses);
        var wanted = string.Join(",", addresses.Order(StringComparer.Ordinal));
        var existing = WindowsFirewall.ReadRule(ScannerBlock.FirewallRuleName);

        if (addresses.Count == 0)
        {
            if (existing != null)
                WindowsFirewall.RemoveRule(ScannerBlock.FirewallRuleName);
            return;
        }

        // Windows rewrites addresses with masks, so compare by the address list it reports.
        var existingAddresses = existing?.RemoteAddresses?.Split(',').Select(entry => entry.Split('/')[0]).Order(StringComparer.Ordinal);
        if (existingAddresses != null && string.Join(",", existingAddresses) == wanted)
            return;

        if (existing != null)
            WindowsFirewall.RemoveRule(ScannerBlock.FirewallRuleName);

        WindowsFirewall.AddBlockRule(ScannerBlock.FirewallRuleName, "Internet addresses that scanned this computer or touched a decoy port.", false, wanted, null);
        Logger.LogInformation("Scanner blocklist now holds {Count} addresses", addresses.Count);
    }
}
