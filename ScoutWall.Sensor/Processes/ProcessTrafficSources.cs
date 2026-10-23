using System.Collections.Concurrent;
using System.Net;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;
using ScoutWall.Sensor.Network;
using ScoutWall.Sensor.SystemHealth;

namespace ScoutWall.Sensor.Processes;

public record ProcessTrafficEvent(
    DateTime Timestamp,
    string ImagePath,
    IPAddress LocalAddress,
    int LocalPort,
    IPAddress RemoteAddress,
    int RemotePort,
    string Protocol,
    int Bytes,
    bool IsSend);

public interface IProcessTrafficSource
{
    Task Run(Action<ProcessTrafficEvent> onEvent, CancellationToken cancellationToken);
}

/// <summary>
/// Per-process send and receive events from the Microsoft-Windows-Kernel-Network ETW provider.
/// Every TCP and UDP datagram carries the owning process id, so even short-lived DNS lookups are attributed.
/// Requires administrator rights.
/// </summary>
public class EtwProcessTrafficSource : IProcessTrafficSource
{
    private const string ProviderName = "Microsoft-Windows-Kernel-Network";
    private const string ProcessProviderName = "Microsoft-Windows-Kernel-Process";
    private const ulong ProcessKeyword = 0x10;
    private const int ProcessStartEvent = 1;
    private const int ProcessStopEvent = 2;

    // Kernel-File: only new files, deletes and renames (DELETE_PATH 0x400, RENAME_SETLINK_PATH 0x800,
    // CREATE_NEW_FILE 0x1000). These are rare next to reads and writes, and say which program changed a file.
    private const string FileProviderName = "Microsoft-Windows-Kernel-File";
    private const ulong FileKeywords = 0x400 | 0x800 | 0x1000;
    private const int FileDeletePathEvent = 26;
    private const int FileRenamePathEvent = 27;
    private const int FileCreateNewFileEvent = 30;
    private const string SessionName = "ScoutWall-ProcessNetwork";
    private const ulong Ipv4AndIpv6Keywords = 0x10 | 0x20;

    private static readonly HashSet<int> TcpSendEvents = [10, 26];
    private static readonly HashSet<int> TcpReceiveEvents = [11, 27];
    private static readonly HashSet<int> UdpSendEvents = [42, 58];
    private static readonly HashSet<int> UdpReceiveEvents = [43, 59];

    private readonly NetworkClassifier networkClassifier;

    public EtwProcessTrafficSource(NetworkClassifier networkClassifier)
    {
        this.networkClassifier = networkClassifier;
    }

    public async Task Run(Action<ProcessTrafficEvent> onEvent, CancellationToken cancellationToken)
    {
        if (TraceEventSession.IsElevated() != true)
            throw new UnauthorizedAccessException("Per-program traffic tracking needs the sensor to run as administrator.");

        using var traceEventSession = new TraceEventSession(SessionName) { StopOnDispose = true };
        var registeredParser = new RegisteredTraceEventParser(traceEventSession.Source);
        registeredParser.All += traceEvent =>
        {
            if (traceEvent.ProviderName == ProcessProviderName)
            {
                RememberProcess(traceEvent);
                return;
            }

            if (traceEvent.ProviderName == FileProviderName)
            {
                RememberFileActor(traceEvent);
                return;
            }

            var processTrafficEvent = Convert(traceEvent);
            if (processTrafficEvent != null)
                onEvent(processTrafficEvent);
        };

        traceEventSession.EnableProvider(ProcessProviderName, TraceEventLevel.Informational, ProcessKeyword);
        traceEventSession.EnableProvider(FileProviderName, TraceEventLevel.Informational, FileKeywords);
        traceEventSession.EnableProvider(ProviderName, TraceEventLevel.Informational, Ipv4AndIpv6Keywords);
        using var cancellationRegistration = cancellationToken.Register(() => traceEventSession.Dispose());
        await Task.Run(() => traceEventSession.Source.Process(), CancellationToken.None);
    }

    private static void RememberProcess(TraceEvent traceEvent)
    {
        var processId = ReadInteger(traceEvent, "ProcessID");
        if ((int)traceEvent.ID == ProcessStartEvent && traceEvent.PayloadByName("ImageName") is string imageName)
            ProcessPathResolver.RememberStart(processId, imageName);
        else if ((int)traceEvent.ID == ProcessStopEvent)
            ProcessPathResolver.RememberExit(processId);
    }

    private static void RememberFileActor(TraceEvent traceEvent)
    {
        var fieldName = (int)traceEvent.ID switch
        {
            FileCreateNewFileEvent => "FileName",
            FileDeletePathEvent or FileRenamePathEvent => "FilePath",
            _ => null
        };
        if (fieldName != null && traceEvent.PayloadByName(fieldName) is string devicePath)
            FileActors.Remember(traceEvent.ProcessID, devicePath);
    }

    private ProcessTrafficEvent? Convert(TraceEvent traceEvent)
    {
        var eventId = (int)traceEvent.ID;
        var isSend = TcpSendEvents.Contains(eventId) || UdpSendEvents.Contains(eventId);
        var isReceive = TcpReceiveEvents.Contains(eventId) || UdpReceiveEvents.Contains(eventId);
        if (!isSend && !isReceive)
            return null;

        var destinationAddress = ReadAddress(traceEvent, "daddr");
        var sourceAddress = ReadAddress(traceEvent, "saddr");
        if (destinationAddress == null || sourceAddress == null)
            return null;

        // Which field holds the remote address differs between event versions; the host's own address tells them apart.
        var sourceIsLocal = networkClassifier.IsHostAddress(sourceAddress);
        var destinationIsLocal = networkClassifier.IsHostAddress(destinationAddress);
        if (sourceIsLocal && destinationIsLocal)
            return null;

        var localIsSource = sourceIsLocal || !destinationIsLocal;
        var processId = ReadInteger(traceEvent, "PID");
        var protocol = TcpSendEvents.Contains(eventId) || TcpReceiveEvents.Contains(eventId) ? "TCP" : "UDP";

        return new ProcessTrafficEvent(
            traceEvent.TimeStamp.ToUniversalTime(),
            ProcessPathResolver.Resolve(processId),
            localIsSource ? sourceAddress : destinationAddress,
            ReadInteger(traceEvent, localIsSource ? "sport" : "dport"),
            localIsSource ? destinationAddress : sourceAddress,
            ReadInteger(traceEvent, localIsSource ? "dport" : "sport"),
            protocol,
            ReadInteger(traceEvent, "size"),
            isSend);
    }

    /// <summary>
    /// Reads fields through their formatted string form, which applies the manifest's IPv4/IPv6/port
    /// formatting and so avoids byte-order guesswork.
    /// </summary>
    private static IPAddress? ReadAddress(TraceEvent traceEvent, string fieldName)
    {
        var fieldIndex = traceEvent.PayloadIndex(fieldName);
        if (fieldIndex < 0)
            return null;

        return IPAddress.TryParse(traceEvent.PayloadString(fieldIndex), out var address) ? address : null;
    }

    private static int ReadInteger(TraceEvent traceEvent, string fieldName)
    {
        var fieldIndex = traceEvent.PayloadIndex(fieldName);
        if (fieldIndex < 0)
            return 0;

        var text = traceEvent.PayloadString(fieldIndex).Replace(",", string.Empty);
        return int.TryParse(text, out var value) ? value : 0;
    }
}

/// <summary>
/// Fake per-program traffic for synthetic mode, including a suspicious updater that uploads steadily.
/// </summary>
public class SyntheticProcessTrafficSource : IProcessTrafficSource
{
    private static readonly IPAddress LocalAddress = IPAddress.Parse("192.168.1.50");

    private static readonly (string ImagePath, string RemoteAddress, int RemotePort, int SendBytes, int ReceiveBytes)[] Programs =
    [
        (@"C:\Program Files\Google\Chrome\Application\chrome.exe", "142.250.72.100", 443, 2_000, 40_000),
        (@"C:\Program Files\Google\Chrome\Application\chrome.exe", "151.101.1.140", 443, 1_500, 25_000),
        (@"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "20.190.151.68", 443, 30_000, 2_000),
        (@"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", "23.45.229.117", 443, 3_000, 8_000),
        (@"C:\Windows\System32\svchost.exe", "1.1.1.1", 53, 120, 300),
        (@"C:\Users\Public\Libraries\svcupdate.exe", "95.213.255.5", 443, 60_000, 500),
        (@"C:\Users\Public\Libraries\svcupdate.exe", "47.95.164.112", 8443, 25_000, 300)
    ];

    private readonly Random random = new();

    public async Task Run(Action<ProcessTrafficEvent> onEvent, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            var program = Programs[random.Next(Programs.Length)];
            var remoteAddress = IPAddress.Parse(program.RemoteAddress);
            var localPort = random.Next(50000, 65000);
            var protocol = program.RemotePort == 53 ? "UDP" : "TCP";

            onEvent(new ProcessTrafficEvent(DateTime.UtcNow, program.ImagePath, LocalAddress, localPort, remoteAddress,
                program.RemotePort, protocol, random.Next(program.SendBytes / 2, program.SendBytes * 2), IsSend: true));
            onEvent(new ProcessTrafficEvent(DateTime.UtcNow, program.ImagePath, LocalAddress, localPort, remoteAddress,
                program.RemotePort, protocol, random.Next(program.ReceiveBytes / 2, program.ReceiveBytes * 2), IsSend: false));
        }
    }
}

/// <summary>
/// Which program owns a local port, learned from the per-process events. Lets packet-level records such as
/// TLS server names be tagged with the program that made the connection.
/// </summary>
public class ConnectionOwnerMap
{
    private static readonly TimeSpan EntryLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<(string Protocol, int LocalPort), (string ImagePath, DateTime SeenAt)> owners = new();

    public void Record(ProcessTrafficEvent processTrafficEvent)
    {
        owners[(processTrafficEvent.Protocol, processTrafficEvent.LocalPort)] = (processTrafficEvent.ImagePath, processTrafficEvent.Timestamp);
    }

    public string? FindProcessName(string protocol, IPAddress localAddress, int localPort)
    {
        if (!owners.TryGetValue((protocol, localPort), out var owner))
            return null;

        return Path.GetFileName(owner.ImagePath);
    }

    public void Prune(DateTime now)
    {
        foreach (var entry in owners.Where(entry => now - entry.Value.SeenAt > EntryLifetime))
            owners.TryRemove(entry.Key, out _);
    }
}
