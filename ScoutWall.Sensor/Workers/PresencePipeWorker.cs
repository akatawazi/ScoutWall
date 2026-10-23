using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Workers;

/// <summary>
/// Serves the presence agents over a local named pipe: each signed-in person's agent reports their last keyboard or
/// mouse input and collects desktop notifications. The Windows session and account are taken from the pipe itself,
/// not from what the agent says, so one person can't report presence for another.
/// </summary>
public class PresencePipeWorker : BackgroundService
{
    private readonly SensorRuntime sensorRuntime;
    private readonly ILogger<PresencePipeWorker> logger;

    public PresencePipeWorker(SensorRuntime sensorRuntime, ILogger<PresencePipeWorker> logger)
    {
        this.sensorRuntime = sensorRuntime;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!OperatingSystem.IsWindows())
            return;

        await sensorRuntime.WaitUntilReady(stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream pipe;
            try
            {
                pipe = CreatePipe();
                await pipe.WaitForConnectionAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (IOException exception)
            {
                logger.LogWarning("Presence pipe could not be opened: {Message}", exception.Message);
                await SensorWorker.DelayQuietly(TimeSpan.FromSeconds(30), stoppingToken);
                continue;
            }

            _ = Task.Run(() => Serve(pipe, stoppingToken), CancellationToken.None);
        }
    }

    [SupportedOSPlatform("windows")]
    private static NamedPipeServerStream CreatePipe()
    {
        // Signed-in people can talk to it; nobody can take over the pipe name.
        var security = new PipeSecurity();
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(PresenceChannel.PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, security);
    }

    [SupportedOSPlatform("windows")]
    private async Task Serve(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        await using (pipe)
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                timeout.CancelAfter(TimeSpan.FromSeconds(10));

                var request = await ReadRequest(pipe, timeout.Token);
                var response = request == null
                    ? new PresenceResponse(false, [], "Unreadable request.")
                    : await Handle(pipe, request);

                var bytes = JsonSerializer.SerializeToUtf8Bytes(response);
                await pipe.WriteAsync(bytes, timeout.Token);
                await pipe.WriteAsync("\n"u8.ToArray(), timeout.Token);
                await pipe.FlushAsync(timeout.Token);
            }
            catch (Exception exception) when (exception is IOException or OperationCanceledException or JsonException)
            {
                // The agent went away or sent something else; it tries again in a few seconds.
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private async Task<PresenceResponse> Handle(NamedPipeServerStream pipe, PresenceRequest request)
    {
        await using var dataContext = sensorRuntime.CreateDataContext();
        switch (request.Type)
        {
            case "report" when request.LastInputAt.HasValue:
            {
                if (!GetNamedPipeClientSessionId(pipe.SafePipeHandle.DangerousGetHandle(), out var sessionId))
                    return new PresenceResponse(false, [], "Unknown session.");

                var userName = pipe.GetImpersonationUserName();
                var now = DateTime.UtcNow;
                var lastInputAt = request.LastInputAt.Value.ToUniversalTime();
                await UserPresence.Report(dataContext, new UserPresence
                {
                    SessionKey = $"{Environment.MachineName}:{sessionId}",
                    UserName = userName,
                    SessionId = (int)sessionId,
                    LastInputAt = lastInputAt > now ? now : lastInputAt,
                    ReportedAt = now
                });
                return new PresenceResponse(true, []);
            }

            case "notifications":
            {
                var due = await NotificationDelivery.GetDue(dataContext, NotificationChannel.Desktop, 3);
                foreach (var delivery in due)
                    await NotificationDelivery.MarkSent(dataContext, delivery.Id);

                return new PresenceResponse(true, due.Select(delivery => new PresenceNotification(delivery.Title, delivery.Message, delivery.Severity >= AlertSeverity.High)).ToList());
            }

            default:
                return new PresenceResponse(false, [], "Unknown request.");
        }
    }

    private static async Task<PresenceRequest?> ReadRequest(Stream pipe, CancellationToken cancellationToken)
    {
        var buffer = new byte[PresenceChannel.MaximumMessageBytes];
        var length = 0;
        while (length < buffer.Length)
        {
            var read = await pipe.ReadAsync(buffer.AsMemory(length), cancellationToken);
            if (read == 0)
                break;

            length += read;
            if (Array.IndexOf(buffer, (byte)'\n', 0, length) >= 0)
                break;
        }

        var line = Encoding.UTF8.GetString(buffer, 0, length).Split('\n')[0];
        return line.Length == 0 ? null : JsonSerializer.Deserialize<PresenceRequest>(line);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientSessionId(IntPtr pipe, out uint clientSessionId);
}
