using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using ScoutWall.Data;

namespace ScoutWall.Presence;

/// <summary>
/// A notification-area icon with no window. Reports the last input time every few seconds and pops up
/// queued desktop notifications. It talks to the sensor over a local named pipe; it never opens the database.
/// </summary>
public class PresenceAgent : ApplicationContext
{
    private static readonly TimeSpan ReportInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan NotificationInterval = TimeSpan.FromSeconds(10);

    private readonly string dashboardUrl;
    private readonly NotifyIcon notifyIcon;
    private readonly System.Windows.Forms.Timer reportTimer;
    private readonly System.Windows.Forms.Timer notificationTimer;
    private bool isBusy;

    public PresenceAgent(string dashboardUrl)
    {
        this.dashboardUrl = dashboardUrl;

        var contextMenu = new ContextMenuStrip();
        contextMenu.Items.Add("Open ScoutWall", null, (sender, eventArgs) => OpenDashboard());
        contextMenu.Items.Add("Exit presence agent", null, (sender, eventArgs) => ExitThread());

        notifyIcon = new NotifyIcon
        {
            Icon = LoadScoutIcon(),
            Text = "ScoutWall is watching network traffic",
            ContextMenuStrip = contextMenu,
            Visible = true
        };
        notifyIcon.DoubleClick += (sender, eventArgs) => OpenDashboard();
        notifyIcon.BalloonTipClicked += (sender, eventArgs) => OpenDashboard();

        reportTimer = new System.Windows.Forms.Timer { Interval = (int)ReportInterval.TotalMilliseconds };
        reportTimer.Tick += async (sender, eventArgs) => await RunGuarded(ReportPresence);
        reportTimer.Start();

        notificationTimer = new System.Windows.Forms.Timer { Interval = (int)NotificationInterval.TotalMilliseconds };
        notificationTimer.Tick += async (sender, eventArgs) => await RunGuarded(ShowNotifications);
        notificationTimer.Start();
    }

    protected override void ExitThreadCore()
    {
        reportTimer.Stop();
        notificationTimer.Stop();
        notifyIcon.Visible = false;
        notifyIcon.Dispose();
        base.ExitThreadCore();
    }

    private async Task RunGuarded(Func<Task> work)
    {
        if (isBusy)
            return;

        isBusy = true;
        try
        {
            await work();
        }
        catch (TimeoutException)
        {
            notifyIcon.Text = "ScoutWall: waiting for the ScoutWall service";
        }
        catch (Exception exception)
        {
            notifyIcon.Text = Truncate($"ScoutWall: {exception.Message}", 127);
        }
        finally
        {
            isBusy = false;
        }
    }

    private async Task ReportPresence()
    {
        await Ask(new PresenceRequest("report", DateTime.UtcNow.Subtract(GetIdleTime())));
        notifyIcon.Text = "ScoutWall is watching network traffic";
    }

    private async Task ShowNotifications()
    {
        var response = await Ask(new PresenceRequest("notifications", null));
        foreach (var notification in response.Notifications)
        {
            var toolTipIcon = notification.IsSerious ? ToolTipIcon.Warning : ToolTipIcon.Info;
            notifyIcon.ShowBalloonTip(10_000, Truncate($"ScoutWall: {notification.Title}", 63), Truncate(notification.Message, 255), toolTipIcon);
        }
    }

    /// <summary>
    /// One request and its answer over the sensor's pipe. The sensor identifies this session from the pipe itself.
    /// </summary>
    private static async Task<PresenceResponse> Ask(PresenceRequest request)
    {
        await using var pipe = new NamedPipeClientStream(".", PresenceChannel.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            TokenImpersonationLevel.Identification);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            await pipe.ConnectAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            throw new TimeoutException();
        }

        await pipe.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(request), timeout.Token);
        await pipe.WriteAsync("\n"u8.ToArray(), timeout.Token);
        await pipe.FlushAsync(timeout.Token);

        using var reader = new StreamReader(pipe, Encoding.UTF8);
        var line = await reader.ReadLineAsync(timeout.Token);
        return line == null ? new PresenceResponse(false, []) : JsonSerializer.Deserialize<PresenceResponse>(line) ?? new PresenceResponse(false, []);
    }

    /// <summary>
    /// Scout, the ScoutWall dog, in the notification area.
    /// </summary>
    private static Icon LoadScoutIcon()
    {
        using var iconStream = typeof(PresenceAgent).Assembly.GetManifestResourceStream("ScoutWall.Presence.scout.ico");
        return iconStream == null ? SystemIcons.Shield : new Icon(iconStream, SystemInformation.SmallIconSize);
    }

    private void OpenDashboard()
    {
        Process.Start(new ProcessStartInfo(dashboardUrl) { UseShellExecute = true });
    }

    private static TimeSpan GetIdleTime()
    {
        var lastInputInfo = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref lastInputInfo))
            return TimeSpan.Zero;

        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - lastInputInfo.Time));
    }

    private static string Truncate(string text, int maximumLength)
    {
        return text.Length <= maximumLength ? text : text[..(maximumLength - 1)] + "…";
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo lastInputInfo);
}
