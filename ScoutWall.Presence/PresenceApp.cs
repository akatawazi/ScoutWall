namespace ScoutWall.Presence;

/// <summary>
/// "scoutwall presence": the agent in each signed-in person's session. Reports keyboard and mouse idle time to the
/// sensor and shows ScoutWall desktop notifications. Option: --url "http://localhost:5215"
/// </summary>
public static class PresenceApp
{
    /// <summary>
    /// Runs the notification-area agent on its own STA thread (Windows Forms needs one) until it is closed.
    /// </summary>
    public static int Run(string[] args)
    {
        var thread = new Thread(() => RunAgent(args));
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        return 0;
    }

    private static void RunAgent(string[] args)
    {
        using var singleInstance = new Mutex(true, $@"Local\ScoutWall.Presence.{Environment.UserName}", out var isFirstInstance);
        if (!isFirstInstance)
            return;

        var dashboardUrl = ReadOption(args, "--url") ?? "http://localhost:5215";

        // What the Windows Forms template's ApplicationConfiguration.Initialize does (it only exists in executables).
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.SetHighDpiMode(HighDpiMode.SystemAware);
        Application.Run(new PresenceAgent(dashboardUrl));
    }

    private static string? ReadOption(string[] args, string name)
    {
        var index = Array.FindIndex(args, argument => string.Equals(argument, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
