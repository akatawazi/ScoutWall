using ScoutWall;
using ScoutWall.Installation;
using ScoutWall.Sensor;

// One executable, several roles. The installed services run "scoutwall web" and "scoutwall sensor"; the presence
// agent runs "scoutwall presence" in each signed-in session. With no command (or only options, as Visual Studio
// starts it) the web console runs.
var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0].ToLowerInvariant() : "web";
var rest = args.Length > 0 && !args[0].StartsWith('-') ? args[1..] : args;

switch (command)
{
    case "web":
        return await WebConsole.RunAsync(rest);

    case "sensor":
        return await SensorHost.RunAsync(rest);

    case "presence":
#if WINDOWS
        return ScoutWall.Presence.PresenceApp.Run(rest);
#else
        Console.Error.WriteLine("The presence agent is only available on Windows.");
        return 1;
#endif

    case "install":
        return await Installer.Install(rest);

    case "uninstall":
        return await Installer.Uninstall(rest);

    case "update":
        return await Updater.Update(rest);

    case "rescue":
        return await RescueCommand.Run(rest);

    case "version" or "--version":
        Console.WriteLine($"ScoutWall {Installer.Version}");
        return 0;

    default:
        Console.WriteLine($"""
            ScoutWall {Installer.Version}: watches this computer's network traffic and warns about problems.

            Usage: scoutwall <command>

              install     Install or upgrade ScoutWall on this computer (administrator/root).
                          Options: --port 5215, --no-start
              update      Download and install the newest release (administrator/root). --check only reports.
              uninstall   Remove ScoutWall. Add --delete-data to also delete its database and settings.
              rescue      Remove every ScoutWall firewall rule and undo Windows audit changes (administrator).
              web         Run the web console (what the "ScoutWall Web" service runs).
              sensor      Run the sensor (what the "ScoutWall Sensor" service runs).
              presence    Run the notification-area agent (Windows, started at sign-in).
              version     Show the version.
            """);
        return command is "help" or "-h" or "--help" or "/?" ? 0 : 2;
}
