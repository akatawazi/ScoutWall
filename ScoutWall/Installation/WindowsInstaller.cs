using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;
using ScoutWall.Data;
using ScoutWall.Sensor;

namespace ScoutWall.Installation;

/// <summary>
/// Windows: copies scoutwall.exe to Program Files, installs the console as the "ScoutWall Web" service under its
/// own low-privilege virtual account and the sensor as "ScoutWall Sensor" (LocalSystem), locks the data folder down
/// to SYSTEM, Administrators and the console's account, registers the boot-time firewall rescue task and starts the
/// presence agent at every sign-in.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsInstaller
{
    private const string RescueTaskName = "ScoutWall Firewall Rescue";
    private const string LegacyPresenceTaskName = "ScoutWall Presence";
    private const string RunKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string RunValueName = "ScoutWall Presence";
    private static readonly string WebAccount = $@"NT SERVICE\{WebConsole.ServiceName}";

    private static string InstallFolder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "ScoutWall");
    private static string InstalledExecutable => Path.Combine(InstallFolder, "scoutwall.exe");
    private static string Sc => Path.Combine(Environment.SystemDirectory, "sc.exe");
    private static string Schtasks => Path.Combine(Environment.SystemDirectory, "schtasks.exe");

    public static async Task Install(int port, bool start)
    {
        Console.WriteLine($"Installing ScoutWall {Installer.Version}");
        var dataFolder = ScoutWallPaths.DataFolder;
        var runtimeFolder = Path.Combine(dataFolder, "runtime");

        // Running programs can't be replaced, so everything stops first (an upgrade looks just like an install).
        StopService(SensorHost.ServiceName);
        StopService(WebConsole.ServiceName);
        StopPresenceAgents();

        Directory.CreateDirectory(InstallFolder);
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Can't tell where this program is.");
        if (!string.Equals(Path.GetFullPath(source), InstalledExecutable, StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(source, InstalledExecutable, overwrite: true);
            Installer.Step($"Copied to {InstalledExecutable}");
        }

        RemoveLegacyLayout();

        var webArguments = $"web --urls http://localhost:{port}";
        InstallService(WebConsole.ServiceName, webArguments, WebAccount,
            $"ScoutWall web console on http://localhost:{port} (this computer only).", runtimeFolder);
        InstallService(SensorHost.ServiceName, "sensor", "LocalSystem",
            "ScoutWall network sensor: capture, detection, the analyst and firewall responses.", runtimeFolder);
        Installer.Step("Services installed: ScoutWall Web (own account) and ScoutWall Sensor (LocalSystem)");

        SecureDataFolder(dataFolder);
        Directory.CreateDirectory(runtimeFolder);
        Installer.Step($"Data folder {dataFolder} limited to SYSTEM, Administrators and the console");

        Installer.RunOrThrow(Schtasks, "/Create", "/TN", RescueTaskName, "/TR", $"\"{InstalledExecutable}\" rescue --at-boot",
            "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST", "/F");
        Installer.Step("Boot-time firewall rescue task registered");

        // Started through the headless console host so no window appears at sign-in.
        using (var runKey = Registry.LocalMachine.CreateSubKey(RunKeyPath))
            runKey.SetValue(RunValueName, PresenceCommand(port));
        Installer.Step("Presence agent starts at every sign-in");

        if (!File.Exists(Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll")))
            Installer.Step("Npcap isn't installed: using Windows' built-in packet capture (install Npcap from npcap.com for faster capture)");

        if (!start)
        {
            Console.WriteLine("Installed. Start the services with: sc start \"ScoutWall Web\" and sc start \"ScoutWall Sensor\"");
            return;
        }

        // The console owns the database schema, so it starts (and upgrades the database) before the sensor.
        new ServiceController(WebConsole.ServiceName).Start();
        if (!await Installer.WaitForConsole(port, TimeSpan.FromSeconds(90)))
            throw new InvalidOperationException("The web console didn't start. See Windows Event Viewer, Application log, source \"ScoutWall Web\".");

        new ServiceController(SensorHost.ServiceName).Start();
        StartPresenceForCurrentUser(port);

        Console.WriteLine();
        Console.WriteLine($"ScoutWall is running. Open http://localhost:{port} (the first time, it asks you to create your account).");
        Console.WriteLine($"Emergency: \"{InstalledExecutable}\" rescue (as administrator) removes every ScoutWall firewall rule.");
    }

    public static async Task Uninstall(bool deleteData)
    {
        Console.WriteLine("Removing ScoutWall");
        StopService(SensorHost.ServiceName);
        await RescueCommand.Run([]);

        StopService(WebConsole.ServiceName);
        StopPresenceAgents();
        foreach (var serviceName in new[] { SensorHost.ServiceName, WebConsole.ServiceName })
        {
            if (ServiceExists(serviceName))
                Installer.Run(Sc, "delete", serviceName);
            if (EventLog.SourceExists(serviceName))
                EventLog.DeleteEventSource(serviceName);
        }

        Installer.Run(Schtasks, "/Delete", "/TN", RescueTaskName, "/F");
        Installer.Run(Schtasks, "/Delete", "/TN", LegacyPresenceTaskName, "/F");
        using (var runKey = Registry.LocalMachine.OpenSubKey(RunKeyPath, writable: true))
            runKey?.DeleteValue(RunValueName, throwOnMissingValue: false);
        Installer.Step("Services, tasks and the sign-in agent removed");

        var dataFolder = ScoutWallPaths.DataFolder;
        if (deleteData && Directory.Exists(dataFolder))
        {
            Directory.Delete(dataFolder, recursive: true);
            Installer.Step($"Deleted {dataFolder}");
        }
        else
        {
            Installer.Step($"Kept your data in {dataFolder} (delete it, or run uninstall --delete-data, to remove it)");
        }

        // This program may be the one in Program Files; it is removed a moment after it exits.
        if (Directory.Exists(InstallFolder))
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                $"/c ping 127.0.0.1 -n 3 > nul & rd /s /q \"{InstallFolder}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }

        Console.WriteLine("ScoutWall removed.");
    }

    private static void InstallService(string name, string arguments, string account, string description, string runtimeFolder)
    {
        var binaryPath = $"\"{InstalledExecutable}\" {arguments}";
        if (ServiceExists(name))
            Installer.RunOrThrow(Sc, "config", name, "binPath=", binaryPath, "start=", "auto", "obj=", account, "DisplayName=", name);
        else
            Installer.RunOrThrow(Sc, "create", name, "binPath=", binaryPath, "start=", "auto", "obj=", account, "DisplayName=", name);

        Installer.Run(Sc, "description", name, description);
        Installer.Run(Sc, "failure", name, "reset=", "86400", "actions=", "restart/5000/restart/30000/restart/60000");

        // Where the single-file executable unpacks its files: inside the protected data folder, not a temp folder.
        using (var serviceKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}", writable: true))
            serviceKey?.SetValue("Environment", new[] { $"DOTNET_BUNDLE_EXTRACT_BASE_DIR={runtimeFolder}" }, RegistryValueKind.MultiString);

        if (!EventLog.SourceExists(name))
            EventLog.CreateEventSource(name, "Application");
    }

    /// <summary>
    /// The folder holds browsing history, file activity and presence, so only SYSTEM (the sensor), Administrators
    /// and the console's own service account may open it. Inherited permissions (Users can read ProgramData) are cut.
    /// </summary>
    private static void SecureDataFolder(string dataFolder)
    {
        var directory = Directory.CreateDirectory(dataFolder);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        const InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new NTAccount(WebAccount), FileSystemRights.Modify, inherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(security);

        // Files and folders created earlier with their own permissions (older versions granted every user access)
        // are reset to inherit from the folder.
        foreach (var entry in directory.EnumerateFileSystemInfos("*", SearchOption.AllDirectories))
        {
            try
            {
                if (entry is DirectoryInfo childDirectory)
                {
                    var childSecurity = new DirectorySecurity();
                    childSecurity.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                    childDirectory.SetAccessControl(childSecurity);
                }
                else if (entry is FileInfo file && file.Name != "setup-code.txt")
                {
                    var childSecurity = new FileSecurity();
                    childSecurity.SetAccessRuleProtection(isProtected: false, preserveInheritance: false);
                    file.SetAccessControl(childSecurity);
                }
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or IOException)
            {
                // A file in use keeps its permissions until the next install.
            }
        }
    }

    /// <summary>
    /// Earlier versions installed three programs in subfolders and started the agent with a scheduled task.
    /// </summary>
    private static void RemoveLegacyLayout()
    {
        Installer.Run(Schtasks, "/Delete", "/TN", LegacyPresenceTaskName, "/F");
        foreach (var folder in new[] { "Sensor", "Web", "Presence" })
        {
            var path = Path.Combine(InstallFolder, folder);
            try
            {
                if (Directory.Exists(path))
                    Directory.Delete(path, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Installer.Step($"Couldn't remove the old {path} folder yet: {exception.Message}");
            }
        }
    }

    private static void StopService(string name)
    {
        if (!ServiceExists(name))
            return;

        using var service = new ServiceController(name);
        if (service.Status is ServiceControllerStatus.Stopped)
            return;

        try
        {
            service.Stop();
            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(60));
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ServiceProcess.TimeoutException)
        {
            Installer.Step($"{name} didn't stop cleanly: {exception.Message}");
        }
    }

    /// <summary>
    /// Stops presence agents run from the installed program (or the old separate agent), and nothing else: a
    /// scoutwall.exe started from a development folder is left alone.
    /// </summary>
    private static void StopPresenceAgents()
    {
        var self = Environment.ProcessId;
        foreach (var process in Process.GetProcessesByName("scoutwall").Concat(Process.GetProcessesByName("ScoutWall.Presence")))
        {
            using (process)
            {
                if (process.Id == self)
                    continue;

                try
                {
                    var path = process.MainModule?.FileName ?? string.Empty;
                    var isInstalled = path.StartsWith(InstallFolder + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
                    if (!isInstalled)
                        continue;

                    process.Kill();
                    process.WaitForExit(5000);
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
                {
                }
            }
        }
    }

    /// <summary>
    /// The installer runs as administrator; the agent should run as the person, so it is started with a normal
    /// (non-elevated) token. It also starts at every sign-in.
    /// </summary>
    private static void StartPresenceForCurrentUser(int port)
    {
        try
        {
            Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "runas.exe"),
                $"/trustlevel:0x20000 \"{PresenceCommand(port).Replace("\"", "\\\"")}\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false
            });
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            Installer.Step("Scout appears in the notification area after your next sign-in");
        }
    }

    private static string PresenceCommand(int port)
    {
        return $"\"{Path.Combine(Environment.SystemDirectory, "conhost.exe")}\" --headless \"{InstalledExecutable}\" presence --url http://localhost:{port}";
    }

    private static bool ServiceExists(string name)
    {
        return ServiceController.GetServices().Any(service => string.Equals(service.ServiceName, name, StringComparison.OrdinalIgnoreCase));
    }
}
