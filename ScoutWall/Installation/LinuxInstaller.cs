using System.Runtime.Versioning;
using ScoutWall.Data;

namespace ScoutWall.Installation;

/// <summary>
/// Linux: copies the executable to /opt/scoutwall, creates the "scoutwall" system account and /var/lib/scoutwall
/// (readable by that account only), and installs two systemd services. The sensor runs as the same unprivileged
/// account with just the capabilities packet capture and the decoy ports need; nothing runs as root.
/// </summary>
[SupportedOSPlatform("linux")]
public static class LinuxInstaller
{
    private const string Account = "scoutwall";
    private const string InstallFolder = "/opt/scoutwall";
    private const string Executable = InstallFolder + "/scoutwall";
    private const string WebUnit = "scoutwall-web.service";
    private const string SensorUnit = "scoutwall-sensor.service";
    private const string UnitFolder = "/etc/systemd/system";

    public static async Task Install(int port, bool start)
    {
        Console.WriteLine($"Installing ScoutWall {Installer.Version}");
        var dataFolder = ScoutWallPaths.DataFolder;

        Installer.Run("systemctl", "stop", SensorUnit);
        Installer.Run("systemctl", "stop", WebUnit);

        Directory.CreateDirectory(InstallFolder);
        var source = Environment.ProcessPath ?? throw new InvalidOperationException("Can't tell where this program is.");
        if (!string.Equals(Path.GetFullPath(source), Executable, StringComparison.Ordinal))
        {
            File.Copy(source, Executable, overwrite: true);
            Installer.Step($"Copied to {Executable}");
        }

        File.SetUnixFileMode(Executable, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);

        if (Installer.Run("id", "-u", Account).ExitCode != 0)
        {
            Installer.RunOrThrow("useradd", "--system", "--home-dir", dataFolder, "--no-create-home", "--shell", "/usr/sbin/nologin", Account);
            Installer.Step($"Created the system account \"{Account}\"");
        }

        Directory.CreateDirectory(Path.Combine(dataFolder, "runtime"));
        Installer.RunOrThrow("chown", "-R", $"{Account}:{Account}", dataFolder);
        Installer.RunOrThrow("chmod", "750", dataFolder);
        Installer.Step($"Data folder {dataFolder} readable by the {Account} account only");

        if (!HasLibpcap())
            Installer.Step("libpcap isn't installed, so live capture won't work yet: install it (Debian/Ubuntu: apt install libpcap0.8, Fedora: dnf install libpcap)");

        var environment = $"""
            Environment=SCOUTWALL_DATA={dataFolder}
            Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR={dataFolder}/runtime
            Environment=ASPNETCORE_ENVIRONMENT=Production
            Environment=DOTNET_hostBuilder__reloadConfigOnChange=false
            WorkingDirectory={dataFolder}
            """;
        var hardening = $"""
            NoNewPrivileges=true
            ProtectSystem=strict
            ProtectHome=true
            PrivateTmp=true
            ReadWritePaths={dataFolder}
            Restart=on-failure
            RestartSec=5
            """;

        await File.WriteAllTextAsync(Path.Combine(UnitFolder, WebUnit), $"""
            [Unit]
            Description=ScoutWall web console (http://localhost:{port})
            After=network-online.target

            [Service]
            Type=notify
            User={Account}
            Group={Account}
            ExecStart={Executable} web --urls http://localhost:{port}
            {environment}
            {hardening}

            [Install]
            WantedBy=multi-user.target

            """);

        await File.WriteAllTextAsync(Path.Combine(UnitFolder, SensorUnit), $"""
            [Unit]
            Description=ScoutWall network sensor
            After=network-online.target {WebUnit}
            Wants={WebUnit}

            [Service]
            Type=notify
            User={Account}
            Group={Account}
            ExecStart={Executable} sensor
            AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
            CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
            {environment}
            {hardening}

            [Install]
            WantedBy=multi-user.target

            """);

        Installer.RunOrThrow("systemctl", "daemon-reload");
        Installer.RunOrThrow("systemctl", "enable", WebUnit, SensorUnit);
        Installer.Step("systemd services installed: scoutwall-web and scoutwall-sensor");

        if (!start)
        {
            Console.WriteLine("Installed. Start it with: systemctl start scoutwall-web scoutwall-sensor");
            return;
        }

        Installer.RunOrThrow("systemctl", "start", WebUnit);
        if (!await Installer.WaitForConsole(port, TimeSpan.FromSeconds(90)))
            throw new InvalidOperationException("The web console didn't start. See: journalctl -u scoutwall-web");

        Installer.RunOrThrow("systemctl", "start", SensorUnit);
        Console.WriteLine();
        Console.WriteLine($"ScoutWall is running. Open http://localhost:{port} (the first time, it asks you to create your account).");
        Console.WriteLine("On Linux, ScoutWall watches and alerts; per-program tracking and blocking are Windows-only for now.");
    }

    public static Task Uninstall(bool deleteData)
    {
        Console.WriteLine("Removing ScoutWall");
        foreach (var unit in new[] { SensorUnit, WebUnit })
        {
            Installer.Run("systemctl", "disable", "--now", unit);
            File.Delete(Path.Combine(UnitFolder, unit));
        }

        Installer.Run("systemctl", "daemon-reload");
        if (Directory.Exists(InstallFolder))
            Directory.Delete(InstallFolder, recursive: true);
        Installer.Step("Services and program removed");

        var dataFolder = ScoutWallPaths.DataFolder;
        if (deleteData)
        {
            if (Directory.Exists(dataFolder))
                Directory.Delete(dataFolder, recursive: true);
            Installer.Run("userdel", Account);
            Installer.Step($"Deleted {dataFolder} and the {Account} account");
        }
        else
        {
            Installer.Step($"Kept your data in {dataFolder} (run uninstall --delete-data to remove it)");
        }

        Console.WriteLine("ScoutWall removed.");
        return Task.CompletedTask;
    }

    private static bool HasLibpcap()
    {
        var (exitCode, output) = Installer.Run("ldconfig", "-p");
        return exitCode == 0 && output.Contains("libpcap.so", StringComparison.Ordinal);
    }
}
