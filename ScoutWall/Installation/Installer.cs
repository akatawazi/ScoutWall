using System.Diagnostics;
using System.Reflection;

namespace ScoutWall.Installation;

/// <summary>
/// "scoutwall install" and "scoutwall uninstall". The executable copies itself into place and sets up the two
/// services (web console and sensor), so installing is one command and upgrading is the same command again.
/// </summary>
public static class Installer
{
    public const int DefaultPort = 5215;

    public static string Version => ScoutWall.Data.ScoutWallVersion.Current;

    public static async Task<int> Install(string[] args)
    {
        if (!Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine(OperatingSystem.IsWindows()
                ? "Run this from an administrator prompt (right-click PowerShell or Terminal, \"Run as administrator\")."
                : "Run this as root, for example: sudo ./scoutwall install");
            return 1;
        }

        var port = ReadInteger(args, "--port") ?? DefaultPort;
        var start = !args.Contains("--no-start", StringComparer.OrdinalIgnoreCase);
        try
        {
            if (OperatingSystem.IsWindows())
                await WindowsInstaller.Install(port, start);
            else if (OperatingSystem.IsLinux())
                await LinuxInstaller.Install(port, start);
            else
                throw new PlatformNotSupportedException("ScoutWall installs on Windows and Linux.");

            return 0;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            Console.Error.WriteLine($"Install failed: {exception.Message}");
            return 1;
        }
    }

    public static async Task<int> Uninstall(string[] args)
    {
        if (!Environment.IsPrivilegedProcess)
        {
            Console.Error.WriteLine(OperatingSystem.IsWindows() ? "Run this from an administrator prompt." : "Run this as root (sudo).");
            return 1;
        }

        var deleteData = args.Contains("--delete-data", StringComparer.OrdinalIgnoreCase);
        try
        {
            if (OperatingSystem.IsWindows())
                await WindowsInstaller.Uninstall(deleteData);
            else if (OperatingSystem.IsLinux())
                await LinuxInstaller.Uninstall(deleteData);

            return 0;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            Console.Error.WriteLine($"Uninstall failed: {exception.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Waits until the console answers, so the sensor starts after the schema is in place.
    /// </summary>
    public static async Task<bool> WaitForConsole(int port, TimeSpan timeout)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var stopwatch = Stopwatch.StartNew();
        while (stopwatch.Elapsed < timeout)
        {
            try
            {
                using var response = await http.GetAsync($"http://localhost:{port}/Account/Login");
                if ((int)response.StatusCode < 500)
                    return true;
            }
            catch (HttpRequestException)
            {
            }
            catch (TaskCanceledException)
            {
            }

            await Task.Delay(1000);
        }

        return false;
    }

    /// <summary>
    /// Runs a program and returns its exit code and output. Arguments are passed one by one, never through a shell.
    /// </summary>
    public static (int ExitCode, string Output) Run(string fileName, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(fileName)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start {fileName}.");
        var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output.Trim());
    }

    public static void RunOrThrow(string fileName, params string[] arguments)
    {
        var (exitCode, output) = Run(fileName, arguments);
        if (exitCode != 0)
            throw new InvalidOperationException($"{Path.GetFileName(fileName)} {string.Join(' ', arguments)} failed: {output}");
    }

    public static void Step(string text)
    {
        Console.WriteLine($"  - {text}");
    }

    private static int? ReadInteger(string[] args, string name)
    {
        var index = Array.FindIndex(args, argument => string.Equals(argument, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length && int.TryParse(args[index + 1], out var value) && value is > 0 and < 65536 ? value : null;
    }
}
