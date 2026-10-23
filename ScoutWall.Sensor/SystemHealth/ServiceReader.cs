using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.SystemHealth;

/// <summary>
/// Lists Windows services with their program and account, read from the service manager and the registry
/// rather than WMI, which is slower and can stall.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ServiceReader
{
    public static List<SystemService> Read()
    {
        var services = new List<SystemService>();
        foreach (var serviceController in ServiceController.GetServices())
        {
            using (serviceController)
            {
                try
                {
                    using var serviceKey = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceController.ServiceName}");
                    services.Add(new SystemService
                    {
                        ServiceName = serviceController.ServiceName,
                        DisplayName = serviceController.DisplayName,
                        State = serviceController.Status.ToString(),
                        StartMode = serviceController.StartType.ToString(),
                        BinaryPath = serviceKey?.GetValue("ImagePath") as string,
                        Account = serviceKey?.GetValue("ObjectName") as string
                    });
                }
                catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
                {
                    // The service disappeared while being read; it shows up (or not) on the next pass.
                }
            }
        }

        return services;
    }
}
