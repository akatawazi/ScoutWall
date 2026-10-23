using System.Diagnostics;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Response;

/// <summary>
/// Adds and removes ScoutWall block rules in Windows Defender Firewall through its COM API.
/// Every rule is placed in the "ScoutWall" group and named "ScoutWall {action id} ...", so the sensor
/// can always find and remove its own rules without touching anything else.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsFirewall
{
    private const int DirectionInbound = 1;
    private const int DirectionOutbound = 2;
    private const int ActionBlock = 0;
    private const int AllProfiles = 0x7FFFFFFF;

    public static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static HashSet<string> GetRuleNames()
    {
        var ruleNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");

        foreach (dynamic rule in policy.Rules)
        {
            string? grouping = rule.Grouping;
            string? name = rule.Name;
            if (grouping == ResponseAction.RuleGroup && name != null)
                ruleNames.Add(name);
        }

        return ruleNames;
    }

    public static void AddBlockRule(string ruleName, string description, bool isOutbound, string? remoteAddresses, string? applicationPath)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        dynamic rule = CreateComObject("HNetCfg.FWRule");
        rule.Name = ruleName;
        rule.Description = description;
        rule.Grouping = ResponseAction.RuleGroup;
        rule.Direction = isOutbound ? DirectionOutbound : DirectionInbound;
        rule.Action = ActionBlock;
        rule.Profiles = AllProfiles;
        rule.Enabled = true;

        if (!string.IsNullOrEmpty(remoteAddresses))
            rule.RemoteAddresses = remoteAddresses;

        if (!string.IsNullOrEmpty(applicationPath))
            rule.ApplicationName = applicationPath;

        policy.Rules.Add(rule);
    }

    /// <summary>
    /// Lets connections reach the decoy ports, only for the sensor itself and only on home and work networks.
    /// </summary>
    public static void AddDecoyAllowRule(string ruleName, string description, IEnumerable<int> localPorts, string applicationPath)
    {
        const int ActionAllow = 1;
        const int ProtocolTcp = 6;
        const int DomainAndPrivateProfiles = 0x1 | 0x2;

        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        dynamic rule = CreateComObject("HNetCfg.FWRule");
        rule.Name = ruleName;
        rule.Description = description;
        rule.Grouping = ResponseAction.RuleGroup;
        rule.Direction = DirectionInbound;
        rule.Action = ActionAllow;
        rule.Profiles = DomainAndPrivateProfiles;
        rule.Protocol = ProtocolTcp;
        rule.LocalPorts = string.Join(",", localPorts);
        rule.ApplicationName = applicationPath;
        rule.Enabled = true;
        policy.Rules.Add(rule);
    }

    /// <summary>
    /// The current settings of one rule, or null when it doesn't exist.
    /// </summary>
    public static (string? RemoteAddresses, string? LocalPorts)? ReadRule(string ruleName)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        foreach (dynamic rule in policy.Rules)
        {
            string? name = rule.Name;
            if (name == ruleName)
                return ((string?)rule.RemoteAddresses, (string?)rule.LocalPorts);
        }

        return null;
    }

    public static void RemoveRule(string ruleName)
    {
        dynamic policy = CreateComObject("HNetCfg.FwPolicy2");
        policy.Rules.Remove(ruleName);
    }

    public static int RemoveAllRules()
    {
        var ruleNames = GetRuleNames();
        foreach (var ruleName in ruleNames)
            RemoveRule(ruleName);

        return ruleNames.Count;
    }

    private static dynamic CreateComObject(string programId)
    {
        var comType = Type.GetTypeFromProgID(programId)
            ?? throw new InvalidOperationException($"{programId} is not available on this system.");
        return Activator.CreateInstance(comType)!;
    }
}

/// <summary>
/// Outbound throttling through Windows QoS policies (New-NetQosPolicy). Windows QoS can only shape traffic
/// this machine sends, so throttling never slows down inbound data.
/// </summary>
[SupportedOSPlatform("windows")]
public static partial class WindowsQualityOfService
{
    public static HashSet<string> GetPolicyNames()
    {
        var output = RunPowerShell($"Get-NetQosPolicy | Where-Object {{ $_.Name -like '{ResponseAction.RuleNamePrefix}*' }} | ForEach-Object {{ $_.Name }}");
        return output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public static void AddAddressThrottle(string policyName, IPAddress remoteAddress, long bitsPerSecond)
    {
        var prefixLength = remoteAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 128 : 32;
        RunPowerShell($"New-NetQosPolicy -Name {Quote(policyName)} -IPDstPrefixMatchCondition {Quote($"{remoteAddress}/{prefixLength}")} -ThrottleRateActionBitsPerSecond {bitsPerSecond} | Out-Null");
    }

    public static void AddProgramThrottle(string policyName, string applicationPath, long bitsPerSecond)
    {
        if (!SafePathCharacters().IsMatch(applicationPath))
            throw new ArgumentException($"Refusing to throttle '{applicationPath}': the path contains characters that are not safe to pass to PowerShell.");

        RunPowerShell($"New-NetQosPolicy -Name {Quote(policyName)} -AppPathNameMatchCondition {Quote(applicationPath)} -ThrottleRateActionBitsPerSecond {bitsPerSecond} | Out-Null");
    }

    public static void RemovePolicy(string policyName)
    {
        RunPowerShell($"Remove-NetQosPolicy -Name {Quote(policyName)} -Confirm:$false");
    }

    public static int RemoveAllPolicies()
    {
        var policyNames = GetPolicyNames();
        foreach (var policyName in policyNames)
            RemovePolicy(policyName);

        return policyNames.Count;
    }

    /// <summary>
    /// Single-quoted PowerShell literal: nothing inside is expanded, and embedded quotes are doubled.
    /// </summary>
    private static string Quote(string value)
    {
        return "'" + value.Replace("'", "''") + "'";
    }

    /// <summary>
    /// Letters, digits and ordinary path punctuation only. PowerShell treats several Unicode quote marks as
    /// string delimiters, so anything outside this set is rejected rather than escaped.
    /// </summary>
    [System.Text.RegularExpressions.GeneratedRegex(@"^[A-Za-z0-9 :\._\-()]+$")]
    private static partial System.Text.RegularExpressions.Regex SafePathCharacters();

    private static string RunPowerShell(string command)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(command);

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("PowerShell did not finish within 30 seconds.");
        }

        var output = outputTask.GetAwaiter().GetResult();
        var error = errorTask.GetAwaiter().GetResult();

        if (process.ExitCode != 0 || !string.IsNullOrWhiteSpace(error))
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? $"PowerShell exited with {process.ExitCode}." : error.Trim());

        return output;
    }
}
