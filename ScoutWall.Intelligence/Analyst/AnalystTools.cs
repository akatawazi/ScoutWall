using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Intelligence.Analyst;

public record AnalystToolDefinition(string Name, string Description, Dictionary<string, object> Properties, string[] Required);

/// <summary>
/// Read-only lookups the analyst agent can call while investigating. Every result is wrapped as untrusted data,
/// because hostnames, server names and program names can be chosen by an attacker.
/// </summary>
public class AnalystTools
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

    private readonly DataContext dataContext;

    public AnalystTools(DataContext dataContext)
    {
        this.dataContext = dataContext;
    }

    public static readonly IReadOnlyList<AnalystToolDefinition> Definitions =
    [
        new("get_address_profile",
            "Everything ScoutWall knows about one IP address: owner (ISP, organization, autonomous system), location, blocklist status, DNS and TLS names seen for it, when it was first seen, traffic with it in the last 24 hours, and which programs on this computer talked to it.",
            new() { ["ip"] = new { type = "string", description = "IPv4 or IPv6 address" } },
            ["ip"]),
        new("get_program_profile",
            "Facts about a program on this computer: publisher and version from the executable, when ScoutWall first saw it on the network, how much it sent and received in the last 24 hours and 7 days, how much it sent while nobody was using the computer, and its top destinations.",
            new() { ["program_path"] = new { type = "string", description = "Full path of the executable" } },
            ["program_path"]),
        new("get_traffic_history",
            "Hour-by-hour bytes sent and received for a program, a remote address, or a program talking to a remote address, over up to 7 days. Use it to tell a steady pattern from a sudden change.",
            new()
            {
                ["program_path"] = new { type = "string", description = "Full path of the executable, or empty" },
                ["ip"] = new { type = "string", description = "Remote IP address, or empty" },
                ["hours"] = new { type = "integer", description = "How many hours back, 1 to 168" }
            },
            ["program_path", "ip", "hours"]),
        new("get_related_alerts",
            "Recent alerts that involve an address or a program, with their status and any earlier analyst notes.",
            new()
            {
                ["program_path"] = new { type = "string", description = "Full path of the executable, or empty" },
                ["ip"] = new { type = "string", description = "IP address, or empty" }
            },
            ["program_path", "ip"]),
        new("get_prior_assessments",
            "Earlier analyst conclusions about the same program or destination, so judgements stay consistent and changes stand out.",
            new()
            {
                ["program_path"] = new { type = "string", description = "Full path of the executable, or empty" },
                ["destination"] = new { type = "string", description = "Hostname or IP address, or empty" }
            },
            ["program_path", "destination"]),
        new("get_system_events",
            "Notable Windows events (service installs and crashes, scheduled tasks, failed sign-ins, account and group changes, Defender detections, cleared logs, unexpected restarts, disk problems, app crashes) around a point in time.",
            new()
            {
                ["hours_back"] = new { type = "integer", description = "How many hours before now to look, 1 to 168" },
                ["subject"] = new { type = "string", description = "Only events about this service, task, account or threat name, or empty for all" }
            },
            ["hours_back", "subject"]),
        new("get_service",
            "One Windows service: its program and command line, account, start type, state, and when ScoutWall first saw it (or whether it was already there when ScoutWall was installed).",
            new() { ["service_name"] = new { type = "string", description = "The service's short name" } },
            ["service_name"]),
        new("get_program_resources",
            "Processor and memory use of a program over the last days, and whether it is running right now.",
            new() { ["program_path"] = new { type = "string", description = "Full path of the executable" } },
            ["program_path"])
    ];

    public async Task<string> Execute(string toolName, IReadOnlyDictionary<string, JsonElement> input)
    {
        try
        {
            object result = toolName switch
            {
                "get_address_profile" => await GetAddressProfile(ReadString(input, "ip")),
                "get_program_profile" => await GetProgramProfile(ReadString(input, "program_path")),
                "get_traffic_history" => await GetTrafficHistory(ReadString(input, "program_path"), ReadString(input, "ip"), ReadInteger(input, "hours", 24)),
                "get_related_alerts" => await GetRelatedAlerts(ReadString(input, "program_path"), ReadString(input, "ip")),
                "get_prior_assessments" => await GetPriorAssessments(ReadString(input, "program_path"), ReadString(input, "destination")),
                "get_system_events" => await GetSystemEvents(ReadInteger(input, "hours_back", 24), ReadString(input, "subject")),
                "get_service" => await GetService(ReadString(input, "service_name")),
                "get_program_resources" => await GetProgramResources(ReadString(input, "program_path")),
                _ => new { error = $"Unknown tool {toolName}" }
            };
            return Wrap(result);
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or KeyNotFoundException)
        {
            return Wrap(new { error = exception.Message });
        }
    }

    /// <summary>
    /// Delimits network-derived content so the model reads it as evidence, not as instructions.
    /// </summary>
    public static string Wrap(object result)
    {
        return "<untrusted_network_data>\n" + JsonSerializer.Serialize(result, JsonOptions) + "\n</untrusted_network_data>";
    }

    private async Task<object> GetAddressProfile(string ipAddress)
    {
        var profile = await IpAddressProfile.Get(dataContext, item => item.IpAddress == ipAddress);
        var since = DateTimeOffset.UtcNow.AddHours(-24).ToUnixTimeSeconds();
        var traffic = await dataContext.TrafficMinutes.AsNoTracking()
            .Where(record => record.RemoteIp == ipAddress && record.BucketStart >= since)
            .GroupBy(record => 1)
            .Select(group => new { bytesIn = group.Sum(record => record.BytesIn), bytesOut = group.Sum(record => record.BytesOut), connections = group.Sum(record => record.ConnectionCount) })
            .FirstOrDefaultAsync();
        var programs = await ProcessTrafficMinute.GetForAddress(dataContext, ipAddress, since, 10);
        var dnsNames = await DnsRecord.GetForAddress(dataContext, ipAddress, 10);
        var tlsNames = await TlsSession.GetForAddress(dataContext, ipAddress, 10);

        return new
        {
            ip = ipAddress,
            known = profile != null,
            owner = profile?.Isp,
            organization = profile?.Organization,
            autonomous_system = profile?.AutonomousSystemDisplay,
            location = profile?.LocationDisplay,
            reverse_dns = profile?.ReverseDns,
            is_private = profile?.IsPrivate,
            blocklisted_by = profile?.BlocklistSource,
            first_seen = profile?.FirstSeenAt,
            dns_names = dnsNames.Select(record => record.Hostname).Distinct(),
            tls_server_names = tlsNames.Select(session => new { session.ServerName, session.ServerPort, session.ProcessName }).Distinct(),
            last_24_hours = traffic,
            programs = programs.Select(program => new { program = program.ProcessImage?.ImagePath, program.BytesSent, program.BytesReceived })
        };
    }

    private async Task<object> GetProgramProfile(string programPath)
    {
        var processImage = await ProcessImage.Get(dataContext, item => item.ImagePath == programPath);
        if (processImage == null)
            return new { program_path = programPath, seen_on_network = false };

        var fileInfo = new
        {
            friendly_name = processImage.FriendlyName,
            publisher = processImage.Publisher,
            publisher_verified = processImage.PublisherVerified,
            company = processImage.Company,
            product = processImage.ProductName,
            version = processImage.FileVersion
        };

        var lastDay = DateTimeOffset.UtcNow.AddHours(-24).ToUnixTimeSeconds();
        var lastWeek = DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds();
        var records = dataContext.ProcessTrafficMinutes.AsNoTracking().Where(record => record.ProcessImageId == processImage.Id);

        var dayTotals = await Totals(records.Where(record => record.BucketStart >= lastDay));
        var weekTotals = await Totals(records.Where(record => record.BucketStart >= lastWeek));
        var destinations = await ProcessTrafficMinute.GetRemoteAddresses(dataContext, processImage.Id, lastWeek, 15);

        return new
        {
            program_path = programPath,
            seen_on_network = true,
            first_seen = processImage.FirstSeenAt,
            last_seen = processImage.LastSeenAt,
            file = fileInfo,
            last_24_hours = dayTotals,
            last_7_days = weekTotals,
            top_destinations = destinations.Select(destination => new
            {
                ip = destination.IpAddress,
                name = destination.Hostname,
                owner = destination.Profile?.IspDisplay,
                country = destination.Profile?.CountryName,
                bytes_sent = destination.BytesOut,
                bytes_received = destination.BytesIn
            })
        };
    }

    private static async Task<object> Totals(IQueryable<ProcessTrafficMinute> records)
    {
        return await records
            .GroupBy(record => 1)
            .Select(group => new
            {
                bytes_sent = group.Sum(record => record.BytesSent),
                bytes_received = group.Sum(record => record.BytesReceived),
                bytes_sent_while_idle = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                bytes_received_while_idle = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0),
                bytes_while_presence_unknown = group.Sum(record => record.Presence == PresenceState.Unknown ? record.BytesSent + record.BytesReceived : 0),
                destinations = group.Select(record => record.RemoteIp).Distinct().Count()
            })
            .FirstOrDefaultAsync() ?? (object)new { bytes_sent = 0 };
    }

    private async Task<object> GetTrafficHistory(string programPath, string ipAddress, int hours)
    {
        var since = DateTimeOffset.UtcNow.AddHours(-Math.Clamp(hours, 1, 168)).ToUnixTimeSeconds();

        if (!string.IsNullOrEmpty(programPath))
        {
            var processImage = await ProcessImage.Get(dataContext, item => item.ImagePath == programPath);
            if (processImage == null)
                return new { error = "ScoutWall has no traffic recorded for that program." };

            var records = dataContext.ProcessTrafficMinutes.AsNoTracking()
                .Where(record => record.ProcessImageId == processImage.Id && record.BucketStart >= since);
            if (!string.IsNullOrEmpty(ipAddress))
                records = records.Where(record => record.RemoteIp == ipAddress);

            return await records
                .GroupBy(record => record.BucketStart / 3600)
                .Select(group => new
                {
                    hour = group.Key * 3600,
                    bytes_sent = group.Sum(record => record.BytesSent),
                    bytes_received = group.Sum(record => record.BytesReceived),
                    sent_while_idle = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesSent : 0),
                    received_while_idle = group.Sum(record => record.Presence == PresenceState.Away ? record.BytesReceived : 0)
                })
                .OrderBy(point => point.hour)
                .ToListAsync();
        }

        return await dataContext.TrafficHours.AsNoTracking()
            .Where(record => record.RemoteIp == ipAddress && record.BucketStart >= since)
            .GroupBy(record => record.BucketStart)
            .Select(group => new { hour = group.Key, bytes_in = group.Sum(record => record.BytesIn), bytes_out = group.Sum(record => record.BytesOut) })
            .OrderBy(point => point.hour)
            .ToListAsync();
    }

    private async Task<object> GetRelatedAlerts(string programPath, string ipAddress)
    {
        var since = DateTime.UtcNow.AddDays(-7);
        var alerts = await dataContext.Alerts.AsNoTracking()
            .Where(alert => alert.LastSeenAt >= since
                && ((ipAddress != string.Empty && (alert.SourceIp == ipAddress || alert.DestinationIp == ipAddress))
                    || (programPath != string.Empty && alert.ProcessPath == programPath)))
            .OrderByDescending(alert => alert.LastSeenAt)
            .Take(20)
            .ToListAsync();

        return alerts.Select(alert => new
        {
            alert.RuleName,
            severity = alert.Severity.ToString(),
            status = alert.Status.ToString(),
            alert.Title,
            alert.OccurrenceCount,
            alert.LastSeenAt,
            alert.AnalystNote
        });
    }

    private async Task<object> GetSystemEvents(int hoursBack, string subject)
    {
        var since = DateTime.UtcNow.AddHours(-Math.Clamp(hoursBack, 1, 168));
        var systemEvents = await SystemEvent.GetRecent(dataContext, since, 200);
        var matching = string.IsNullOrWhiteSpace(subject)
            ? systemEvents
            : systemEvents.Where(systemEvent => systemEvent.Subject != null && systemEvent.Subject.Contains(subject, StringComparison.OrdinalIgnoreCase)).ToList();

        return matching.Take(60).Select(systemEvent => new
        {
            at = systemEvent.OccurredAt,
            category = systemEvent.Category.ToString(),
            log = systemEvent.Channel,
            event_id = systemEvent.EventId,
            what = systemEvent.Summary,
            subject = systemEvent.Subject,
            program = systemEvent.ProgramPath,
            address = systemEvent.RemoteAddress,
            count = systemEvent.OccurrenceCount
        });
    }

    private async Task<object> GetService(string serviceName)
    {
        var service = await SystemService.Get(dataContext, item => item.ServiceName == serviceName);
        if (service == null)
            return new { error = $"No service named {serviceName} is known." };

        return new
        {
            name = service.ServiceName,
            display_name = service.DisplayName,
            command = service.BinaryPath,
            account = service.Account,
            start = service.StartMode,
            state = service.State,
            present_when_scoutwall_was_installed = service.IsBaseline,
            first_seen = service.FirstSeenAt,
            removed = service.RemovedAt
        };
    }

    private async Task<object> GetProgramResources(string programPath)
    {
        var processImage = await ProcessImage.Get(dataContext, image => image.ImagePath == programPath);
        var snapshot = await RunningProgramSnapshot.Load(dataContext);
        var runningNow = snapshot.Programs.FirstOrDefault(program => string.Equals(program.ImagePath, programPath, StringComparison.OrdinalIgnoreCase));
        var samples = processImage == null
            ? []
            : await ProcessResourceSample.GetForProgram(dataContext, processImage.Id, DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds());

        return new
        {
            running_now = runningNow == null ? null : new { instances = runningNow.InstanceCount, cpu_percent = runningNow.CpuPercent, memory_bytes = runningNow.MemoryBytes },
            last_7_days = samples.Count == 0
                ? null
                : new
                {
                    average_cpu_percent = Math.Round(samples.Average(sample => sample.CpuPercentAverage), 1),
                    peak_cpu_percent = samples.Max(sample => sample.CpuPercentPeak),
                    peak_memory_bytes = samples.Max(sample => sample.MemoryBytesPeak),
                    five_minute_periods_among_heaviest = samples.Count
                }
        };
    }

    private async Task<object> GetPriorAssessments(string programPath, string destination)
    {
        var assessments = await AnalystAssessment.GetPrior(dataContext, NullIfEmpty(programPath), NullIfEmpty(destination), 10);
        return assessments.Select(assessment => new
        {
            verdict = assessment.VerdictLabel,
            assessment.Title,
            assessment.Explanation,
            assessment.CreatedAt,
            assessment.ProcessPath,
            assessment.Destination,
            assessment.EnvelopeBytesOutPerHour
        });
    }

    internal static string ReadString(IReadOnlyDictionary<string, JsonElement> input, string name)
    {
        return input.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString()!.Trim() : string.Empty;
    }

    internal static int ReadInteger(IReadOnlyDictionary<string, JsonElement> input, string name, int fallback)
    {
        return input.TryGetValue(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : fallback;
    }

    private static string? NullIfEmpty(string value)
    {
        return string.IsNullOrEmpty(value) ? null : value;
    }
}
