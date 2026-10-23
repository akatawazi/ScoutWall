using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// Metadata visible in a TLS ClientHello without decrypting anything: server name, offered ALPN, version.
/// </summary>
[Table("tls_sessions")]
[Index(nameof(ClientIp), nameof(ServerIp), nameof(ServerPort), nameof(ServerName), IsUnique = true)]
[Index(nameof(ServerIp))]
[Index(nameof(ServerName))]
[Index(nameof(LastSeenAt))]
public class TlsSession : Repository<TlsSession>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("client_ip")]
    [MaxLength(45)]
    public string ClientIp { get; set; } = string.Empty;

    [Column("server_ip")]
    [MaxLength(45)]
    public string ServerIp { get; set; } = string.Empty;

    [Column("server_port")]
    public int ServerPort { get; set; }

    [Column("server_name")]
    [MaxLength(256)]
    public string ServerName { get; set; } = string.Empty;

    [Column("tls_version")]
    [MaxLength(16)]
    public string TlsVersion { get; set; } = string.Empty;

    [Column("application_protocols")]
    [MaxLength(128)]
    public string? ApplicationProtocols { get; set; }

    [Column("process_name")]
    [MaxLength(256)]
    public string? ProcessName { get; set; }

    [Column("first_seen_at")]
    public DateTime FirstSeenAt { get; set; }

    [Column("last_seen_at")]
    public DateTime LastSeenAt { get; set; }

    [Column("connection_count")]
    public long ConnectionCount { get; set; }

    public static async Task RecordObservations(DataContext dataContext, IEnumerable<TlsObservation> tlsObservations)
    {
        const string commandText = """
            INSERT INTO tls_sessions
                (client_ip, server_ip, server_port, server_name, tls_version, application_protocols, process_name,
                 first_seen_at, last_seen_at, connection_count)
            VALUES
                ($clientIp, $serverIp, $serverPort, $serverName, $tlsVersion, $applicationProtocols, $processName,
                 $observedAt, $observedAt, 1)
            ON CONFLICT (client_ip, server_ip, server_port, server_name) DO UPDATE SET
                tls_version = excluded.tls_version,
                application_protocols = excluded.application_protocols,
                process_name = coalesce(excluded.process_name, process_name),
                last_seen_at = excluded.last_seen_at,
                connection_count = connection_count + 1;
            """;

        await ExecuteBatch(dataContext, commandText, tlsObservations, (parameters, tlsObservation) =>
        {
            parameters.AddWithValue("$clientIp", tlsObservation.ClientIp);
            parameters.AddWithValue("$serverIp", tlsObservation.ServerIp);
            parameters.AddWithValue("$serverPort", tlsObservation.ServerPort);
            parameters.AddWithValue("$serverName", tlsObservation.ServerName);
            parameters.AddWithValue("$tlsVersion", tlsObservation.TlsVersion);
            parameters.AddWithValue("$applicationProtocols", DatabaseValue(tlsObservation.ApplicationProtocols));
            parameters.AddWithValue("$processName", DatabaseValue(tlsObservation.ProcessName));
            parameters.AddWithValue("$observedAt", tlsObservation.ObservedAt);
        });
    }

    public static async Task<List<TlsSession>> GetRecent(DataContext dataContext, string? search, int count)
    {
        var query = Query(dataContext);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(tlsSession => tlsSession.ServerName.Contains(search)
                || tlsSession.ServerIp.Contains(search)
                || tlsSession.ClientIp.Contains(search));

        return await query
            .OrderByDescending(tlsSession => tlsSession.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<TlsSession>> GetForAddress(DataContext dataContext, string ipAddress, int count)
    {
        return await Query(dataContext)
            .Where(tlsSession => tlsSession.ServerIp == ipAddress || tlsSession.ClientIp == ipAddress)
            .OrderByDescending(tlsSession => tlsSession.LastSeenAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, tlsSession => tlsSession.LastSeenAt < cutoff);
    }
}

public record TlsObservation(
    string ClientIp,
    string ServerIp,
    int ServerPort,
    string ServerName,
    string TlsVersion,
    string? ApplicationProtocols,
    string? ProcessName,
    DateTime ObservedAt);
