using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.EntityFrameworkCore;

namespace ScoutWall.Data.Models;

/// <summary>
/// An HTTP request recovered from TLS traffic using session keys from an SSLKEYLOGFILE.
/// Only request metadata is stored: never bodies, cookies, authorization headers or query strings.
/// </summary>
[Table("decrypted_requests")]
[Index(nameof(CapturedAt))]
[Index(nameof(ServerIp))]
[Index(nameof(Host))]
public class DecryptedRequest : Repository<DecryptedRequest>
{
    [Key]
    [Column("id")]
    public long Id { get; set; }

    [Column("captured_at")]
    public DateTime CapturedAt { get; set; }

    [Column("client_ip")]
    [MaxLength(45)]
    public string ClientIp { get; set; } = string.Empty;

    [Column("server_ip")]
    [MaxLength(45)]
    public string ServerIp { get; set; } = string.Empty;

    [Column("server_port")]
    public int ServerPort { get; set; }

    [Column("http_version")]
    [MaxLength(16)]
    public string HttpVersion { get; set; } = string.Empty;

    [Column("method")]
    [MaxLength(16)]
    public string Method { get; set; } = string.Empty;

    [Column("host")]
    [MaxLength(256)]
    public string Host { get; set; } = string.Empty;

    [Column("path")]
    [MaxLength(2048)]
    public string Path { get; set; } = string.Empty;

    [Column("user_agent")]
    [MaxLength(512)]
    public string? UserAgent { get; set; }

    [Column("source_file")]
    [MaxLength(260)]
    public string SourceFile { get; set; } = string.Empty;

    public static string RemoveQueryString(string path)
    {
        var queryIndex = path.IndexOf('?');
        return queryIndex < 0 ? path : path[..queryIndex];
    }

    public static async Task InsertBatch(DataContext dataContext, IEnumerable<DecryptedRequest> decryptedRequests)
    {
        dataContext.DecryptedRequests.AddRange(decryptedRequests);
        await dataContext.SaveChangesAsync();
        dataContext.ChangeTracker.Clear();
    }

    public static async Task<List<DecryptedRequest>> GetRecent(DataContext dataContext, string? search, int count)
    {
        var query = Query(dataContext);
        if (!string.IsNullOrWhiteSpace(search))
            query = query.Where(decryptedRequest => decryptedRequest.Host.Contains(search)
                || decryptedRequest.Path.Contains(search)
                || decryptedRequest.ServerIp.Contains(search)
                || decryptedRequest.ClientIp.Contains(search));

        return await query
            .OrderByDescending(decryptedRequest => decryptedRequest.CapturedAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<List<DecryptedRequest>> GetForAddress(DataContext dataContext, string ipAddress, int count)
    {
        return await Query(dataContext)
            .Where(decryptedRequest => decryptedRequest.ServerIp == ipAddress || decryptedRequest.ClientIp == ipAddress)
            .OrderByDescending(decryptedRequest => decryptedRequest.CapturedAt)
            .Take(count)
            .ToListAsync();
    }

    public static async Task<int> DeleteBefore(DataContext dataContext, DateTime cutoff)
    {
        return await DeleteWhere(dataContext, decryptedRequest => decryptedRequest.CapturedAt < cutoff);
    }
}
