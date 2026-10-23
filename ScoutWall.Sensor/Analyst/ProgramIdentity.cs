using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace ScoutWall.Sensor.Analyst;

/// <param name="PublisherVerified">Windows verified the signature, either embedded or through a system catalog.</param>
public record ProgramFileInfo(string Fingerprint, long Size, DateTime LastWriteUtc, string? Publisher, bool PublisherVerified, string? Company, string? Product,
    string? Description, string? Version);

/// <summary>
/// Identifies a program build (size and timestamp) and reads its publisher information, so a remembered
/// conclusion stops applying when the executable is replaced.
/// </summary>
public static class ProgramIdentity
{
    private static readonly ConcurrentDictionary<string, (DateTime ReadAt, ProgramFileInfo? Info)> Cache = new();
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(10);

    public static ProgramFileInfo? Read(string? imagePath)
    {
        if (string.IsNullOrEmpty(imagePath) || !Path.IsPathFullyQualified(imagePath))
            return null;

        if (Cache.TryGetValue(imagePath, out var cached) && DateTime.UtcNow - cached.ReadAt < CacheLifetime)
            return cached.Info;

        var programFileInfo = ReadUncached(imagePath);
        Cache[imagePath] = (DateTime.UtcNow, programFileInfo);
        return programFileInfo;
    }

    public static string? Fingerprint(string? imagePath)
    {
        return Read(imagePath)?.Fingerprint;
    }

    private static ProgramFileInfo? ReadUncached(string imagePath)
    {
        try
        {
            var fileInfo = new FileInfo(imagePath);
            if (!fileInfo.Exists)
                return null;

            var versionInfo = FileVersionInfo.GetVersionInfo(imagePath);
            var signature = CodeSignature.Verify(imagePath);
            return new ProgramFileInfo(
                $"{fileInfo.Length:x}-{fileInfo.LastWriteTimeUtc.Ticks:x}",
                fileInfo.Length,
                fileInfo.LastWriteTimeUtc,
                signature?.Signer ?? ReadPublisher(imagePath),
                signature != null,
                versionInfo.CompanyName,
                versionInfo.ProductName,
                versionInfo.FileDescription,
                versionInfo.FileVersion);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// The subject of the embedded Authenticode certificate, for files whose signature Windows didn't verify (or
    /// off Windows). It shows who claims to have signed the file, so it is only a hint alongside the path and behaviour.
    /// </summary>
    private static string? ReadPublisher(string imagePath)
    {
        try
        {
            using var certificate = X509CertificateLoader.LoadCertificate(X509Certificate.CreateFromSignedFile(imagePath).GetRawCertData());
            return certificate.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            return null;
        }
    }
}
