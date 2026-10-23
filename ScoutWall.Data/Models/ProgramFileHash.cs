using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace ScoutWall.Data.Models;

/// <summary>
/// SHA-256 of a program file, cached by size and last write time so repeated allowlist checks don't reread it.
/// </summary>
public static class ProgramFileHash
{
    private static readonly ConcurrentDictionary<(string Path, long Length, DateTime LastWriteUtc), string> Cache = new();

    /// <summary>
    /// The lowercase hex hash, or null when the file can't be read.
    /// </summary>
    public static string? Compute(string path)
    {
        try
        {
            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists)
                return null;

            var key = (path.ToLowerInvariant(), fileInfo.Length, fileInfo.LastWriteTimeUtc);
            if (Cache.TryGetValue(key, out var cachedHash))
                return cachedHash;

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var hash = Convert.ToHexStringLower(SHA256.HashData(stream));
            if (Cache.Count > 2000)
                Cache.Clear();

            Cache[key] = hash;
            return hash;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
