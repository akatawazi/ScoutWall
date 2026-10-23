using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace ScoutWall.Data;

/// <summary>
/// Encrypts configuration secrets (API keys, SMTP password, webhook addresses) before they are stored.
/// On Windows: DPAPI in machine scope, so the web console and the sensor on the same machine can both read them.
/// On Linux: AES-GCM with a random key in a file next to the database that only ScoutWall's account can read.
/// Either way this protects the database file when it is copied elsewhere, not against the machine's administrators.
/// </summary>
public static class SecretProtector
{
    private const string ProtectedPrefix = "dpapi:";
    private const string KeyFilePrefix = "aesgcm:";
    private const string KeyFileName = "secret.key";

    /// <summary>
    /// The folder holding the Linux key file; set from the database location when the data context is created.
    /// </summary>
    public static string? KeyFolder { get; set; }
    private const string RedactedValue = "********";
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("ScoutWall.Settings");
    private static readonly string[] SecretPropertyNames = ["SmtpPassword", "WebhookUrl", "ApiKey", "OpenAiApiKey", "OpenRouterApiKey", "WebhookSecret"];

    public static string? Protect(string? plainText)
    {
        if (string.IsNullOrEmpty(plainText) || IsProtected(plainText))
            return plainText;

        if (!OperatingSystem.IsWindows())
            return EncryptWithKeyFile(plainText);

        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(plainText), Entropy, DataProtectionScope.LocalMachine);
        return ProtectedPrefix + Convert.ToBase64String(protectedBytes);
    }

    public static string? Unprotect(string? storedValue)
    {
        if (string.IsNullOrEmpty(storedValue) || !IsProtected(storedValue))
            return storedValue;

        if (storedValue.StartsWith(KeyFilePrefix, StringComparison.Ordinal))
            return DecryptWithKeyFile(storedValue);

        if (!OperatingSystem.IsWindows())
            return null;

        var protectedBytes = Convert.FromBase64String(storedValue[ProtectedPrefix.Length..]);
        var plainBytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine);
        return Encoding.UTF8.GetString(plainBytes);
    }

    public static bool IsProtected(string? storedValue)
    {
        return storedValue != null
            && (storedValue.StartsWith(ProtectedPrefix, StringComparison.Ordinal) || storedValue.StartsWith(KeyFilePrefix, StringComparison.Ordinal));
    }

    private static string EncryptWithKeyFile(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using (var aes = new AesGcm(ReadOrCreateKey(), tag.Length))
            aes.Encrypt(nonce, plainBytes, cipherBytes, tag, Entropy);

        return KeyFilePrefix + Convert.ToBase64String([.. nonce, .. tag, .. cipherBytes]);
    }

    private static string? DecryptWithKeyFile(string storedValue)
    {
        var bytes = Convert.FromBase64String(storedValue[KeyFilePrefix.Length..]);
        var nonceSize = AesGcm.NonceByteSizes.MaxSize;
        var tagSize = AesGcm.TagByteSizes.MaxSize;
        if (bytes.Length < nonceSize + tagSize)
            return null;

        var plainBytes = new byte[bytes.Length - nonceSize - tagSize];
        try
        {
            using var aes = new AesGcm(ReadOrCreateKey(), tagSize);
            aes.Decrypt(bytes.AsSpan(0, nonceSize), bytes.AsSpan(nonceSize + tagSize), bytes.AsSpan(nonceSize, tagSize), plainBytes, Entropy);
            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (CryptographicException)
        {
            // The key file was replaced; the secret has to be entered again.
            return null;
        }
    }

    /// <summary>
    /// The 256-bit key, created on first use with permissions for ScoutWall's own account only (0600).
    /// </summary>
    private static byte[] ReadOrCreateKey()
    {
        var folder = KeyFolder ?? throw new InvalidOperationException("The secret key folder is not set.");
        var keyPath = Path.Combine(folder, KeyFileName);
        if (File.Exists(keyPath))
            return File.ReadAllBytes(keyPath);

        Directory.CreateDirectory(folder);
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

            using var stream = new FileStream(keyPath, options);
            stream.Write(key);
            return key;
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            // The web console and the sensor started together and the other one wrote it first.
            return File.ReadAllBytes(keyPath);
        }
    }

    /// <summary>
    /// Replaces secret values in a settings JSON document so it can be written to the audit log.
    /// </summary>
    public static string RedactJson(string json)
    {
        if (JsonNode.Parse(json) is not JsonObject jsonObject)
            return json;

        foreach (var propertyName in SecretPropertyNames)
        {
            if (jsonObject[propertyName] != null)
                jsonObject[propertyName] = RedactedValue;
        }

        return jsonObject.ToJsonString();
    }
}
