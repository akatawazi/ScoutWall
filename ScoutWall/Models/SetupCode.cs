using System.Net;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace ScoutWall.Models;

/// <summary>
/// Protects first-time setup. From this computer, setup just works. From anywhere else it needs a one-time code,
/// valid for 15 minutes and usable once, written to a file only administrators can read.
/// </summary>
public static class SetupCode
{
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private static readonly object SyncRoot = new();
    private static string? currentCode;
    private static DateTime expiresAt;

    public static string? CodeFilePath { get; private set; }

    public static bool IsLocalRequest(HttpContext httpContext)
    {
        var remoteAddress = httpContext.Connection.RemoteIpAddress;
        return remoteAddress != null && IPAddress.IsLoopback(remoteAddress);
    }

    /// <summary>
    /// Makes sure a valid code exists, creating a new one (and its file) when there is none or it expired.
    /// </summary>
    public static void EnsureIssued(string dataDirectory)
    {
        lock (SyncRoot)
        {
            if (currentCode != null && DateTime.UtcNow < expiresAt)
                return;

            var codeBuilder = new StringBuilder();
            for (var index = 0; index < 8; index++)
                codeBuilder.Append(Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]);

            currentCode = codeBuilder.ToString();
            expiresAt = DateTime.UtcNow.Add(Lifetime);
            CodeFilePath = Path.Combine(dataDirectory, "setup-code.txt");
            WriteCodeFile(CodeFilePath, currentCode, expiresAt);
        }
    }

    public static bool Matches(string? candidate)
    {
        lock (SyncRoot)
        {
            if (currentCode == null || DateTime.UtcNow >= expiresAt || string.IsNullOrWhiteSpace(candidate))
                return false;

            var expected = Encoding.UTF8.GetBytes(currentCode);
            var supplied = Encoding.UTF8.GetBytes(candidate.Trim().ToUpperInvariant());
            return CryptographicOperations.FixedTimeEquals(expected, supplied);
        }
    }

    public static void Consume()
    {
        lock (SyncRoot)
        {
            currentCode = null;
            if (CodeFilePath != null)
                TryDelete(CodeFilePath);
        }
    }

    private static void WriteCodeFile(string filePath, string code, DateTime validUntil)
    {
        try
        {
            File.WriteAllText(filePath, $"ScoutWall setup code: {code}\r\nValid until {validUntil:u}. It works once.\r\n");
            if (OperatingSystem.IsWindows())
                RestrictToAdministrators(filePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Setup from this computer still works without the file.
        }
    }

    /// <summary>
    /// ProgramData is readable by every local user, so the code file is limited to Administrators and SYSTEM.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static void RestrictToAdministrators(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        var fileSecurity = new FileSecurity();
        fileSecurity.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        fileSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        fileSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));

        // The console's own service account, so it can delete the file once the code is used.
        if (WindowsIdentity.GetCurrent().User is { } consoleAccount)
            fileSecurity.AddAccessRule(new FileSystemAccessRule(consoleAccount, FileSystemRights.FullControl, AccessControlType.Allow));

        fileInfo.SetAccessControl(fileSecurity);
    }

    private static void TryDelete(string filePath)
    {
        try
        {
            File.Delete(filePath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
