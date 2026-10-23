namespace ScoutWall.Data;

/// <summary>
/// How the presence agent (running as the signed-in person) talks to the sensor (running as a service): one JSON
/// line each way over a local named pipe. The agent never opens the database, which only ScoutWall's services can read.
/// </summary>
public static class PresenceChannel
{
    public const string PipeName = "ScoutWall.Presence";
    public const int MaximumMessageBytes = 16 * 1024;
}

/// <summary>
/// "report": when the person last used keyboard or mouse. "notifications": ask for desktop notifications to show.
/// </summary>
public record PresenceRequest(string Type, DateTime? LastInputAt);

public record PresenceNotification(string Title, string Message, bool IsSerious);

public record PresenceResponse(bool Ok, List<PresenceNotification> Notifications, string? Error = null);
