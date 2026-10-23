using System.Runtime.InteropServices;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Presence;

/// <summary>
/// Whether a person is using the machine. IsIdle is null when the sensor has no way to tell.
/// </summary>
public record IdleState(bool? IsIdle, TimeSpan? IdleFor, string Source)
{
    public static IdleState Unknown { get; } = new(null, null, "Unknown");
}

/// <summary>
/// Works out whether anyone is at the keyboard. Sources, best first:
/// 1. the presence agent running in each user session (real keyboard and mouse idle time),
/// 2. GetLastInputInfo when the sensor itself runs in an interactive session,
/// 3. Windows session state: every session locked or disconnected counts as idle.
/// </summary>
public static class IdleDetector
{
    private static readonly TimeSpan PresenceReportMaximumAge = TimeSpan.FromSeconds(30);

    public static async Task<IdleState> Detect(DataContext dataContext, TimeSpan idleThreshold)
    {
        var allSessionsLocked = WindowsSessions.AreAllSessionsLockedOrDisconnected();
        if (allSessionsLocked == true)
            return new IdleState(true, null, "All sessions locked");

        var userPresences = await UserPresence.GetFresh(dataContext, PresenceReportMaximumAge);
        if (userPresences.Count > 0)
        {
            var lastInputAt = userPresences.Max(presence => presence.LastInputAt);
            return FromIdleTime(DateTime.UtcNow - lastInputAt, idleThreshold, "Presence agent");
        }

        var localIdleTime = GetLocalIdleTime();
        if (localIdleTime.HasValue)
            return FromIdleTime(localIdleTime.Value, idleThreshold, "Local input");

        return IdleState.Unknown;
    }

    private static IdleState FromIdleTime(TimeSpan idleTime, TimeSpan idleThreshold, string source)
    {
        var clampedIdleTime = idleTime < TimeSpan.Zero ? TimeSpan.Zero : idleTime;
        return new IdleState(clampedIdleTime >= idleThreshold, clampedIdleTime, source);
    }

    /// <summary>
    /// Only meaningful inside an interactive session; services in session 0 see no user input.
    /// </summary>
    private static TimeSpan? GetLocalIdleTime()
    {
        if (!OperatingSystem.IsWindows() || !Environment.UserInteractive || WindowsSessions.CurrentSessionId() == 0)
            return null;

        var lastInputInfo = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref lastInputInfo))
            return null;

        var idleMilliseconds = unchecked((uint)Environment.TickCount - lastInputInfo.Time);
        return TimeSpan.FromMilliseconds(idleMilliseconds);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo lastInputInfo);
}

/// <summary>
/// Reads the state of interactive Windows sessions through the Terminal Services API.
/// </summary>
public static class WindowsSessions
{
    private const int WtsActive = 0;
    private const int WtsDisconnected = 4;
    private const int WtsSessionInfoEx = 25;
    private const int WtsSessionStateLock = 0;

    public static int CurrentSessionId()
    {
        return System.Diagnostics.Process.GetCurrentProcess().SessionId;
    }

    /// <summary>
    /// True when user sessions exist and all of them are locked or disconnected; null when it cannot be determined.
    /// </summary>
    public static bool? AreAllSessionsLockedOrDisconnected()
    {
        if (!OperatingSystem.IsWindows())
            return null;

        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out var sessionInfoPointer, out var sessionCount))
            return null;

        try
        {
            var userSessionCount = 0;
            var awaySessionCount = 0;
            var structureSize = Marshal.SizeOf<WtsSessionInfo>();

            for (var index = 0; index < sessionCount; index++)
            {
                var sessionInfo = Marshal.PtrToStructure<WtsSessionInfo>(sessionInfoPointer + index * structureSize);
                if (sessionInfo.SessionId == 0 || (sessionInfo.State != WtsActive && sessionInfo.State != WtsDisconnected))
                    continue;

                userSessionCount++;
                if (sessionInfo.State == WtsDisconnected || IsSessionLocked(sessionInfo.SessionId) == true)
                    awaySessionCount++;
            }

            return userSessionCount == 0 ? null : awaySessionCount == userSessionCount;
        }
        finally
        {
            WTSFreeMemory(sessionInfoPointer);
        }
    }

    private static bool? IsSessionLocked(int sessionId)
    {
        if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WtsSessionInfoEx, out var buffer, out var bytesReturned) || bytesReturned == 0)
            return null;

        try
        {
            // WTSINFOEX: Level (4 bytes), then the WTSINFOEX_LEVEL1 union, which is 8-byte aligned because it holds
            // LARGE_INTEGER times: SessionId at 8, SessionState at 12, SessionFlags at 16.
            var sessionFlags = Marshal.ReadInt32(buffer, 16);
            return sessionFlags == WtsSessionStateLock;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessionInfo, out int count);

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
}
