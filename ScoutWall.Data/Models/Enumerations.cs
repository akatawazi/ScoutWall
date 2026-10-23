namespace ScoutWall.Data.Models;

public enum AlertScope
{
    Network = 0,
    Host = 1
}

public enum AlertSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum AlertStatus
{
    Open = 1,
    Acknowledged = 2,
    Resolved = 3
}

/// <summary>
/// Which side started the conversation, relative to the configured local networks.
/// </summary>
public enum TrafficDirection
{
    Inbound = 1,
    Outbound = 2,
    Internal = 3,
    Transit = 4
}

public enum LoginOutcome
{
    Succeeded = 1,
    InvalidCredentials = 2,
    LockedOut = 3
}
