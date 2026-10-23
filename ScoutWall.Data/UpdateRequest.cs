using System.Text.Json;
using ScoutWall.Data.Models;

namespace ScoutWall.Data;

public enum UpdateAction
{
    Check,
    Install
}

/// <summary>
/// "Check for updates" or "Install update", asked for in the console. The console runs without administrator
/// rights, so it leaves the request here and the sensor (LocalSystem) carries it out within a few seconds.
/// </summary>
public class UpdateRequest
{
    public const string StateKey = "update_request";

    public UpdateAction Action { get; set; }
    public DateTime RequestedAt { get; set; }
    public string RequestedBy { get; set; } = string.Empty;

    public static async Task<UpdateRequest?> Load(DataContext dataContext)
    {
        return Read<UpdateRequest>(await SystemState.GetValue(dataContext, StateKey));
    }

    public async Task Save(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(this));
    }

    public static async Task Clear(DataContext dataContext)
    {
        await SystemState.SetValue(dataContext, StateKey, string.Empty);
    }

    internal static T? Read<T>(string? json) where T : class
    {
        if (string.IsNullOrEmpty(json))
            return null;

        try
        {
            return JsonSerializer.Deserialize<T>(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}

public enum UpdateProgress
{
    Waiting,
    Checking,
    UpToDate,
    Available,
    Installing,
    Installed,
    Failed
}

/// <summary>
/// How the last check or install went, shown in the console.
/// </summary>
public class UpdateStatus
{
    public const string StateKey = "update_status";

    public UpdateProgress Progress { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? TargetVersion { get; set; }
    public DateTime At { get; set; }

    /// <summary>
    /// Still being worked on; the console checks back every few seconds.
    /// </summary>
    public bool IsBusy => Progress is UpdateProgress.Waiting or UpdateProgress.Checking or UpdateProgress.Installing
        && DateTime.UtcNow - At < TimeSpan.FromMinutes(10);

    public static async Task<UpdateStatus?> Load(DataContext dataContext)
    {
        return UpdateRequest.Read<UpdateStatus>(await SystemState.GetValue(dataContext, StateKey));
    }

    public static async Task Set(DataContext dataContext, UpdateProgress progress, string message, string? targetVersion = null)
    {
        var updateStatus = new UpdateStatus { Progress = progress, Message = message, TargetVersion = targetVersion, At = DateTime.UtcNow };
        await SystemState.SetValue(dataContext, StateKey, JsonSerializer.Serialize(updateStatus));
    }
}
