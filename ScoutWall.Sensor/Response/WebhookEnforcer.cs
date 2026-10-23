using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Response;

/// <summary>
/// Hands blocks to a router or firewall that accepts webhooks. Each request is signed with HMAC-SHA256 over
/// "timestamp.body", carries a nonce and the action id so the receiver can reject replays and stay idempotent,
/// and must be acknowledged with a 2xx response.
/// </summary>
public static class WebhookEnforcer
{
    private const string AppliedStateKey = "webhook_applied_actions";
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static async Task Reconcile(DataContext dataContext, EnforcementSettings enforcementSettings, List<ResponseAction> desiredActions, ILogger logger)
    {
        var appliedIds = await ReadAppliedIds(dataContext);
        var desiredIds = desiredActions.Select(action => action.Id).ToHashSet();

        foreach (var removedId in appliedIds.Where(id => !desiredIds.Contains(id)).ToList())
        {
            if (await TrySend(enforcementSettings, "remove", removedId, null, logger))
                appliedIds.Remove(removedId);
        }

        foreach (var responseAction in desiredActions.Where(action => !appliedIds.Contains(action.Id)))
        {
            if (!enforcementSettings.Supports(responseAction.ActionType))
            {
                await ResponseAction.MarkFailed(dataContext, responseAction.Id, $"Your router or firewall webhook cannot carry out {responseAction.ActionType}.");
                continue;
            }

            if (!await TrySend(enforcementSettings, "apply", responseAction.Id, responseAction, logger))
            {
                await ResponseAction.MarkFailed(dataContext, responseAction.Id, "The router or firewall webhook did not accept the request.");
                continue;
            }

            appliedIds.Add(responseAction.Id);
            await ResponseAction.MarkApplied(dataContext, responseAction.Id);
        }

        await SaveAppliedIds(dataContext, appliedIds);
    }

    public static async Task<int> RemoveAll(DataContext dataContext, EnforcementSettings enforcementSettings, ILogger? logger)
    {
        var appliedIds = await ReadAppliedIds(dataContext);
        var removedCount = 0;

        foreach (var appliedId in appliedIds.ToList())
        {
            if (await TrySend(enforcementSettings, "remove", appliedId, null, logger))
            {
                appliedIds.Remove(appliedId);
                removedCount++;
            }
        }

        await SaveAppliedIds(dataContext, appliedIds);
        return removedCount;
    }

    private static async Task<bool> TrySend(EnforcementSettings enforcementSettings, string eventName, long actionId, ResponseAction? responseAction, ILogger? logger)
    {
        if (string.IsNullOrWhiteSpace(enforcementSettings.WebhookUrl))
            return false;

        var body = JsonSerializer.Serialize(new
        {
            @event = eventName,
            id = actionId,
            type = responseAction?.ActionType.ToString(),
            target = responseAction?.Target,
            inbound = responseAction?.BlockInbound,
            outbound = responseAction?.BlockOutbound,
            reason = responseAction?.Reason,
            expires_at = responseAction?.ExpiresAt,
            nonce = Guid.NewGuid().ToString("N")
        });
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

        using var request = new HttpRequestMessage(HttpMethod.Post, enforcementSettings.WebhookUrl)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        request.Headers.Add("X-ScoutWall-Timestamp", timestamp);
        request.Headers.Add("X-ScoutWall-Signature", "sha256=" + Sign(enforcementSettings, timestamp, body));

        try
        {
            using var response = await HttpClient.SendAsync(request);
            if (response.IsSuccessStatusCode)
                return true;

            logger?.LogWarning("Firewall webhook answered {Status} for {Event} {Id}", (int)response.StatusCode, eventName, actionId);
            return false;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
        {
            logger?.LogWarning("Firewall webhook unreachable: {Message}", exception.Message);
            return false;
        }
    }

    private static string Sign(EnforcementSettings enforcementSettings, string timestamp, string body)
    {
        var secret = SecretProtector.Unprotect(enforcementSettings.WebhookSecret) ?? string.Empty;
        var signature = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(timestamp + "." + body));
        return Convert.ToHexString(signature).ToLowerInvariant();
    }

    private static async Task<HashSet<long>> ReadAppliedIds(DataContext dataContext)
    {
        var storedValue = await SystemState.GetValue(dataContext, AppliedStateKey);
        return string.IsNullOrEmpty(storedValue) ? [] : JsonSerializer.Deserialize<HashSet<long>>(storedValue) ?? [];
    }

    private static async Task SaveAppliedIds(DataContext dataContext, HashSet<long> appliedIds)
    {
        await SystemState.SetValue(dataContext, AppliedStateKey, JsonSerializer.Serialize(appliedIds));
    }
}
