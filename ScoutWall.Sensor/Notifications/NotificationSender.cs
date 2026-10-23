using System.Net.Http.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Sensor.Notifications;

/// <summary>
/// Delivers queued notifications by email (SMTP) and webhook (generic JSON, Slack, Teams or Discord).
/// Desktop notifications are shown by the presence agent, not here.
/// </summary>
public static class NotificationSender
{
    private static readonly HttpClient HttpClient = new() { Timeout = TimeSpan.FromSeconds(15) };

    public static async Task SendEmail(NotificationSettings notificationSettings, NotificationDelivery notificationDelivery, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(notificationSettings.SmtpHost) || notificationSettings.EmailTo.Count == 0)
            throw new InvalidOperationException("Email is enabled but the SMTP host or recipients are not set.");

        var mimeMessage = new MimeMessage();
        mimeMessage.From.Add(MailboxAddress.Parse(notificationSettings.EmailFrom ?? notificationSettings.SmtpUsername ?? "scoutwall@localhost"));
        foreach (var recipient in notificationSettings.EmailTo)
            mimeMessage.To.Add(MailboxAddress.Parse(recipient));

        mimeMessage.Subject = $"[ScoutWall {notificationDelivery.Severity}] {notificationDelivery.Title}";
        mimeMessage.Body = new TextPart("plain") { Text = notificationDelivery.Message };

        using var smtpClient = new SmtpClient { Timeout = 15_000 };
        var secureSocketOptions = notificationSettings.SmtpUseTls ? SecureSocketOptions.Auto : SecureSocketOptions.None;
        await smtpClient.ConnectAsync(notificationSettings.SmtpHost, notificationSettings.SmtpPort, secureSocketOptions, cancellationToken);

        if (!string.IsNullOrWhiteSpace(notificationSettings.SmtpUsername))
        {
            var smtpPassword = SecretProtector.Unprotect(notificationSettings.SmtpPassword) ?? string.Empty;
            await smtpClient.AuthenticateAsync(notificationSettings.SmtpUsername, smtpPassword, cancellationToken);
        }

        await smtpClient.SendAsync(mimeMessage, cancellationToken);
        await smtpClient.DisconnectAsync(true, cancellationToken);
    }

    public static async Task SendWebhook(NotificationSettings notificationSettings, NotificationDelivery notificationDelivery, CancellationToken cancellationToken)
    {
        var webhookUrl = SecretProtector.Unprotect(notificationSettings.WebhookUrl);
        if (string.IsNullOrWhiteSpace(webhookUrl))
            throw new InvalidOperationException("Webhook is enabled but no URL is set.");

        var text = $"*[{notificationDelivery.Severity}] {notificationDelivery.Title}*\n{notificationDelivery.Message}";
        object body = notificationSettings.WebhookFormat switch
        {
            WebhookFormat.Slack => new { text },
            WebhookFormat.Teams => new { text },
            WebhookFormat.Discord => new { content = text.Length > 1900 ? text[..1900] : text },
            _ => new
            {
                source = "ScoutWall",
                severity = notificationDelivery.Severity.ToString(),
                title = notificationDelivery.Title,
                message = notificationDelivery.Message,
                alertId = notificationDelivery.AlertId,
                createdAt = notificationDelivery.CreatedAt
            }
        };

        using var response = await HttpClient.PostAsJsonAsync(webhookUrl, body, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
