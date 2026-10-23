using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

public class SettingsController : Controller
{
    /// <summary>
    /// The everyday settings page: a few plain choices, with every detailed setting one click away.
    /// </summary>
    public async Task<IActionResult> Simple([FromServices] DataContext dataContext)
    {
        return View(await SettingsOverview.Build(dataContext, null));
    }

    [HttpPost]
    public async Task<IActionResult> SaveEnforcement([Bind(Prefix = "Enforcement")] EnforcementSettings enforcementSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, enforcementSettings, revision, "protection");
    }

    public async Task<IActionResult> Index(string? tab, [FromServices] DataContext dataContext)
    {
        var settingsOverview = await SettingsOverview.Build(dataContext, tab);
        return View(settingsOverview);
    }

    [HttpPost]
    public async Task<IActionResult> SaveCapture([Bind(Prefix = "Capture")] CaptureSettings captureSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, captureSettings, revision, "capture");
    }

    [HttpPost]
    public async Task<IActionResult> SaveResponse([Bind(Prefix = "Response")] ResponseSettings responseSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, responseSettings, revision, "response");
    }

    [HttpPost]
    public async Task<IActionResult> SaveDetection([Bind(Prefix = "Detection")] DetectionSettings detectionSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, detectionSettings, revision, "detection");
    }

    [HttpPost]
    public async Task<IActionResult> SaveVerdict([Bind(Prefix = "Verdict")] VerdictSettings verdictSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, verdictSettings, revision, "analysis");
    }

    [HttpPost]
    public async Task<IActionResult> SaveAnalyst([Bind(Prefix = "Analyst")] AnalystSettings analystSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, analystSettings, revision, "analyst");
    }

    [HttpPost]
    public async Task<IActionResult> SaveNotification([Bind(Prefix = "Notification")] NotificationSettings notificationSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, notificationSettings, revision, "notifications");
    }

    [HttpPost]
    public async Task<IActionResult> SaveIntegration([Bind(Prefix = "Integration")] IntegrationSettings integrationSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, integrationSettings, revision, "integrations");
    }

    [HttpPost]
    public async Task<IActionResult> SaveRetention([Bind(Prefix = "Retention")] RetentionSettings retentionSettings, long revision, [FromServices] DataContext dataContext)
    {
        return await Save(dataContext, retentionSettings, revision, "retention");
    }

    [HttpPost]
    public async Task<IActionResult> TestNotification(NotificationChannel channel, [FromServices] DataContext dataContext)
    {
        await NotificationDelivery.Enqueue(dataContext, channel, AlertSeverity.Low, "ScoutWall test notification",
            $"This is a test notification requested by {UserSession.Email(User)}.", null);
        TempData["Message"] = $"A test {channel} notification was queued. The sensor sends it within about ten seconds.";
        return RedirectToAction(nameof(Index), new { tab = "notifications" });
    }

    [HttpPost]
    public async Task<IActionResult> CreateUser(string? email, string? temporaryPassword, [FromServices] DataContext dataContext)
    {
        var error = await Data.Models.User.Create(dataContext, email, temporaryPassword, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? $"{email} was added and must change the password at first login.";
        return RedirectToAction(nameof(Index), new { tab = "users" });
    }

    [HttpPost]
    public async Task<IActionResult> RemoveUser(long id, [FromServices] DataContext dataContext)
    {
        var error = await Data.Models.User.Remove(dataContext, id, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "The user was removed.";
        return RedirectToAction(nameof(Index), new { tab = "users" });
    }

    private async Task<IActionResult> Save<T>(DataContext dataContext, T section, long revision, string tab)
        where T : class, ISettingsSection<T>, new()
    {
        var errors = await Setting.Save(dataContext, section, revision, UserSession.Email(User));
        TempData[errors.Count == 0 ? "Message" : "Error"] = errors.Count == 0
            ? "Settings saved. The sensor picks them up within a few seconds."
            : string.Join(" ", errors);
        return RedirectToAction(nameof(Index), new { tab });
    }
}
