using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// "Check for updates" and "Install update". The console runs without administrator rights, so it leaves the
/// request for the sensor, which checks GitHub, verifies the download and installs it within a few seconds.
/// </summary>
public class UpdatesController : Controller
{
    public async Task<IActionResult> Index([FromServices] DataContext dataContext)
    {
        return View(await UpdatesPage.Load(dataContext));
    }

    /// <summary>
    /// What the sensor is doing with the request, for the page to follow without reloading.
    /// </summary>
    public async Task<IActionResult> Status([FromServices] DataContext dataContext)
    {
        var updateStatus = await UpdateStatus.Load(dataContext);
        return Json(new { busy = updateStatus?.IsBusy == true, progress = updateStatus?.Progress.ToString(), message = updateStatus?.Message });
    }

    [HttpPost]
    public async Task<IActionResult> Check([FromServices] DataContext dataContext)
    {
        return await Ask(dataContext, UpdateAction.Check, "Update check requested");
    }

    [HttpPost]
    public async Task<IActionResult> Install([FromServices] DataContext dataContext)
    {
        return await Ask(dataContext, UpdateAction.Install, "Update install requested");
    }

    private async Task<IActionResult> Ask(DataContext dataContext, UpdateAction action, string auditAction)
    {
        var current = await UpdateStatus.Load(dataContext);
        if (current?.IsBusy == true)
        {
            TempData["Error"] = "An update check or install is already under way.";
            return RedirectToAction(nameof(Index));
        }

        var userEmail = UserSession.Email(User);
        await new UpdateRequest { Action = action, RequestedAt = DateTime.UtcNow, RequestedBy = userEmail }.Save(dataContext);
        await UpdateStatus.Set(dataContext, UpdateProgress.Waiting, "Waiting for the sensor to pick this up…");
        await AuditEntry.Record(dataContext, userEmail, auditAction, "ScoutWall", new { running = ScoutWallVersion.Current });
        return RedirectToAction(nameof(Index));
    }
}

public class UpdatesPage
{
    public LatestRelease? LatestRelease { get; set; }
    public UpdateStatus? Status { get; set; }

    public static async Task<UpdatesPage> Load(DataContext dataContext)
    {
        return new UpdatesPage
        {
            LatestRelease = await LatestRelease.Load(dataContext),
            Status = await UpdateStatus.Load(dataContext)
        };
    }
}
