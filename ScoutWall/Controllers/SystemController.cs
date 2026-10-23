using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// What is running on this computer, how hard it is working, and what its Windows logs have reported.
/// </summary>
public class SystemController : Controller
{
    public async Task<IActionResult> Index(string? range, bool allServices, [FromServices] DataContext dataContext)
    {
        var systemReport = await SystemReport.Build(dataContext, TimeRange.Parse(range), allServices);
        return View(systemReport);
    }

    [HttpPost]
    public async Task<IActionResult> Scan([FromServices] DataContext dataContext)
    {
        var error = await ScanStatus.Request(dataContext, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "Scanning this computer. Results appear here in a minute or two.";
        return Redirect(Url.Action(nameof(Index)) + "#scan");
    }

    /// <summary>
    /// Windows ships with the scheduled-task history log switched off; the owner can turn it on from here.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> EnableTaskLog([FromServices] DataContext dataContext)
    {
        // The sensor makes the change; the console runs without administrator rights.
        await SystemState.SetValue(dataContext, "request:enable_task_log", DateTime.UtcNow.ToString("O"));
        await AuditEntry.Record(dataContext, UserSession.Email(User), "Scheduled task logging turned on", "Windows event log", new { });
        TempData["Message"] = "Turning on scheduled task logging. Within a minute ScoutWall will start noticing new scheduled tasks.";
        return RedirectToAction(nameof(Index));
    }
}
