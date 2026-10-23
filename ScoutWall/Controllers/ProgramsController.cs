using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// Data bleed: which programs send data out, and how much of it happens while nobody is using the computer.
/// </summary>
public class ProgramsController : Controller
{
    public async Task<IActionResult> Index(string? range, bool local, [FromServices] DataContext dataContext)
    {
        var dataBleedReport = await DataBleedReport.Build(dataContext, TimeRange.Parse(range), local);
        return View(dataBleedReport);
    }

    public async Task<IActionResult> Details(long id, string? range, [FromServices] DataContext dataContext)
    {
        var programReport = await ProgramReport.Build(dataContext, id, TimeRange.Parse(range));
        if (programReport == null)
            return NotFound();

        return View(programReport);
    }

    [HttpPost]
    public async Task<IActionResult> Allow(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        var error = await ProgramAllowlist.Allow(dataContext, id, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "Always allowed. ScoutWall will never block or slow this program, and any block on it was lifted.";
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Disallow(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        var error = await ProgramAllowlist.Remove(dataContext, id, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "Removed from the allowlist. ScoutWall can block this program again if it misbehaves.";
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Index));
    }
}
