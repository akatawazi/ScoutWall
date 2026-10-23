using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// What the analyst agent concluded: findings that need a person, and the reasoning behind everything it closed.
/// </summary>
public class AnalystController : Controller
{
    public async Task<IActionResult> Index(AnalystVerdict? verdict, [FromServices] DataContext dataContext)
    {
        var analystOverview = await AnalystOverview.Build(dataContext, verdict);
        return View(analystOverview);
    }

    [HttpPost]
    public async Task<IActionResult> Acknowledge(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        await AnalystAssessment.Acknowledge(dataContext, id, UserSession.Email(User));
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> ConfirmSuppression(long id, [FromServices] DataContext dataContext)
    {
        var error = await AnalystAssessment.ConfirmSuppression(dataContext, id, UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "Suppression confirmed. That source will no longer raise this alert.";
        return RedirectToAction(nameof(Index));
    }
}
