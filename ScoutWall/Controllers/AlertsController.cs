using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

public class AlertsController : Controller
{
    public async Task<IActionResult> Index(AlertFilter alertFilter, [FromServices] DataContext dataContext)
    {
        var alertsPage = await AlertsPage.Build(dataContext, alertFilter, Request.QueryString.HasValue);
        return View(alertsPage);
    }

    public async Task<IActionResult> Details(long id, [FromServices] DataContext dataContext)
    {
        var alert = await Alert.Get(dataContext, item => item.Id == id);
        if (alert == null)
            return NotFound();

        alert.HostActionTargets = await HostActionOptions.Build(dataContext, alert);
        return View(alert);
    }

    [HttpPost]
    public async Task<IActionResult> Acknowledge(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        await Alert.Acknowledge(dataContext, id, UserSession.Email(User));
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Details), new { id });
    }

    [HttpPost]
    public async Task<IActionResult> Resolve(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        await Alert.Resolve(dataContext, id, UserSession.Email(User));
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Details), new { id });
    }
}
