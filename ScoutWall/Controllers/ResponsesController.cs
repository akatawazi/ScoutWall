using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// Blocks and throttles: what is in force, manual actions, and the kill switch.
/// </summary>
public class ResponsesController : Controller
{
    public async Task<IActionResult> Index([FromServices] DataContext dataContext)
    {
        var responseOverview = await ResponseOverview.Build(dataContext);
        return View(responseOverview);
    }

    [HttpPost]
    public async Task<IActionResult> Create(ResponseActionType actionType, string? target, int durationMinutes, bool inboundOnly, string? returnUrl, [FromServices] DataContext dataContext)
    {
        var requesterAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        var error = await ResponseAction.RequestManual(dataContext, actionType, target, durationMinutes, UserSession.Email(User), requesterAddress, inboundOnly);
        TempData[error == null ? "Message" : "Error"] = error ?? (actionType == ResponseActionType.BlockProgram
            ? $"{Path.GetFileName(target)} is being blocked from the internet until you unblock it. The sensor applies it within a few seconds."
            : $"{actionType} requested for {target}. The sensor applies it within a few seconds.");
        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Revoke(long id, string? returnUrl, [FromServices] DataContext dataContext)
    {
        var revoked = await ResponseAction.Revoke(dataContext, id, UserSession.Email(User));
        if (revoked && returnUrl != null)
            TempData["Message"] = "Unblocked. The sensor removes the block within a few seconds.";

        return Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> UnblockScanner(long? id, [FromServices] DataContext dataContext)
    {
        var removedCount = await ScannerBlock.Remove(dataContext, id);
        await AuditEntry.Record(dataContext, UserSession.Email(User), "Scanner block removed", id?.ToString() ?? "all", new { removedCount });
        TempData["Message"] = removedCount == 1 ? "Unblocked. The firewall is updated within half a minute." : $"Unblocked {removedCount} addresses.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> RevokeAll([FromServices] DataContext dataContext)
    {
        var revokedCount = await ResponseAction.RevokeAll(dataContext, UserSession.Email(User));
        TempData["Message"] = $"Revoked {revokedCount} actions. The sensor removes every ScoutWall firewall rule on its next pass.";
        return RedirectToAction(nameof(Index));
    }
}
