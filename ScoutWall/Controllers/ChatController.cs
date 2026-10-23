using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Intelligence.Analyst;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// "Ask ScoutWall": questions and changes by conversation. Proposed changes only happen when confirmed here.
/// </summary>
public class ChatController : Controller
{
    public async Task<IActionResult> Index([FromServices] DataContext dataContext)
    {
        var chatPage = await ChatPage.Build(dataContext, UserSession.UserId(User));
        return View(chatPage);
    }

    [HttpPost]
    public async Task<IActionResult> Send(string? message, [FromServices] DataContext dataContext, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(message))
            return RedirectToAction(nameof(Index));

        var model = AnalystModelFactory.Create(await Setting.Load<AnalystSettings>(dataContext));
        if (model == null)
        {
            TempData["Error"] = "Choose an assistant first, under Settings.";
            return RedirectToAction(nameof(Index));
        }

        try
        {
            await new ChatAssistant(model, dataContext).Respond(UserSession.UserId(User), message.Trim()[..Math.Min(message.Trim().Length, 2000)], cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidOperationException or Anthropic.Exceptions.AnthropicApiException or TaskCanceledException)
        {
            TempData["Error"] = $"The assistant couldn't answer: {exception.Message}";
        }

        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Confirm(long id, [FromServices] DataContext dataContext)
    {
        var error = await ChatProposals.Confirm(dataContext, id, UserSession.UserId(User), UserSession.Email(User));
        TempData[error == null ? "Message" : "Error"] = error ?? "Done. The change is in place.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Reject(long id, [FromServices] DataContext dataContext)
    {
        await ChatProposals.Reject(dataContext, id, UserSession.UserId(User));
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    public async Task<IActionResult> Clear([FromServices] DataContext dataContext)
    {
        await ChatMessage.Clear(dataContext, UserSession.UserId(User));
        return RedirectToAction(nameof(Index));
    }
}
