using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ScoutWall.Models;

namespace ScoutWall.Filters;

/// <summary>
/// Sends a user who still has a temporary or default password to the change-password page before anything else.
/// </summary>
public class RequirePasswordChangeFilter : IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (!UserSession.MustChangePassword(context.HttpContext.User))
            return;

        var controllerName = context.RouteData.Values["controller"]?.ToString();
        if (controllerName == "Account")
            return;

        context.Result = new RedirectToActionResult("ChangePassword", "Account", null);
    }

    public void OnActionExecuted(ActionExecutedContext context)
    {
    }
}
