using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Filters;

/// <summary>
/// Until there is an administrator, every page leads to account creation. After that, until setup is finished,
/// signed-in users are taken through the remaining setup steps.
/// </summary>
public class SetupRequiredFilter : IAsyncActionFilter
{
    private static volatile bool setupKnownComplete;

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var controllerName = context.RouteData.Values["controller"]?.ToString();
        if (setupKnownComplete || controllerName == "Setup")
        {
            await next();
            return;
        }

        var dataContext = context.HttpContext.RequestServices.GetRequiredService<DataContext>();
        if (!await User.AnyExist(dataContext))
        {
            context.Result = new RedirectToActionResult("Account", "Setup", null);
            return;
        }

        if (await SystemState.IsSetupCompleted(dataContext))
        {
            setupKnownComplete = true;
            await next();
            return;
        }

        var isSignedIn = context.HttpContext.User.Identity?.IsAuthenticated == true;
        if (isSignedIn && controllerName != "Account")
        {
            context.Result = new RedirectToActionResult("Index", "Setup", null);
            return;
        }

        await next();
    }

    public static void Reset()
    {
        setupKnownComplete = false;
    }
}
