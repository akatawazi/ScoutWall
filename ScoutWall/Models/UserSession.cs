using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using ScoutWall.Data.Models;

namespace ScoutWall.Models;

/// <summary>
/// Builds and reads the authentication cookie for a signed-in user.
/// </summary>
public static class UserSession
{
    private const string MustChangePasswordClaim = "must_change_password";
    private const string SessionStampClaim = "session_stamp";

    public static async Task SignIn(HttpContext httpContext, User user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Email),
            new(MustChangePasswordClaim, user.MustChangePassword ? "true" : "false"),
            new(SessionStampClaim, user.SessionStamp())
        };

        var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
    }

    public static async Task SignOut(HttpContext httpContext)
    {
        await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    /// <summary>
    /// Runs on every request: rejects the cookie when the user was removed or has changed password since.
    /// </summary>
    public static async Task Validate(CookieValidatePrincipalContext context)
    {
        if (context.Principal == null)
            return;

        var dataContext = context.HttpContext.RequestServices.GetRequiredService<ScoutWall.Data.DataContext>();
        var userId = UserId(context.Principal);
        var user = await User.Get(dataContext, item => item.Id == userId);
        if (user != null && context.Principal.FindFirstValue(SessionStampClaim) == user.SessionStamp())
            return;

        context.RejectPrincipal();
        await SignOut(context.HttpContext);
    }

    public static bool MustChangePassword(ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.Identity?.IsAuthenticated == true && claimsPrincipal.FindFirstValue(MustChangePasswordClaim) == "true";
    }

    public static long UserId(ClaimsPrincipal claimsPrincipal)
    {
        return long.TryParse(claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId) ? userId : 0;
    }

    public static string Email(ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.Identity?.Name ?? "unknown";
    }
}
