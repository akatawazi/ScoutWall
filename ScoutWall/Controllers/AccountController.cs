using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

public class AccountController : Controller
{
    [AllowAnonymous]
    public IActionResult Login(string? returnUrl)
    {
        return View(new LoginForm { ReturnUrl = returnUrl });
    }

    [AllowAnonymous]
    [HttpPost]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Login(LoginForm loginForm, [FromServices] DataContext dataContext)
    {
        if (!ModelState.IsValid)
            return View(loginForm);

        var loginResult = await Data.Models.User.Authenticate(dataContext, loginForm.Email, loginForm.Password);
        if (loginResult.Outcome != LoginOutcome.Succeeded)
        {
            ModelState.AddModelError(string.Empty, "Incorrect email or password, or too many failed attempts. Try again later.");
            return View(loginForm);
        }

        await UserSession.SignIn(HttpContext, loginResult.User!);
        return Url.IsLocalUrl(loginForm.ReturnUrl) ? Redirect(loginForm.ReturnUrl) : RedirectToAction("Index", "Dashboard");
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
        await UserSession.SignOut(HttpContext);
        return RedirectToAction(nameof(Login));
    }

    public IActionResult ChangePassword()
    {
        return View(new ChangePasswordForm());
    }

    [HttpPost]
    public async Task<IActionResult> ChangePassword(ChangePasswordForm changePasswordForm, [FromServices] DataContext dataContext)
    {
        if (!ModelState.IsValid)
            return View(changePasswordForm);

        var userId = UserSession.UserId(User);
        var user = await Data.Models.User.Get(dataContext, item => item.Id == userId);
        if (user == null)
            return RedirectToAction(nameof(Login));

        var error = await user.ChangePassword(dataContext, changePasswordForm.CurrentPassword, changePasswordForm.NewPassword);
        if (error != null)
        {
            ModelState.AddModelError(string.Empty, error);
            return View(changePasswordForm);
        }

        await UserSession.SignIn(HttpContext, user);
        TempData["Message"] = "Your password was changed.";
        return RedirectToAction("Index", "Dashboard");
    }
}
