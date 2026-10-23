using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Filters;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// First-run setup: an administrator account, then a few plain-language choices.
/// </summary>
public class SetupController : Controller
{
    [AllowAnonymous]
    public async Task<IActionResult> Account([FromServices] DataContext dataContext)
    {
        if (await Data.Models.User.AnyExist(dataContext))
            return RedirectToAction("Login", "Account");

        var isLocal = SetupCode.IsLocalRequest(HttpContext);
        if (!isLocal)
            SetupCode.EnsureIssued(Path.GetDirectoryName(dataContext.Database.GetDbConnection().DataSource) ?? ".");

        return View(new SetupAccountForm { IsLocal = isLocal, CodeFilePath = SetupCode.CodeFilePath });
    }

    [AllowAnonymous]
    [HttpPost]
    [EnableRateLimiting("login")]
    public async Task<IActionResult> Account(SetupAccountForm setupAccountForm, [FromServices] DataContext dataContext)
    {
        setupAccountForm.IsLocal = SetupCode.IsLocalRequest(HttpContext);
        setupAccountForm.CodeFilePath = SetupCode.CodeFilePath;
        if (!setupAccountForm.IsLocal && !SetupCode.Matches(setupAccountForm.SetupCode))
            ModelState.AddModelError(string.Empty, "That setup code is not valid or has expired. A new one has been written to the file.");

        if (!ModelState.IsValid)
            return View(setupAccountForm);

        var error = await Data.Models.User.CreateFirstAdministrator(dataContext, setupAccountForm.Email, setupAccountForm.Password);
        if (error != null)
        {
            ModelState.AddModelError(string.Empty, error);
            return View(setupAccountForm);
        }

        SetupCode.Consume();
        var user = await Data.Models.User.GetByEmail(dataContext, setupAccountForm.Email);
        await UserSession.SignIn(HttpContext, user!);
        return RedirectToAction(nameof(Watch));
    }

    public IActionResult Index()
    {
        return RedirectToAction(nameof(Watch));
    }

    public async Task<IActionResult> Watch([FromServices] DataContext dataContext)
    {
        return View(await SettingsOverview.Build(dataContext, "capture"));
    }

    [HttpPost]
    public async Task<IActionResult> Watch(List<string>? interfaceNames, [FromServices] DataContext dataContext)
    {
        var errors = await SetupChoices.ChooseInterfaces(dataContext, interfaceNames ?? [], UserSession.Email(User));
        return NextStep(errors, nameof(Watch), nameof(Protect));
    }

    public async Task<IActionResult> Protect([FromServices] DataContext dataContext)
    {
        ViewData["ProtectionChoice"] = await SetupChoices.CurrentProtection(dataContext);
        return View(await SettingsOverview.Build(dataContext, "protection"));
    }

    [HttpPost]
    public async Task<IActionResult> Protect(ProtectionChoice protectionChoice, EnforcementProvider enforcementProvider, bool practiceMode,
        string? webhookUrl, string? webhookSecret, [FromServices] DataContext dataContext)
    {
        var errors = await SetupChoices.ChooseProtection(dataContext, protectionChoice, enforcementProvider, practiceMode, webhookUrl, webhookSecret, UserSession.Email(User));
        return NextStep(errors, nameof(Protect), nameof(Assistant));
    }

    public async Task<IActionResult> Assistant([FromServices] DataContext dataContext)
    {
        return View(await SettingsOverview.Build(dataContext, "analyst"));
    }

    [HttpPost]
    public async Task<IActionResult> Assistant([Bind(Prefix = "Analyst")] AnalystSettings analystSettings, [FromServices] DataContext dataContext)
    {
        var errors = await SetupChoices.ChooseAssistant(dataContext, analystSettings, UserSession.Email(User));
        return NextStep(errors, nameof(Assistant), nameof(Finish));
    }

    public async Task<IActionResult> Finish([FromServices] DataContext dataContext)
    {
        return View(await SettingsOverview.Build(dataContext, "capture"));
    }

    [HttpPost]
    [ActionName("Finish")]
    public async Task<IActionResult> Complete([FromServices] DataContext dataContext)
    {
        await SystemState.MarkSetupCompleted(dataContext, UserSession.Email(User));
        SetupRequiredFilter.Reset();
        TempData["Message"] = "You're all set. ScoutWall is watching.";
        return RedirectToAction("Index", "Home");
    }

    private IActionResult NextStep(List<string> errors, string currentStep, string nextStep)
    {
        if (errors.Count == 0 && Request.Query.ContainsKey("fromSettings"))
        {
            TempData["Message"] = "Saved. ScoutWall picks up the change within a few seconds.";
            return RedirectToAction("Simple", "Settings");
        }

        if (errors.Count == 0)
            return RedirectToAction(nextStep);

        TempData["Error"] = string.Join(" ", errors);
        return RedirectToAction(currentStep);
    }
}
