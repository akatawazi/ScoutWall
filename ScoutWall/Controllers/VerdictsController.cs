using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// Flow verdicts from the ScoreCard and external engines such as zev, with their agreement.
/// </summary>
public class VerdictsController : Controller
{
    public async Task<IActionResult> Index(string? provider, Verdict? verdict, [FromServices] DataContext dataContext)
    {
        var verdictReport = await VerdictReport.Build(dataContext, provider, verdict);
        return View(verdictReport);
    }

    public async Task<IActionResult> Details(long id, [FromServices] DataContext dataContext)
    {
        var flowVerdict = await FlowVerdict.Get(dataContext, item => item.Id == id);
        if (flowVerdict == null)
            return NotFound();

        return View(flowVerdict);
    }
}
