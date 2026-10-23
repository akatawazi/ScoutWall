using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.ViewModels;

namespace ScoutWall.Controllers;

public class DashboardController : Controller
{
    public async Task<IActionResult> Index(string? range, [FromServices] DataContext dataContext)
    {
        var dashboardReport = await DashboardReport.Build(dataContext, TimeRange.Parse(range));
        return View(dashboardReport);
    }

    [AllowAnonymous]
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}
