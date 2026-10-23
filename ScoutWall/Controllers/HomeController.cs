using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// The simple home page: is my computer OK, what needs me, what happened today.
/// </summary>
public class HomeController : Controller
{
    public async Task<IActionResult> Index([FromServices] DataContext dataContext)
    {
        var homeReport = await HomeReport.Build(dataContext);
        return View(homeReport);
    }
}
