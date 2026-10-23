using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

public class TrafficController : Controller
{
    public async Task<IActionResult> Index(string? range, [FromServices] DataContext dataContext)
    {
        var trafficReport = await TrafficReport.Build(dataContext, TimeRange.Parse(range), 25);
        return View(trafficReport);
    }
}
