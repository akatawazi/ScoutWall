using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

public class DecryptionController : Controller
{
    public async Task<IActionResult> Index(string? search, [FromServices] DataContext dataContext)
    {
        var decryptionReport = await DecryptionReport.Build(dataContext, search);
        return View(decryptionReport);
    }
}
