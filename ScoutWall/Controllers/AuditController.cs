using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

public class AuditController : Controller
{
    public async Task<IActionResult> Index([FromServices] DataContext dataContext)
    {
        var auditEntries = await AuditEntry.GetRecent(dataContext, 500);
        return View(auditEntries);
    }
}
