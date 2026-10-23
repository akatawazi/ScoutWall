using System.Net;
using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;

namespace ScoutWall.Controllers;

public class AddressesController : Controller
{
    public async Task<IActionResult> Details(string id, string? range, [FromServices] DataContext dataContext)
    {
        if (!IPAddress.TryParse(id, out var ipAddress))
            return NotFound();

        var ipAddressReport = await IpAddressReport.Build(dataContext, ipAddress.ToString(), TimeRange.Parse(range));
        return View(ipAddressReport);
    }
}
