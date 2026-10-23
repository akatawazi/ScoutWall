using Microsoft.AspNetCore.Mvc;
using ScoutWall.Data;
using ScoutWall.Data.Models;
using ScoutWall.Models;

namespace ScoutWall.Controllers;

/// <summary>
/// Disk activity and file changes: how hard each drive works, which programs read and write the most, and which
/// files were created, changed, deleted, renamed or read.
/// </summary>
public class IoController : Controller
{
    public async Task<IActionResult> Index(string? range, FileScope scope, string? text, FileChangeKind? kind, long? program, bool important,
        bool data, bool routine, [FromServices] DataContext dataContext)
    {
        var filter = new FileChangeFilter
        {
            Scope = scope, Text = text, Kind = kind, ProcessImageId = program, ImportantOnly = important, DataOnly = data, ShowRoutine = routine
        };
        var ioReport = await IoReport.Build(dataContext, TimeRange.Parse(range), filter);
        return View(ioReport);
    }

    /// <summary>
    /// Turns read tracking on or off. The sensor makes (or undoes) the Windows audit changes within half a minute.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> ReadTracking(bool enable, long revision, [FromServices] DataContext dataContext)
    {
        var tracking = await Setting.Load<FileTrackingSettings>(dataContext);
        tracking.ReadTrackingEnabled = enable;
        var errors = await Setting.Save(dataContext, tracking, revision, UserSession.Email(User));
        if (errors.Count == 0)
        {
            await AuditEntry.Record(dataContext, UserSession.Email(User), enable ? "File read tracking turned on" : "File read tracking turned off",
                "Windows file auditing", new { enable });
        }

        TempData[errors.Count == 0 ? "Message" : "Error"] = errors.Count > 0
            ? string.Join(" ", errors)
            : enable
                ? "Read tracking is being switched on. Within half a minute ScoutWall turns on Windows file auditing for your folders."
                : "Read tracking is being switched off. Within half a minute ScoutWall puts the Windows audit settings back.";
        return Redirect(Url.Action(nameof(Index), new { scope = FileScope.Mine }) + "#reads");
    }

    [HttpPost]
    public async Task<IActionResult> MyFolders(string? folders, long revision, [FromServices] DataContext dataContext)
    {
        var tracking = await Setting.Load<FileTrackingSettings>(dataContext);
        tracking.ExtraMyFilesFoldersText = folders ?? string.Empty;
        var errors = await Setting.Save(dataContext, tracking, revision, UserSession.Email(User));
        TempData[errors.Count == 0 ? "Message" : "Error"] = errors.Count > 0
            ? string.Join(" ", errors)
            : "Saved. Changes in those folders count as your files from now on.";
        return Redirect(Url.Action(nameof(Index), new { scope = FileScope.Mine }) + "#reads");
    }
}
