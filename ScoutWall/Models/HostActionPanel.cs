using ScoutWall.Data.Models;

namespace ScoutWall.Models;

/// <summary>
/// The task and service buttons shown on an alert (all choices) or a Home finding (Disable and Stop only, since
/// removing a task deserves the full alert page).
/// </summary>
public record HostActionPanel(List<HostActionTarget> Targets, bool Compact, string ReturnUrl);
