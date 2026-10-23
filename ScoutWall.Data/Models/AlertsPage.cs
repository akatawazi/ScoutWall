namespace ScoutWall.Data.Models;

/// <summary>
/// The Alerts tab: what needs watching, split into this computer (System), data leaving it (Data) and network
/// activity (Network), each alert with the actions that fit it.
/// </summary>
public class AlertsPage
{
    public AlertFilter Filter { get; set; } = new();
    public List<Alert> Alerts { get; set; } = [];
    public Dictionary<AlertGroup, int> OpenCounts { get; set; } = [];

    public int OpenCount(AlertGroup? group)
    {
        return group == null ? OpenCounts.Values.Sum() : OpenCounts.GetValueOrDefault(group.Value);
    }

    /// <summary>
    /// With no filter chosen, the page opens on what matters: unresolved alerts of medium severity or higher.
    /// </summary>
    public static async Task<AlertsPage> Build(DataContext dataContext, AlertFilter alertFilter, bool filterChosen)
    {
        if (!filterChosen)
        {
            alertFilter.Status = AlertStatus.Open;
            alertFilter.Severity = AlertSeverity.Medium;
        }

        var alerts = await Alert.GetFiltered(dataContext, alertFilter);
        await Alert.AttachHostActions(dataContext, alerts.Take(100));

        return new AlertsPage
        {
            Filter = alertFilter,
            Alerts = alerts,
            OpenCounts = await Alert.CountOpenByGroup(dataContext, AlertSeverity.Medium, DateTime.UtcNow.Subtract(alertFilter.TimeRange.Duration))
        };
    }
}
