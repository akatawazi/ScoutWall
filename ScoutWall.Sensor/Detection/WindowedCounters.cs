namespace ScoutWall.Sensor.Detection;

/// <summary>
/// Sums values per key over fixed (tumbling) time windows.
/// </summary>
public class WindowedCounter<TKey> where TKey : notnull
{
    private readonly Dictionary<TKey, (DateTime WindowStart, long Total)> totals = [];

    public long Add(TKey key, long amount, DateTime timestamp, TimeSpan window)
    {
        if (!totals.TryGetValue(key, out var entry) || timestamp - entry.WindowStart >= window)
            entry = (timestamp, 0);

        entry.Total += amount;
        totals[key] = entry;
        return entry.Total;
    }

    public void Reset(TKey key)
    {
        totals.Remove(key);
    }

    public void Prune(DateTime now, TimeSpan window)
    {
        var expiredKeys = totals.Where(entry => now - entry.Value.WindowStart >= window).Select(entry => entry.Key).ToList();
        foreach (var expiredKey in expiredKeys)
            totals.Remove(expiredKey);
    }
}

/// <summary>
/// Counts distinct values per key over fixed time windows, for example distinct ports per scanning address.
/// </summary>
public class WindowedDistinctCounter<TKey, TValue> where TKey : notnull
{
    private const int MaximumValuesPerKey = 70_000;
    private readonly Dictionary<TKey, (DateTime WindowStart, HashSet<TValue> Values)> windows = [];

    public int Add(TKey key, TValue value, DateTime timestamp, TimeSpan window)
    {
        if (!windows.TryGetValue(key, out var entry) || timestamp - entry.WindowStart >= window)
        {
            entry = (timestamp, []);
            windows[key] = entry;
        }

        if (entry.Values.Count < MaximumValuesPerKey)
            entry.Values.Add(value);

        return entry.Values.Count;
    }

    public IReadOnlyCollection<TValue> GetValues(TKey key)
    {
        return windows.TryGetValue(key, out var entry) ? entry.Values : [];
    }

    public void Reset(TKey key)
    {
        windows.Remove(key);
    }

    public void Prune(DateTime now, TimeSpan window)
    {
        var expiredKeys = windows.Where(entry => now - entry.Value.WindowStart >= window).Select(entry => entry.Key).ToList();
        foreach (var expiredKey in expiredKeys)
            windows.Remove(expiredKey);
    }
}
