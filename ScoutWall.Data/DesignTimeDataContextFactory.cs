using Microsoft.EntityFrameworkCore.Design;

namespace ScoutWall.Data;

/// <summary>
/// Used only by the dotnet-ef tooling when creating migrations.
/// </summary>
public class DesignTimeDataContextFactory : IDesignTimeDbContextFactory<DataContext>
{
    public DataContext CreateDbContext(string[] args)
    {
        var databasePath = Path.Combine(Path.GetTempPath(), "scoutwall-design.db");
        return DataContext.Create(databasePath);
    }
}
