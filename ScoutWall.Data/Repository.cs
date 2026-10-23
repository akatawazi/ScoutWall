using System.Linq.Expressions;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace ScoutWall.Data;

public abstract class Repository<T> where T : class
{
    public static async Task<List<T>> GetAll(DataContext dataContext)
    {
        return await Query(dataContext).ToListAsync();
    }

    public static async Task<List<T>> GetAll(DataContext dataContext, Expression<Func<T, bool>> predicate)
    {
        return await Query(dataContext).Where(predicate).ToListAsync();
    }

    public static async Task<T?> Get(DataContext dataContext, Expression<Func<T, bool>> predicate)
    {
        return await Query(dataContext).FirstOrDefaultAsync(predicate);
    }

    public static async Task<T> Insert(DataContext dataContext, T entity)
    {
        dataContext.Set<T>().Add(entity);
        await dataContext.SaveChangesAsync();
        return entity;
    }

    public static async Task<T> Update(DataContext dataContext, T entity)
    {
        dataContext.Set<T>().Update(entity);
        await dataContext.SaveChangesAsync();
        return entity;
    }

    public static async Task Delete(DataContext dataContext, T entity)
    {
        dataContext.Set<T>().Remove(entity);
        await dataContext.SaveChangesAsync();
    }

    public static async Task<bool> DeleteById(DataContext dataContext, object id)
    {
        var entity = await dataContext.Set<T>().FindAsync(id);
        if (entity == null)
            return false;

        await Delete(dataContext, entity);
        return true;
    }

    public static async Task<int> DeleteWhere(DataContext dataContext, Expression<Func<T, bool>> predicate)
    {
        return await dataContext.Set<T>().Where(predicate).ExecuteDeleteAsync();
    }

    public static async Task<int> Count(DataContext dataContext)
    {
        return await Query(dataContext).CountAsync();
    }

    public static async Task<int> Count(DataContext dataContext, Expression<Func<T, bool>> predicate)
    {
        return await Query(dataContext).CountAsync(predicate);
    }

    protected static IQueryable<T> Query(DataContext dataContext)
    {
        return dataContext.Set<T>().AsNoTracking();
    }

    /// <summary>
    /// Runs one SQL statement for every row inside a single transaction.
    /// Joins the caller's transaction when one is already open. Used for high-volume sensor upserts.
    /// </summary>
    protected static async Task ExecuteBatch<TRow>(
        DataContext dataContext,
        string commandText,
        IEnumerable<TRow> rows,
        Action<SqliteParameterCollection, TRow> bindParameters)
    {
        var ownsTransaction = dataContext.Database.CurrentTransaction == null;
        var transaction = dataContext.Database.CurrentTransaction ?? await dataContext.Database.BeginTransactionAsync();

        try
        {
            var connection = (SqliteConnection)dataContext.Database.GetDbConnection();
            await using var command = connection.CreateCommand();
            command.CommandText = commandText;
            command.Transaction = (SqliteTransaction)transaction.GetDbTransaction();

            foreach (var row in rows)
            {
                command.Parameters.Clear();
                bindParameters(command.Parameters, row);
                await command.ExecuteNonQueryAsync();
            }

            if (ownsTransaction)
                await transaction.CommitAsync();
        }
        finally
        {
            if (ownsTransaction)
                await transaction.DisposeAsync();
        }
    }

    protected static object DatabaseValue(object? value)
    {
        return value ?? DBNull.Value;
    }
}
