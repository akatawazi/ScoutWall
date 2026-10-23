using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SQLitePCL;

namespace ScoutWall.Data.Querying;

/// <summary>
/// Lets the assistant answer questions with its own SQL, safely. Queries run on a separate read-only connection
/// and SQLite's authorizer allows nothing but reading the table columns the chat_ views (created by a migration)
/// are built from, and calling a short list of ordinary functions. Those columns are learnt by preparing each view
/// under a recording authorizer; names in the query itself are never trusted, because a query can call its own
/// sub-query "chat_anything". Accounts, settings with API keys, chat history and decrypted traffic have no view,
/// so they can't be read; neither can SQLite's own schema or raw pages. Each query is stopped after a few seconds
/// and the result is cut to a size the model can take in.
/// </summary>
public static class ReadOnlyQuery
{
    public const string ViewPrefix = "chat_";

    private const int MaximumRows = 200;
    private const int MaximumCharacters = 48_000;
    private static readonly TimeSpan TimeLimit = TimeSpan.FromSeconds(5);

    private const int SqliteOk = 0;
    private const int SqliteDeny = 1;
    private const int ActionRead = 20;
    private const int ActionSelect = 21;
    private const int ActionFunction = 31;
    private const int ActionRecursive = 33;

    private static readonly HashSet<string> AllowedFunctions = new(StringComparer.OrdinalIgnoreCase)
    {
        "count", "sum", "total", "min", "max", "avg", "group_concat", "string_agg",
        "abs", "round", "coalesce", "ifnull", "nullif", "iif", "typeof", "length", "lower", "upper", "trim", "ltrim", "rtrim",
        "substr", "substring", "instr", "replace", "like", "glob", "printf", "format", "char", "unicode", "hex",
        "date", "time", "datetime", "julianday", "strftime", "unixepoch", "timediff",
        "row_number", "rank", "dense_rank", "lag", "lead", "first_value", "last_value"
    };

    /// <summary>
    /// What each view holds, for the tool description. Column lists are read from the database itself.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> ViewDescriptions = new Dictionary<string, string>
    {
        ["chat_program_traffic"] = "bytes a program exchanged with one remote address per minute, with presence (here/away/unknown) and times in UTC",
        ["chat_traffic_by_hour"] = "all network traffic per hour per remote and local address and port, including traffic not linked to a program",
        ["chat_addresses"] = "what is known about each IP address: place, network owner, reverse DNS name, blocklist",
        ["chat_dns_names"] = "names seen in DNS answers for each IP address",
        ["chat_tls_names"] = "site names seen when connections were set up (TLS server name) for each IP address",
        ["chat_programs"] = "programs ScoutWall has seen, with publisher and when first seen",
        ["chat_alerts"] = "alerts raised by ScoutWall",
        ["chat_blocks"] = "blocks and other actions ScoutWall applied",
        ["chat_findings"] = "the assistant's own assessments of alerts",
        ["chat_verdicts"] = "per-connection verdicts from the scoring",
        ["chat_system_events"] = "notable Windows events",
        ["chat_services"] = "Windows services",
        ["chat_scan_results"] = "items flagged by the last computer scan",
        ["chat_presence"] = "periods when the owner was here, away or unknown",
        ["chat_program_resources"] = "processor and memory use per program in 5-minute steps, with bytes read and written (file, network and device I/O together)",
        ["chat_file_changes"] = "files created, modified, deleted, renamed or read per minute, with the area (my files, app data, program files, windows, other) and the program where known; reads are only recorded for my files when read tracking is on",
        ["chat_disk_activity"] = "bytes each physical disk read and wrote per minute, and how busy it was",
        ["chat_system_resources"] = "processor and memory use of the whole computer per minute"
    };

    public static async Task<string> DescribeViews(DataContext dataContext)
    {
        await using var connection = Open(dataContext);
        var lines = new List<string>();
        foreach (var (view, description) in ViewDescriptions)
        {
            await using var command = connection.CreateCommand();
            command.CommandText = $"SELECT name FROM pragma_table_info('{view}')";
            var columns = new List<string>();
            await using (var reader = await command.ExecuteReaderAsync())
            {
                while (await reader.ReadAsync())
                    columns.Add(reader.GetString(0));
            }

            if (columns.Count > 0)
                lines.Add($"{view}({string.Join(", ", columns)}): {description}");
        }

        return string.Join("\n", lines);
    }

    public static async Task<object> Run(DataContext dataContext, string sql, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(sql))
            return new { error = "Give a SELECT query over the chat_ views." };

        await using var connection = Open(dataContext);
        await using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA query_only = 1;";
            await pragma.ExecuteNonQueryAsync(cancellationToken);
        }

        var handle = connection.Handle!;
        var readableColumns = await ReadableColumns(connection);
        var stopwatch = Stopwatch.StartNew();
        raw.sqlite3_set_authorizer(handle, (_, actionCode, param0, param1, _, _) => actionCode switch
        {
            ActionSelect or ActionRecursive => SqliteOk,
            ActionRead => IsReadable(readableColumns, param0, param1) ? SqliteOk : SqliteDeny,
            ActionFunction => AllowedFunctions.Contains(param1 ?? string.Empty) ? SqliteOk : SqliteDeny,
            _ => SqliteDeny
        }, null);
        raw.sqlite3_progress_handler(handle, 10_000, _ => stopwatch.Elapsed > TimeLimit || cancellationToken.IsCancellationRequested ? 1 : 0, null);

        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = sql;
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);

            var columns = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName).ToList();
            var rows = new List<object?[]>();
            var characters = 0;
            var truncated = false;
            while (await reader.ReadAsync(cancellationToken))
            {
                if (rows.Count >= MaximumRows || characters >= MaximumCharacters)
                {
                    truncated = true;
                    break;
                }

                var row = new object?[reader.FieldCount];
                for (var index = 0; index < reader.FieldCount; index++)
                {
                    row[index] = reader.IsDBNull(index) ? null : reader.GetValue(index) switch
                    {
                        byte[] => "[binary]",
                        string text when text.Length > 500 => text[..500] + "…",
                        var value => value
                    };
                    characters += row[index]?.ToString()?.Length ?? 4;
                }

                rows.Add(row);
            }

            return new { columns, rows, row_count = rows.Count, truncated, note = truncated ? "More rows matched; add filters, GROUP BY or LIMIT." : null };
        }
        catch (SqliteException exception)
        {
            var message = exception.SqliteErrorCode switch
            {
                23 => "Not allowed: only the chat_ views can be read, with ordinary functions.",
                9 => "The query took too long and was stopped. Narrow it with a time filter or LIMIT.",
                _ => exception.Message
            };
            return new { error = message, available_views = ViewDescriptions.Keys };
        }
        finally
        {
            raw.sqlite3_progress_handler(handle, 0, null, null);
        }
    }

    private static HashSet<(string Table, string Column)>? readableColumnsCache;
    private static HashSet<string> databaseTables = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// A column the views expose, or a read with no column at all (COUNT(*), a WITH sub-query's own name), which
    /// returns no data; the latter only for tables the views use or for names that aren't database tables.
    /// </summary>
    private static bool IsReadable(HashSet<(string Table, string Column)> readableColumns, string? table, string? column)
    {
        table ??= string.Empty;
        if (!string.IsNullOrEmpty(column))
            return readableColumns.Contains((table, column));

        return readableColumns.Any(entry => string.Equals(entry.Table, table, StringComparison.OrdinalIgnoreCase)) || !databaseTables.Contains(table);
    }

    /// <summary>
    /// The (table, column) pairs the chat_ views read, recorded while ScoutWall itself prepares each view.
    /// </summary>
    private static async Task<HashSet<(string Table, string Column)>> ReadableColumns(SqliteConnection connection)
    {
        if (readableColumnsCache != null)
            return readableColumnsCache;

        var tables = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        await using (var tableCommand = connection.CreateCommand())
        {
            tableCommand.CommandText = "SELECT name FROM sqlite_master WHERE type IN ('table', 'view')";
            await using var tableReader = await tableCommand.ExecuteReaderAsync();
            while (await tableReader.ReadAsync())
                tables.Add(tableReader.GetString(0));
        }

        tables.UnionWith(["sqlite_master", "sqlite_schema", "sqlite_temp_master", "sqlite_temp_schema", "sqlite_sequence", "sqlite_stat1", "sqlite_dbpage", "sqlite_dbstat"]);
        databaseTables = tables;

        var columns = new HashSet<(string Table, string Column)>();
        raw.sqlite3_set_authorizer(connection.Handle!, (_, actionCode, param0, param1, _, _) =>
        {
            if (actionCode == ActionRead && param0 != null)
                columns.Add((param0, param1 ?? string.Empty));
            return SqliteOk;
        }, null);

        try
        {
            foreach (var view in ViewDescriptions.Keys)
            {
                await using var command = connection.CreateCommand();
                command.CommandText = $"SELECT * FROM {view} LIMIT 0";
                await using var reader = await command.ExecuteReaderAsync();
            }
        }
        finally
        {
            raw.sqlite3_set_authorizer(connection.Handle!, (strdelegate_authorizer)null!, null);
        }

        readableColumnsCache = columns;
        return columns;
    }

    private static SqliteConnection Open(DataContext dataContext)
    {
        var builder = new SqliteConnectionStringBuilder(dataContext.Database.GetConnectionString())
        {
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false
        };
        var connection = new SqliteConnection(builder.ToString());
        connection.Open();
        return connection;
    }
}
