using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class IoTracking : Migration
    {
        /// <summary>
        /// Views for "Ask ScoutWall" over the new I/O data; the program resources view gains read and write bytes.
        /// </summary>
        private static readonly (string Name, string Select)[] Views =
        [
            ("chat_file_changes", """
                SELECT datetime(f.bucket_start, 'unixepoch') AS minute_utc, f.path, f.folder, f.extension,
                       CASE f.kind WHEN 1 THEN 'created' WHEN 2 THEN 'modified' WHEN 3 THEN 'deleted' WHEN 4 THEN 'renamed' END AS change,
                       f.old_path, p.image_path AS program_path, f.change_count
                FROM file_changes f LEFT JOIN process_images p ON p.id = f.process_image_id
                """),
            ("chat_disk_activity", """
                SELECT datetime(bucket_start, 'unixepoch') AS minute_utc, disk_number, drives, read_bytes, write_bytes,
                       read_count, write_count, busy_percent, queue_depth
                FROM disk_io_minutes
                """),
            ("chat_program_resources", """
                SELECT datetime(r.bucket_start, 'unixepoch') AS period_start_utc, p.image_path AS program_path,
                       r.cpu_percent_average, r.cpu_percent_peak, r.memory_bytes_peak, r.private_bytes_peak, r.instance_count,
                       r.read_bytes, r.write_bytes, r.other_bytes
                FROM process_resource_samples r JOIN process_images p ON p.id = r.process_image_id
                """)
        ];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "other_bytes",
                table: "process_resource_samples",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "read_bytes",
                table: "process_resource_samples",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "write_bytes",
                table: "process_resource_samples",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.CreateTable(
                name: "disk_io_minutes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    disk_number = table.Column<int>(type: "INTEGER", nullable: false),
                    drives = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    read_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    write_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    read_count = table.Column<long>(type: "INTEGER", nullable: false),
                    write_count = table.Column<long>(type: "INTEGER", nullable: false),
                    busy_percent = table.Column<double>(type: "REAL", nullable: false),
                    queue_depth = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_disk_io_minutes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "file_changes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    folder = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    extension = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    kind = table.Column<int>(type: "INTEGER", nullable: false),
                    old_path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    process_image_id = table.Column<long>(type: "INTEGER", nullable: true),
                    change_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_changes", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_disk_io_minutes_bucket_start_disk_number",
                table: "disk_io_minutes",
                columns: new[] { "bucket_start", "disk_number" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_file_changes_bucket_start_path_kind",
                table: "file_changes",
                columns: new[] { "bucket_start", "path", "kind" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_file_changes_folder_bucket_start",
                table: "file_changes",
                columns: new[] { "folder", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_file_changes_process_image_id_bucket_start",
                table: "file_changes",
                columns: new[] { "process_image_id", "bucket_start" });

            foreach (var (name, select) in Views)
            {
                migrationBuilder.Sql($"DROP VIEW IF EXISTS {name};");
                migrationBuilder.Sql($"CREATE VIEW {name} AS {select};");
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql("DROP VIEW IF EXISTS chat_file_changes;");
            migrationBuilder.Sql("DROP VIEW IF EXISTS chat_disk_activity;");
            migrationBuilder.Sql("DROP VIEW IF EXISTS chat_program_resources;");
            migrationBuilder.Sql("""
                CREATE VIEW chat_program_resources AS
                SELECT datetime(r.bucket_start, 'unixepoch') AS period_start_utc, p.image_path AS program_path,
                       r.cpu_percent_average, r.cpu_percent_peak, r.memory_bytes_peak, r.private_bytes_peak, r.instance_count
                FROM process_resource_samples r JOIN process_images p ON p.id = r.process_image_id;
                """);

            migrationBuilder.DropTable(
                name: "disk_io_minutes");

            migrationBuilder.DropTable(
                name: "file_changes");

            migrationBuilder.DropColumn(
                name: "other_bytes",
                table: "process_resource_samples");

            migrationBuilder.DropColumn(
                name: "read_bytes",
                table: "process_resource_samples");

            migrationBuilder.DropColumn(
                name: "write_bytes",
                table: "process_resource_samples");
        }
    }
}
