using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class FileAreas : Migration
    {
        /// <summary>
        /// The chat view of file changes gains the area and the "read" kind.
        /// </summary>
        private static readonly (string Name, string Select)[] Views =
        [
            ("chat_file_changes", """
                SELECT datetime(f.bucket_start, 'unixepoch') AS minute_utc, f.path, f.folder, f.extension,
                       CASE f.kind WHEN 1 THEN 'created' WHEN 2 THEN 'modified' WHEN 3 THEN 'deleted' WHEN 4 THEN 'renamed' WHEN 5 THEN 'read' END AS change,
                       CASE f.area WHEN 1 THEN 'my files' WHEN 2 THEN 'app data' WHEN 3 THEN 'program files' WHEN 4 THEN 'windows' ELSE 'other' END AS area,
                       f.old_path, p.image_path AS program_path, f.change_count
                FROM file_changes f LEFT JOIN process_images p ON p.id = f.process_image_id
                """)
        ];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "area",
                table: "file_changes",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.CreateIndex(
                name: "IX_file_changes_area_bucket_start",
                table: "file_changes",
                columns: new[] { "area", "bucket_start" });

            // Rows recorded before areas existed get one from their path. The sensor's own rules (which follow moved
            // Documents folders) apply to everything recorded from now on. 1 my files, 2 app data, 3 Program Files,
            // 4 Windows, 5 other.
            migrationBuilder.Sql("""
                UPDATE file_changes SET area = CASE
                    WHEN path LIKE '_:\Windows\%' THEN 4
                    WHEN path LIKE '_:\Program Files\%' OR path LIKE '_:\Program Files (x86)\%' THEN 3
                    WHEN path LIKE '_:\ProgramData\%' THEN 2
                    WHEN path LIKE '_:\Users\%\AppData\%' OR path LIKE '_:\Users\%\.%\%' THEN 2
                    WHEN path LIKE '_:\Users\Default\%' OR path LIKE '_:\Users\All Users\%' THEN 5
                    WHEN path LIKE '_:\Users\%\%\%' THEN 1
                    WHEN path LIKE '_:\Users\%' THEN 2
                    WHEN path NOT LIKE 'C:%' AND path NOT LIKE '%\$Recycle.Bin\%' AND path NOT LIKE '%\System Volume Information\%' THEN 1
                    ELSE 5 END;
                """);

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
            migrationBuilder.Sql("""
                CREATE VIEW chat_file_changes AS
                SELECT datetime(f.bucket_start, 'unixepoch') AS minute_utc, f.path, f.folder, f.extension,
                       CASE f.kind WHEN 1 THEN 'created' WHEN 2 THEN 'modified' WHEN 3 THEN 'deleted' WHEN 4 THEN 'renamed' END AS change,
                       f.old_path, p.image_path AS program_path, f.change_count
                FROM file_changes f LEFT JOIN process_images p ON p.id = f.process_image_id;
                """);

            migrationBuilder.DropIndex(
                name: "IX_file_changes_area_bucket_start",
                table: "file_changes");

            migrationBuilder.DropColumn(
                name: "area",
                table: "file_changes");
        }
    }
}
