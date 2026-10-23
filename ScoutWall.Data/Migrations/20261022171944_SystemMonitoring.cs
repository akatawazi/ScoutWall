using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class SystemMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "scope",
                table: "alerts",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "subject",
                table: "alerts",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "process_resource_samples",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    process_image_id = table.Column<long>(type: "INTEGER", nullable: false),
                    cpu_percent_average = table.Column<double>(type: "REAL", nullable: false),
                    cpu_percent_peak = table.Column<double>(type: "REAL", nullable: false),
                    memory_bytes_peak = table.Column<long>(type: "INTEGER", nullable: false),
                    private_bytes_peak = table.Column<long>(type: "INTEGER", nullable: false),
                    instance_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_process_resource_samples", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_events",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    occurred_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    channel = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    event_id = table.Column<int>(type: "INTEGER", nullable: false),
                    level = table.Column<int>(type: "INTEGER", nullable: false),
                    provider = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    category = table.Column<int>(type: "INTEGER", nullable: false),
                    subject = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    program_path = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    remote_address = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    summary = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    occurrence_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_events", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_resource_minutes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    cpu_percent = table.Column<double>(type: "REAL", nullable: false),
                    memory_used_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    memory_total_bytes = table.Column<long>(type: "INTEGER", nullable: false),
                    process_count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_resource_minutes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_services",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    service_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    state = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    start_mode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    binary_path = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    account = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    is_baseline = table.Column<bool>(type: "INTEGER", nullable: false),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_changed_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    removed_at = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_services", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_process_resource_samples_bucket_start_process_image_id",
                table: "process_resource_samples",
                columns: new[] { "bucket_start", "process_image_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_process_resource_samples_process_image_id_bucket_start",
                table: "process_resource_samples",
                columns: new[] { "process_image_id", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_system_events_channel_event_id_occurred_at",
                table: "system_events",
                columns: new[] { "channel", "event_id", "occurred_at" });

            migrationBuilder.CreateIndex(
                name: "IX_system_events_occurred_at",
                table: "system_events",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "IX_system_resource_minutes_bucket_start",
                table: "system_resource_minutes",
                column: "bucket_start",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_system_services_service_name",
                table: "system_services",
                column: "service_name",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "process_resource_samples");

            migrationBuilder.DropTable(
                name: "system_events");

            migrationBuilder.DropTable(
                name: "system_resource_minutes");

            migrationBuilder.DropTable(
                name: "system_services");

            migrationBuilder.DropColumn(
                name: "scope",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "subject",
                table: "alerts");
        }
    }
}
