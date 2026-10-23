using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class AnalystSetupAndChat : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "company",
                table: "process_images",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "file_version",
                table: "process_images",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "friendly_name",
                table: "process_images",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "identity_read_at",
                table: "process_images",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "product_name",
                table: "process_images",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "publisher",
                table: "process_images",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "original_verdict",
                table: "flow_verdicts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "is_recommended",
                table: "capture_interfaces",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<long>(
                name: "analyst_assessment_id",
                table: "alerts",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "analyst_note",
                table: "alerts",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "response_considered",
                table: "alerts",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateTable(
                name: "analyst_assessments",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    case_key = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    verdict = table.Column<int>(type: "INTEGER", nullable: false),
                    confidence = table.Column<double>(type: "REAL", nullable: false),
                    title = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    explanation = table.Column<string>(type: "TEXT", nullable: false),
                    recommended_action = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    proposes_suppression = table.Column<bool>(type: "INTEGER", nullable: false),
                    floor_note = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    remember_until = table.Column<DateTime>(type: "TEXT", nullable: true),
                    envelope_bytes_out_per_hour = table.Column<long>(type: "INTEGER", nullable: false),
                    envelope_idle_share = table.Column<double>(type: "REAL", nullable: false),
                    process_fingerprint = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    process_path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    remote_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    destination = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    rule_name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    alert_id = table.Column<long>(type: "INTEGER", nullable: true),
                    evidence_json = table.Column<string>(type: "TEXT", nullable: false),
                    reused_from_id = table.Column<long>(type: "INTEGER", nullable: true),
                    model = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    input_tokens = table.Column<long>(type: "INTEGER", nullable: false),
                    output_tokens = table.Column<long>(type: "INTEGER", nullable: false),
                    cache_read_tokens = table.Column<long>(type: "INTEGER", nullable: false),
                    tool_calls = table.Column<int>(type: "INTEGER", nullable: false),
                    acknowledged = table.Column<bool>(type: "INTEGER", nullable: false),
                    acknowledged_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    acknowledged_at = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_analyst_assessments", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "chat_messages",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    user_id = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    from_user = table.Column<bool>(type: "INTEGER", nullable: false),
                    text = table.Column<string>(type: "TEXT", nullable: false),
                    tokens = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_chat_messages", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "pending_changes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    user_id = table.Column<long>(type: "INTEGER", nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    expires_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    kind = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    payload_json = table.Column<string>(type: "TEXT", nullable: false),
                    summary = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    consequence = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    based_on_network_data = table.Column<bool>(type: "INTEGER", nullable: false),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    resolved_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    error = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_pending_changes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "system_state",
                columns: table => new
                {
                    state_key = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    state_value = table.Column<string>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_system_state", x => x.state_key);
                });

            migrationBuilder.CreateIndex(
                name: "IX_analyst_assessments_case_key_created_at",
                table: "analyst_assessments",
                columns: new[] { "case_key", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_analyst_assessments_created_at",
                table: "analyst_assessments",
                column: "created_at");

            migrationBuilder.CreateIndex(
                name: "IX_analyst_assessments_verdict_acknowledged",
                table: "analyst_assessments",
                columns: new[] { "verdict", "acknowledged" });

            migrationBuilder.CreateIndex(
                name: "IX_chat_messages_user_id_created_at",
                table: "chat_messages",
                columns: new[] { "user_id", "created_at" });

            migrationBuilder.CreateIndex(
                name: "IX_pending_changes_user_id_status",
                table: "pending_changes",
                columns: new[] { "user_id", "status" });

            // Alerts from before this upgrade were already handled by the old immediate response planning.
            migrationBuilder.Sql("UPDATE alerts SET response_considered = 1;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "analyst_assessments");

            migrationBuilder.DropTable(
                name: "chat_messages");

            migrationBuilder.DropTable(
                name: "pending_changes");

            migrationBuilder.DropTable(
                name: "system_state");

            migrationBuilder.DropColumn(
                name: "company",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "file_version",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "friendly_name",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "identity_read_at",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "product_name",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "publisher",
                table: "process_images");

            migrationBuilder.DropColumn(
                name: "original_verdict",
                table: "flow_verdicts");

            migrationBuilder.DropColumn(
                name: "is_recommended",
                table: "capture_interfaces");

            migrationBuilder.DropColumn(
                name: "analyst_assessment_id",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "analyst_note",
                table: "alerts");

            migrationBuilder.DropColumn(
                name: "response_considered",
                table: "alerts");
        }
    }
}
