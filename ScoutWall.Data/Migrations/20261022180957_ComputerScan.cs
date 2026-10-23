using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class ComputerScan : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "scan_results",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    scan_started_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    kind = table.Column<int>(type: "INTEGER", nullable: false),
                    name = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    target = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    program_path = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    command = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    signals = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    score = table.Column<int>(type: "INTEGER", nullable: false),
                    assistant_verdict = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    assistant_reason = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    recommendation = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_results", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scan_results_scan_started_at",
                table: "scan_results",
                column: "scan_started_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scan_results");
        }
    }
}
