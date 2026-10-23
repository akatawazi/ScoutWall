using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class PresencePeriods : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "presence_periods",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    state = table.Column<int>(type: "INTEGER", nullable: false),
                    source = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    started_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    noticed_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    confirmed_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ended_at = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_presence_periods", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_presence_periods_ended_at",
                table: "presence_periods",
                column: "ended_at");

            migrationBuilder.CreateIndex(
                name: "IX_presence_periods_started_at",
                table: "presence_periods",
                column: "started_at");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "presence_periods");
        }
    }
}
