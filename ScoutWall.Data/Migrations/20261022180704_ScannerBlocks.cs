using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class ScannerBlocks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "scanner_blocks",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ip_address = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    reason = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    hit_count = table.Column<int>(type: "INTEGER", nullable: false),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    expires_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scanner_blocks", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scanner_blocks_expires_at",
                table: "scanner_blocks",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "IX_scanner_blocks_ip_address",
                table: "scanner_blocks",
                column: "ip_address",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "scanner_blocks");
        }
    }
}
