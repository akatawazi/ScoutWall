using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class PublisherVerified : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "publisher_verified",
                table: "process_images",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            // Read every program's signature again now, so Windows' own catalog-signed files get their publisher.
            migrationBuilder.Sql("UPDATE process_images SET identity_read_at = NULL;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "publisher_verified",
                table: "process_images");
        }
    }
}
