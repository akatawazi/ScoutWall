using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class UserPresenceSplit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "is_user_idle",
                table: "process_traffic_minutes",
                newName: "user_presence");

            migrationBuilder.RenameIndex(
                name: "IX_process_traffic_minutes_bucket_start_process_image_id_remote_ip_protocol_is_user_idle",
                table: "process_traffic_minutes",
                newName: "IX_process_traffic_minutes_bucket_start_process_image_id_remote_ip_protocol_user_presence");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "user_presence",
                table: "process_traffic_minutes",
                newName: "is_user_idle");

            migrationBuilder.RenameIndex(
                name: "IX_process_traffic_minutes_bucket_start_process_image_id_remote_ip_protocol_user_presence",
                table: "process_traffic_minutes",
                newName: "IX_process_traffic_minutes_bucket_start_process_image_id_remote_ip_protocol_is_user_idle");
        }
    }
}
