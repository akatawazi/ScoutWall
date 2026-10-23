using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "alerts",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    rule_name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    severity = table.Column<int>(type: "INTEGER", nullable: false),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    title = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    description = table.Column<string>(type: "TEXT", nullable: false),
                    source_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    destination_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    destination_port = table.Column<int>(type: "INTEGER", nullable: true),
                    protocol = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
                    process_path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    occurrence_count = table.Column<int>(type: "INTEGER", nullable: false),
                    details = table.Column<string>(type: "TEXT", nullable: true),
                    acknowledged_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    acknowledged_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    resolved_at = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_alerts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "audit_entries",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    occurred_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    user_email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    action = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    target = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    details = table.Column<string>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_entries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "capture_interfaces",
                columns: table => new
                {
                    name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    friendly_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    description = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    addresses = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    mac_address = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    is_loopback = table.Column<bool>(type: "INTEGER", nullable: false),
                    is_capturing = table.Column<bool>(type: "INTEGER", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_capture_interfaces", x => x.name);
                });

            migrationBuilder.CreateTable(
                name: "decrypted_requests",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    captured_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    client_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    server_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    server_port = table.Column<int>(type: "INTEGER", nullable: false),
                    http_version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    method = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    host = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    path = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    user_agent = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
                    source_file = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_decrypted_requests", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "dns_records",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ip_address = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    hostname = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    record_type = table.Column<string>(type: "TEXT", maxLength: 8, nullable: false),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    seen_count = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_dns_records", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "flow_verdicts",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    evaluated_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    provider = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    verdict = table.Column<int>(type: "INTEGER", nullable: false),
                    confidence = table.Column<double>(type: "REAL", nullable: false),
                    score = table.Column<int>(type: "INTEGER", nullable: true),
                    reasons = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    is_shadow = table.Column<bool>(type: "INTEGER", nullable: false),
                    local_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    remote_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    service_port = table.Column<int>(type: "INTEGER", nullable: false),
                    protocol = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    direction = table.Column<int>(type: "INTEGER", nullable: false),
                    process_path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    hostname = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    features_json = table.Column<string>(type: "TEXT", nullable: false),
                    state_hash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    template_version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_flow_verdicts", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "ip_address_profiles",
                columns: table => new
                {
                    ip_address = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    is_private = table.Column<bool>(type: "INTEGER", nullable: false),
                    country_code = table.Column<string>(type: "TEXT", maxLength: 2, nullable: true),
                    country_name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    region = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    city = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    latitude = table.Column<double>(type: "REAL", nullable: true),
                    longitude = table.Column<double>(type: "REAL", nullable: true),
                    isp = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    organization = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    autonomous_system_number = table.Column<long>(type: "INTEGER", nullable: true),
                    autonomous_system_organization = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    reverse_dns = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    lookup_source = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    lookup_error = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    looked_up_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    is_blocklisted = table.Column<bool>(type: "INTEGER", nullable: false),
                    blocklist_source = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ip_address_profiles", x => x.ip_address);
                });

            migrationBuilder.CreateTable(
                name: "notification_deliveries",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    alert_id = table.Column<long>(type: "INTEGER", nullable: true),
                    channel = table.Column<int>(type: "INTEGER", nullable: false),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    severity = table.Column<int>(type: "INTEGER", nullable: false),
                    title = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    message = table.Column<string>(type: "TEXT", nullable: false),
                    attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    next_attempt_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    sent_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    last_error = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_notification_deliveries", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "process_images",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    image_path = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_process_images", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "process_traffic_minutes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    process_image_id = table.Column<long>(type: "INTEGER", nullable: false),
                    remote_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    protocol = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    bytes_sent = table.Column<long>(type: "INTEGER", nullable: false),
                    bytes_received = table.Column<long>(type: "INTEGER", nullable: false),
                    is_user_idle = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_process_traffic_minutes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "response_actions",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    action_type = table.Column<int>(type: "INTEGER", nullable: false),
                    target = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    block_inbound = table.Column<bool>(type: "INTEGER", nullable: false),
                    block_outbound = table.Column<bool>(type: "INTEGER", nullable: false),
                    reason = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    alert_id = table.Column<long>(type: "INTEGER", nullable: true),
                    status = table.Column<int>(type: "INTEGER", nullable: false),
                    ends_when_user_returns = table.Column<bool>(type: "INTEGER", nullable: false),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    created_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    expires_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    applied_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    removed_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    last_error = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_response_actions", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "sensor_statuses",
                columns: table => new
                {
                    sensor_name = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    capture_mode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: false),
                    interfaces = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    started_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_heartbeat_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    packets_captured = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_dropped = table.Column<long>(type: "INTEGER", nullable: false),
                    bytes_captured = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_per_second = table.Column<double>(type: "REAL", nullable: false),
                    bits_per_second = table.Column<double>(type: "REAL", nullable: false),
                    is_user_idle = table.Column<bool>(type: "INTEGER", nullable: true),
                    active_response_mode = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
                    configuration_version = table.Column<long>(type: "INTEGER", nullable: false),
                    last_error = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sensor_statuses", x => x.sensor_name);
                });

            migrationBuilder.CreateTable(
                name: "settings",
                columns: table => new
                {
                    section_name = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    value_json = table.Column<string>(type: "TEXT", nullable: false),
                    revision = table.Column<long>(type: "INTEGER", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_by = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_settings", x => x.section_name);
                });

            migrationBuilder.CreateTable(
                name: "tls_sessions",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    client_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    server_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    server_port = table.Column<int>(type: "INTEGER", nullable: false),
                    server_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    tls_version = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    application_protocols = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    process_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    first_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    last_seen_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    connection_count = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tls_sessions", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "traffic_hours",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    remote_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    local_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    service_port = table.Column<int>(type: "INTEGER", nullable: false),
                    protocol = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    direction = table.Column<int>(type: "INTEGER", nullable: false),
                    bytes_in = table.Column<long>(type: "INTEGER", nullable: false),
                    bytes_out = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_in = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_out = table.Column<long>(type: "INTEGER", nullable: false),
                    connection_count = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_traffic_hours", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "traffic_minutes",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    bucket_start = table.Column<long>(type: "INTEGER", nullable: false),
                    remote_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    local_ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    service_port = table.Column<int>(type: "INTEGER", nullable: false),
                    protocol = table.Column<string>(type: "TEXT", maxLength: 16, nullable: false),
                    direction = table.Column<int>(type: "INTEGER", nullable: false),
                    bytes_in = table.Column<long>(type: "INTEGER", nullable: false),
                    bytes_out = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_in = table.Column<long>(type: "INTEGER", nullable: false),
                    packets_out = table.Column<long>(type: "INTEGER", nullable: false),
                    connection_count = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_traffic_minutes", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "user_presences",
                columns: table => new
                {
                    session_key = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    user_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    session_id = table.Column<int>(type: "INTEGER", nullable: false),
                    last_input_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    reported_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_user_presences", x => x.session_key);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    normalized_email = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    display_name = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    password_hash = table.Column<string>(type: "TEXT", nullable: false),
                    must_change_password = table.Column<bool>(type: "INTEGER", nullable: false),
                    failed_login_count = table.Column<int>(type: "INTEGER", nullable: false),
                    locked_until = table.Column<DateTime>(type: "TEXT", nullable: true),
                    last_login_at = table.Column<DateTime>(type: "TEXT", nullable: true),
                    created_at = table.Column<DateTime>(type: "TEXT", nullable: false),
                    updated_at = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_alerts_destination_ip",
                table: "alerts",
                column: "destination_ip");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_rule_name_source_ip_status",
                table: "alerts",
                columns: new[] { "rule_name", "source_ip", "status" });

            migrationBuilder.CreateIndex(
                name: "IX_alerts_source_ip",
                table: "alerts",
                column: "source_ip");

            migrationBuilder.CreateIndex(
                name: "IX_alerts_status_last_seen_at",
                table: "alerts",
                columns: new[] { "status", "last_seen_at" });

            migrationBuilder.CreateIndex(
                name: "IX_audit_entries_occurred_at",
                table: "audit_entries",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "IX_decrypted_requests_captured_at",
                table: "decrypted_requests",
                column: "captured_at");

            migrationBuilder.CreateIndex(
                name: "IX_decrypted_requests_host",
                table: "decrypted_requests",
                column: "host");

            migrationBuilder.CreateIndex(
                name: "IX_decrypted_requests_server_ip",
                table: "decrypted_requests",
                column: "server_ip");

            migrationBuilder.CreateIndex(
                name: "IX_dns_records_hostname",
                table: "dns_records",
                column: "hostname");

            migrationBuilder.CreateIndex(
                name: "IX_dns_records_ip_address_hostname",
                table: "dns_records",
                columns: new[] { "ip_address", "hostname" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_dns_records_last_seen_at",
                table: "dns_records",
                column: "last_seen_at");

            migrationBuilder.CreateIndex(
                name: "IX_flow_verdicts_evaluated_at",
                table: "flow_verdicts",
                column: "evaluated_at");

            migrationBuilder.CreateIndex(
                name: "IX_flow_verdicts_remote_ip",
                table: "flow_verdicts",
                column: "remote_ip");

            migrationBuilder.CreateIndex(
                name: "IX_flow_verdicts_state_hash_provider",
                table: "flow_verdicts",
                columns: new[] { "state_hash", "provider" });

            migrationBuilder.CreateIndex(
                name: "IX_ip_address_profiles_country_code",
                table: "ip_address_profiles",
                column: "country_code");

            migrationBuilder.CreateIndex(
                name: "IX_ip_address_profiles_looked_up_at",
                table: "ip_address_profiles",
                column: "looked_up_at");

            migrationBuilder.CreateIndex(
                name: "IX_notification_deliveries_status_channel_next_attempt_at",
                table: "notification_deliveries",
                columns: new[] { "status", "channel", "next_attempt_at" });

            migrationBuilder.CreateIndex(
                name: "IX_process_images_image_path",
                table: "process_images",
                column: "image_path",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_process_traffic_minutes_bucket_start_process_image_id_remote_ip_protocol_is_user_idle",
                table: "process_traffic_minutes",
                columns: new[] { "bucket_start", "process_image_id", "remote_ip", "protocol", "is_user_idle" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_process_traffic_minutes_process_image_id_bucket_start",
                table: "process_traffic_minutes",
                columns: new[] { "process_image_id", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_process_traffic_minutes_remote_ip_bucket_start",
                table: "process_traffic_minutes",
                columns: new[] { "remote_ip", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_response_actions_action_type_target_status",
                table: "response_actions",
                columns: new[] { "action_type", "target", "status" });

            migrationBuilder.CreateIndex(
                name: "IX_response_actions_status",
                table: "response_actions",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "IX_tls_sessions_client_ip_server_ip_server_port_server_name",
                table: "tls_sessions",
                columns: new[] { "client_ip", "server_ip", "server_port", "server_name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_tls_sessions_last_seen_at",
                table: "tls_sessions",
                column: "last_seen_at");

            migrationBuilder.CreateIndex(
                name: "IX_tls_sessions_server_ip",
                table: "tls_sessions",
                column: "server_ip");

            migrationBuilder.CreateIndex(
                name: "IX_tls_sessions_server_name",
                table: "tls_sessions",
                column: "server_name");

            migrationBuilder.CreateIndex(
                name: "IX_traffic_hours_bucket_start_remote_ip_local_ip_service_port_protocol",
                table: "traffic_hours",
                columns: new[] { "bucket_start", "remote_ip", "local_ip", "service_port", "protocol" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_traffic_hours_local_ip_bucket_start",
                table: "traffic_hours",
                columns: new[] { "local_ip", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_traffic_hours_remote_ip_bucket_start",
                table: "traffic_hours",
                columns: new[] { "remote_ip", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_traffic_minutes_bucket_start_remote_ip_local_ip_service_port_protocol",
                table: "traffic_minutes",
                columns: new[] { "bucket_start", "remote_ip", "local_ip", "service_port", "protocol" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_traffic_minutes_local_ip_bucket_start",
                table: "traffic_minutes",
                columns: new[] { "local_ip", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_traffic_minutes_remote_ip_bucket_start",
                table: "traffic_minutes",
                columns: new[] { "remote_ip", "bucket_start" });

            migrationBuilder.CreateIndex(
                name: "IX_users_normalized_email",
                table: "users",
                column: "normalized_email",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "alerts");

            migrationBuilder.DropTable(
                name: "audit_entries");

            migrationBuilder.DropTable(
                name: "capture_interfaces");

            migrationBuilder.DropTable(
                name: "decrypted_requests");

            migrationBuilder.DropTable(
                name: "dns_records");

            migrationBuilder.DropTable(
                name: "flow_verdicts");

            migrationBuilder.DropTable(
                name: "ip_address_profiles");

            migrationBuilder.DropTable(
                name: "notification_deliveries");

            migrationBuilder.DropTable(
                name: "process_images");

            migrationBuilder.DropTable(
                name: "process_traffic_minutes");

            migrationBuilder.DropTable(
                name: "response_actions");

            migrationBuilder.DropTable(
                name: "sensor_statuses");

            migrationBuilder.DropTable(
                name: "settings");

            migrationBuilder.DropTable(
                name: "tls_sessions");

            migrationBuilder.DropTable(
                name: "traffic_hours");

            migrationBuilder.DropTable(
                name: "traffic_minutes");

            migrationBuilder.DropTable(
                name: "user_presences");

            migrationBuilder.DropTable(
                name: "users");
        }
    }
}
