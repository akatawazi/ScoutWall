using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace ScoutWall.Data.Migrations
{
    /// <summary>
    /// The views "Ask ScoutWall" may query (see ReadOnlyQuery). Only what is listed here is readable from chat;
    /// accounts, settings, chat history, pending changes, the audit log and decrypted requests have no view.
    /// Unix bucket times are turned into readable UTC times.
    /// </summary>
    public partial class ChatQueryViews : Migration
    {
        private static readonly (string Name, string Select)[] Views =
        [
            ("chat_program_traffic", """
                SELECT datetime(t.bucket_start, 'unixepoch') AS minute_utc, p.image_path AS program_path,
                       COALESCE(p.friendly_name, p.product_name, p.name) AS program_name, t.remote_ip, t.protocol,
                       t.bytes_sent, t.bytes_received,
                       CASE t.user_presence WHEN 0 THEN 'here' WHEN 1 THEN 'away' ELSE 'unknown' END AS presence
                FROM process_traffic_minutes t JOIN process_images p ON p.id = t.process_image_id
                """),
            ("chat_traffic_by_hour", """
                SELECT datetime(bucket_start, 'unixepoch') AS hour_utc, remote_ip, local_ip, service_port, protocol,
                       CASE direction WHEN 1 THEN 'inbound' WHEN 2 THEN 'outbound' WHEN 3 THEN 'internal' WHEN 4 THEN 'transit' ELSE 'unknown' END AS direction,
                       bytes_in, bytes_out, packets_in, packets_out, connection_count
                FROM traffic_hours
                """),
            ("chat_addresses", """
                SELECT ip_address, is_private, country_code, country_name, region, city, latitude, longitude, isp, organization,
                       autonomous_system_number, autonomous_system_organization, reverse_dns, is_blocklisted, blocklist_source,
                       first_seen_at, last_seen_at
                FROM ip_address_profiles
                """),
            ("chat_dns_names", "SELECT ip_address, hostname, record_type, first_seen_at, last_seen_at, seen_count FROM dns_records"),
            ("chat_tls_names", """
                SELECT server_ip AS ip_address, server_name AS hostname, server_port, tls_version, process_name,
                       first_seen_at, last_seen_at, connection_count
                FROM tls_sessions
                """),
            ("chat_programs", """
                SELECT id AS program_id, image_path AS program_path, COALESCE(friendly_name, product_name, name) AS program_name,
                       publisher, company, file_version, first_seen_at, last_seen_at
                FROM process_images
                """),
            ("chat_alerts", """
                SELECT id, created_at, last_seen_at, rule_name,
                       CASE severity WHEN 1 THEN 'low' WHEN 2 THEN 'medium' WHEN 3 THEN 'high' WHEN 4 THEN 'critical' END AS severity,
                       CASE status WHEN 1 THEN 'open' WHEN 2 THEN 'acknowledged' WHEN 3 THEN 'resolved' END AS status, title, description, source_ip, destination_ip,
                       destination_port, protocol, process_path, occurrence_count, scope, subject, resolved_at
                FROM alerts
                """),
            ("chat_blocks", """
                SELECT id, action_type, target, block_inbound, block_outbound, reason, alert_id, status, created_at, created_by,
                       expires_at, applied_at, removed_at, undone_at
                FROM response_actions
                """),
            ("chat_findings", """
                SELECT id, created_at, verdict, confidence, title, explanation, recommended_action, process_path, remote_ip,
                       destination, rule_name, alert_id, acknowledged
                FROM analyst_assessments
                """),
            ("chat_verdicts", """
                SELECT id, evaluated_at, provider, verdict, confidence, score, reasons, local_ip, remote_ip, service_port,
                       protocol, direction, process_path, hostname
                FROM flow_verdicts
                """),
            ("chat_system_events", """
                SELECT occurred_at, channel, event_id, level, provider, category, subject, program_path, remote_address,
                       summary, occurrence_count
                FROM system_events
                """),
            ("chat_services", """
                SELECT service_name, display_name, state, start_mode, binary_path, account, is_baseline, first_seen_at,
                       last_seen_at, last_changed_at, removed_at
                FROM system_services
                """),
            ("chat_scan_results", """
                SELECT scan_started_at, kind, name, target, program_path, command, signals, score, assistant_verdict,
                       assistant_reason, recommendation
                FROM scan_results
                """),
            ("chat_presence", """
                SELECT CASE state WHEN 0 THEN 'here' WHEN 1 THEN 'away' ELSE 'unknown' END AS presence,
                       started_at, COALESCE(ended_at, confirmed_at) AS ended_at, ended_at IS NULL AS still_going, source
                FROM presence_periods
                """),
            ("chat_program_resources", """
                SELECT datetime(r.bucket_start, 'unixepoch') AS period_start_utc, p.image_path AS program_path,
                       r.cpu_percent_average, r.cpu_percent_peak, r.memory_bytes_peak, r.private_bytes_peak, r.instance_count
                FROM process_resource_samples r JOIN process_images p ON p.id = r.process_image_id
                """),
            ("chat_system_resources", """
                SELECT datetime(bucket_start, 'unixepoch') AS minute_utc, cpu_percent, memory_used_bytes, memory_total_bytes, process_count
                FROM system_resource_minutes
                """)
        ];

        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            foreach (var (name, select) in Views)
            {
                migrationBuilder.Sql($"DROP VIEW IF EXISTS {name};");
                migrationBuilder.Sql($"CREATE VIEW {name} AS {select};");
            }
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            foreach (var (name, _) in Views)
                migrationBuilder.Sql($"DROP VIEW IF EXISTS {name};");
        }
    }
}
