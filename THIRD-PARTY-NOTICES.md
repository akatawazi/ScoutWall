# Third-party notices

ScoutWall is MIT-licensed. It includes or uses the following components under their own licenses. The full license
texts are included in each package or linked below.

## Bundled in the executable

| Component | License | Source |
|---|---|---|
| .NET runtime, ASP.NET Core, Entity Framework Core, Microsoft.Extensions.* | MIT | https://github.com/dotnet |
| Microsoft.Data.Sqlite / SQLitePCLRaw / SQLite | MIT / Apache-2.0 / public domain | https://github.com/ericsink/SQLitePCL.raw, https://sqlite.org |
| Microsoft.Diagnostics.Tracing.TraceEvent | MIT | https://github.com/microsoft/perfview |
| SharpPcap | MIT | https://github.com/dotpcap/sharppcap |
| PacketDotNet | MPL-2.0 | https://github.com/dotpcap/packetnet |
| MaxMind.GeoIP2, MaxMind.Db | Apache-2.0 | https://github.com/maxmind/GeoIP2-dotnet |
| MailKit, MimeKit | MIT | https://github.com/jstedfast/MailKit |
| Anthropic .NET SDK | Apache-2.0 | https://github.com/anthropics/anthropic-sdk-csharp |
| Bootstrap | MIT | https://getbootstrap.com |
| jQuery, jQuery Validation, jQuery Validation Unobtrusive | MIT | https://jquery.com, https://jqueryvalidation.org, https://github.com/aspnet/jquery-validation-unobtrusive |
| Chart.js | MIT | https://www.chartjs.org |
| Inter typeface | SIL Open Font License 1.1 | https://rsms.me/inter |
| Assistant typeface | SIL Open Font License 1.1 | https://fonts.google.com/specimen/Assistant |
| World map (derived from Natural Earth) | Public domain | https://www.naturalearthdata.com |

PacketDotNet is used unmodified under the Mozilla Public License 2.0; its source is available at the link above.

## Downloaded by ScoutWall at run time

| Component | License | Source |
|---|---|---|
| DB-IP Lite databases (city and ASN): the default location and network-owner data, downloaded monthly into the data folder | Creative Commons Attribution 4.0; credited as "IP geolocation by DB-IP" wherever locations are shown | https://db-ip.com |

## Not bundled: installed or downloaded by you

These are never shipped with ScoutWall. Their own licenses apply when you choose to use them.

| Component | Notes |
|---|---|
| Npcap (https://npcap.com) | Optional faster capture on Windows. Free for personal use on up to five systems; redistribution needs an Npcap OEM license, so ScoutWall never bundles or downloads it. |
| libpcap (https://www.tcpdump.org) | BSD license; installed from your Linux distribution. |
| MaxMind GeoLite2 databases | Optional; used instead of DB-IP when you set them in Settings. You download them yourself under MaxMind's GeoLite2 EULA. |
| ip-api.com | Optional location lookups, off by default. Its free service is for non-commercial use only. |
| Threat blocklists | Defaults to the abuse.ch Feodo Tracker list (CC0). Add others only if their terms allow your use. |
| Wireshark / tshark | Optional, for decrypting your own TLS traffic; GPL-2.0, installed separately. |
