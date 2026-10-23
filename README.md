<p align="center">
  <img src="ScoutWall/wwwroot/img/scoutwall-logo.webp" alt="ScoutWall, with Scout the laser-eyed guard dog" width="560">
</p>

<p align="center">
  <strong>Your computer's guard dog.</strong><br>
  See what leaves your computer, where it goes and which program sent it, and stop what shouldn't.
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#getting-started">Getting started</a> ·
  <a href="#features">Features</a> ·
  <a href="#safety-and-privacy">Safety and privacy</a> ·
  <a href="#build-from-source">Build from source</a>
</p>

---

ScoutWall watches your computer's network traffic and tells you, in plain language, what is going on: which programs
are sending data, how much, to which company and country, and whether it happened while you were away from the
keyboard. It can block programs and addresses, keeps an eye on what runs and changes on the computer, and has a
built-in assistant you can ask things like *"Did anything talk to a .gov site this week?"* or *"What uploaded data
last night?"*

Everything stays on your computer: one local database and a web console at **http://localhost:5215**. There is no
cloud account. The assistant is optional and only talks to an AI provider if you give it a key.

## Install

ScoutWall is one self-contained file per operating system; nothing else (not even .NET) needs installing.

### Windows 10 / 11 (x64)

Open **PowerShell as administrator** (right-click Start → *Terminal (Admin)*) and run:

```powershell
irm https://github.com/akatawazi/ScoutWall/releases/latest/download/install.ps1 | iex
```

### Linux (x86-64 with systemd)

```sh
curl -fsSL https://github.com/akatawazi/ScoutWall/releases/latest/download/install.sh | sudo sh
```

The script downloads the executable for that release, checks it against the release's SHA-256 checksums and
installs and starts ScoutWall. Then open http://localhost:5215.

### Install by hand, or while the repository is private

Download `scoutwall-win-x64.exe` (Windows) or `scoutwall-linux-x64` (Linux) and `SHA256SUMS` from the
[releases page](../../releases). With the GitHub CLI signed in to an account that can see the repository:

```powershell
# Windows, in an administrator PowerShell
gh release download --repo akatawazi/ScoutWall --pattern "scoutwall-win-x64.exe" --pattern SHA256SUMS
(Get-FileHash .\scoutwall-win-x64.exe -Algorithm SHA256).Hash   # compare with SHA256SUMS
.\scoutwall-win-x64.exe install
```

```sh
# Linux
gh release download --repo akatawazi/ScoutWall --pattern scoutwall-linux-x64 --pattern SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
chmod +x scoutwall-linux-x64 && sudo ./scoutwall-linux-x64 install
```

To **upgrade**, run `install` again with a newer executable; your data and settings are kept.
To **remove** ScoutWall: `scoutwall uninstall` (add `--delete-data` to delete the database too).

> The executables aren't code-signed yet, so Windows SmartScreen may warn the first time you run one.

## Getting started

1. **Open http://localhost:5215.** The first visit asks you to **create your account**; there is no default login.
2. **Answer four short questions:** which network connections to watch, what ScoutWall should do when it finds
   something bad (just tell you, block it, slow it down, or block only while you're away), and whether an AI
   assistant should review what it finds.
3. **Let it learn.** For the first day ScoutWall learns what's normal on your computer and stays quiet about
   ordinary activity. Automatic blocking starts in **practice mode**: you see what it *would* block before it does.
4. **Look for Scout in the notification area** (Windows). The tray agent tells ScoutWall when you're at the keyboard
   and pops up alerts.
5. **Explore.** Start with **Home** for today's summary, **Data Flow** to see where your data goes, and **Ask
   ScoutWall** to ask questions in plain words.

## Features

| | Windows | Linux |
|---|:---:|:---:|
| **Home**: today's status, what needs your attention and what was sent while you were away | ✅ | ✅ |
| **Ask ScoutWall**: questions in plain words, answered from your own data (site, country, program, time) | ✅ | ✅ |
| **Data Flow**: every program's uploads and downloads, split by whether you were there; world map, top countries, destinations with names and owners | ✅ | network only |
| **While you were away**: a timeline of when you were at the computer, and exactly what went where while you weren't | ✅ | — |
| **Alerts**: port scans, floods, threat-list contacts, exposed services, data leaks, suspicious Windows events, ransomware-style file renames; each with one-click actions | ✅ | network alerts |
| **Blocking**: block or slow down a program or address, block only while you're away, never-block allowlists, one-click undo, emergency rescue | ✅ | — |
| **Decoy ports** that catch scanners on your network | ✅ | ✅ |
| **System**: running programs and their CPU and memory, services, scheduled tasks, Windows logs; end or block a program; **scan this computer** for suspicious startup items | ✅ | — |
| **I/O**: drive activity and space, which files changed (your files vs. system files), and optionally which programs *read* your files | ✅ | — |
| **Analyst**: an AI reviewer that explains alerts and separates the real ones from noise (optional, bring your own key) | ✅ | ✅ |
| Notifications by email, webhook (Slack, Teams, Discord) and desktop | ✅ | email, webhook |
| Place, network owner and threat-list status of every address; DNS and TLS site names | ✅ | ✅ |

Packet capture works out of the box: ScoutWall uses [Npcap](https://npcap.com) if you have it (it adds promiscuous
and loopback capture) and Windows' built-in packet capture otherwise. On Linux it uses the system's libpcap.

## Safety and privacy

- **Practice mode first.** Automatic blocks are recorded, not applied, until you turn practice mode off.
- **It won't lock you out.** Your local network, gateway, DNS servers, Windows itself and ScoutWall are never blocked.
  Every block can be undone in one click, and `scoutwall rescue` (as administrator) removes every ScoutWall firewall
  rule even if ScoutWall itself is broken.
- **No spoofed blocks.** Scanners are blocked automatically only when they complete a real connection to a decoy
  port; anything that could come from a forged address is reported with a one-click block instead.
- **Your data stays home.** The database lives in `C:\ProgramData\ScoutWall` (Windows) or `/var/lib/scoutwall`
  (Linux), readable only by ScoutWall's services and administrators, and old records are deleted on a schedule you
  set. Nothing is sent anywhere unless you set up the assistant, notifications or an online location service.
- **Least privilege.** The web console runs under its own low-privilege account and listens on localhost only. On
  Linux nothing runs as root; the sensor gets only the network capabilities it needs.

### What installing changes

| | Windows | Linux |
|---|---|---|
| Program | `C:\Program Files\ScoutWall\scoutwall.exe` | `/opt/scoutwall/scoutwall` |
| Data | `C:\ProgramData\ScoutWall` | `/var/lib/scoutwall` |
| Services | **ScoutWall Web** (account `NT SERVICE\ScoutWall Web`), **ScoutWall Sensor** (LocalSystem) | `scoutwall-web`, `scoutwall-sensor` (account `scoutwall`) |
| Also | a boot task that clears leftover firewall rules; the tray agent at sign-in | — |

Turning on read tracking (I/O page) additionally switches on Windows file auditing for your folders and enlarges the
Security log; turning it off, uninstalling or `scoutwall rescue` puts both back.

## Commands

```
scoutwall install      install or upgrade (administrator / root); --port 5215, --no-start
scoutwall uninstall    remove; --delete-data also deletes the database
scoutwall rescue       remove every ScoutWall firewall rule and undo audit changes (administrator)
scoutwall version      show the version
```

## Build from source

Needs the [.NET 10 SDK](https://dotnet.microsoft.com/download). In Visual Studio, open `ScoutWall.slnx`, set
**ScoutWall** as the startup project, pick the **net10.0-windows** framework and the **Web console** profile (or
**Web + Sensor (made-up traffic)**).

```sh
dotnet build ScoutWall.slnx
dotnet run --project ScoutWall --framework net10.0-windows                       # web console
dotnet run --project ScoutWall --framework net10.0-windows -- sensor --Sensor:CaptureMode=Synthetic
```

Single-file executables:

```sh
dotnet publish ScoutWall -c Release -f net10.0-windows -r win-x64 -p:PublishSingleFile=true -o artifacts/win-x64
dotnet publish ScoutWall -c Release -f net10.0 -r linux-x64 -p:PublishSingleFile=true -o artifacts/linux-x64
```

| Project | Purpose |
|---|---|
| `ScoutWall` | The `scoutwall` executable: web console, command dispatcher and installer. |
| `ScoutWall.Sensor` | Capture, detection, enrichment, verdicts, notifications, firewall responses, system and I/O monitoring. |
| `ScoutWall.Data` | Database, models and their logic, migrations, the assistant's safe query layer. |
| `ScoutWall.Intelligence` | The analyst and the Ask ScoutWall assistant. |
| `ScoutWall.Presence` | The Windows tray agent (idle detection and desktop notifications). |

See [CONTRIBUTING.md](CONTRIBUTING.md) to contribute and [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

ScoutWall is released under the [MIT License](LICENSE), © 2026 Blue Shift Technologies. Scout and the ScoutWall
logo are part of the project. Third-party components and their licenses are listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
