# EagleEye Agent 2 (pipeline agent)

The EagleEye agent, as a Windows desktop app (`EagleEyeAgent.exe`) and a command line (`eagleeye`): network
discovery and fingerprinting, passive sniffing and upload to the API, as a pipeline of stages
that report progress, plus an **endpoint inventory** of the machine it runs on (hardware, OS, patches, security
posture, interfaces, listening services, installed software) and, from 2.1.0, its **SBOM**: the software
packages found by Syft, checked for known CVEs by Grype, daily and when the dashboard asks.

It replaces the original 1.x agent (`eagleeye_agent.py` and its `bridge.py` relay), which was retired in
version 2.0.2: the server revoked the 1.x keys and the code was removed (it remains in git history under the
`legacy-archive` tag).

**Connecting:** the dashboard's Agents page gives a **connection code** (one string holding the API URL, agent ID
and API key). Paste it into Settings > Connection code > **Use code**, or pass `--connection-code <code>` to
`eagleeye config init` / `eagleeye run`.

## Requirements
- Python 3.12 or newer
- Optional: Nmap, and Npcap (Windows) / libpcap (macOS). They are **not** bundled (their licences restrict
  redistribution). `check-deps` tells you what is missing and where to get it. Without Nmap, scans use the agent's
  own engine (`scan_engine`) or a built-in sweep.
- Passive listening needs Administrator/root but no capture library: the built-in capture reads Microsoft's own
  NDIS capture driver on Windows and a packet socket (with a kernel filter) on Linux, and decodes the frames itself.
  `passive_backend` (`--capture`): `auto` (Npcap when it is installed **and** scapy is available, else built in),
  `npcap` (the original scapy + Npcap/libpcap sniffers) or `native`. `eagleeye listen --compare` runs both side by
  side. The packaged agent is built without scapy (set `EAGLEEYE_WITH_SCAPY=1` for the old build), so it uses the
  built-in capture.
- For the SBOM: [Syft](https://github.com/anchore/syft) and [Grype](https://github.com/anchore/grype), also not
  bundled (`winget install Anchore.Syft` and `winget install Anchore.Grype` on Windows). Without both, the daily
  SBOM is skipped and a dashboard request fails with that reason. Grype downloads its vulnerability database on
  its first run (a few minutes) and keeps it locally (about 3 GB).

```powershell
cd agent-gui
python -m pip install -r requirements.txt
python -m eagleeye check-deps
```

## Commands
| Command | What it does |
|---|---|
| `python -m eagleeye check-deps` | Reports Nmap, Npcap/libpcap, Python modules and privileges |
| `python -m eagleeye scan 192.168.1.0/24` | Scans once, locally, prints the hosts. Nothing is uploaded. `--json out.json` saves the exact ingest payload |
| `python -m eagleeye listen --seconds 60` | Listens passively (needs Administrator/root) and prints what it saw |
| `python -m eagleeye inventory` | Collects this machine's endpoint inventory and prints a summary. Nothing is uploaded. `--json out.json` saves the full document |
| `python -m eagleeye sbom` | Builds this machine's SBOM (Syft), checks it (Grype) and prints the worst findings. Nothing is uploaded. `--json out.json` saves the SBOM and findings; `--sbom-extra-paths "D:\Apps;E:\Tools"` adds folders |
| `python -m eagleeye config init ...` | Writes the config file |
| `python -m eagleeye config show` | Prints the effective settings, secrets masked |
| `python -m eagleeye run` | The agent: heartbeat, poll the dashboard, run scans, upload results |
| `python -m eagleeye gui` | The desktop app (needs PySide6) |
| `python -m eagleeye netpoll --seed IP --allow RANGE` | The network agent, once: crawls routers and switches over SNMP and prints devices, links, addresses and where each device is plugged in. Nothing is uploaded. See [Network agent](#network-agent-netpoll) |

## Settings
Precedence: config file < `EAGLEEYE_*` environment variables < command-line flags. The variable names are the
same as the original agent's. Config file: `%APPDATA%\EagleEye\config.json` on Windows,
`~/Library/Application Support/EagleEye/config.json` on macOS, `~/.config/eagleeye/config.json` on Linux
(override with `EAGLEEYE_CONFIG`). Secrets (API key, SNMP and Fingerbank keys) are saved in the OS credential store
(Windows Credential Manager: "EagleEye Agent" entries named `<agent id>/api_key` and so on, so two agents or two
config files never share a key) by both the app and `config init`; the file then holds blanks
and `"secrets_in_keychain": true`. Where no credential store is available they stay in the file. A config written by an
older version keeps working; its secrets move to the credential store the next time it is saved.

**Two agents on one PC** (e.g. staging and production): give each its own config file and start it with
`EAGLEEYE_CONFIG`. A file named `config-<name>.json` makes the instance `<name>`, with its own window (title
"EagleEye Agent 2.2.1 (production)"), schedule state (`state-<name>.json`) and logs (`logs-<name>`), so both can run at
the same time. In PowerShell, quote the path and start it with `&`:

```powershell
$env:EAGLEEYE_CONFIG = "$env:APPDATA\EagleEye\config-production.json"
& "C:\Program Files\EagleEye Agent\EagleEyeAgent.exe"        # the desktop app
& "C:\Program Files\EagleEye Agent\eagleeye.exe" run          # or without a window
```

## Endpoint inventory
While `run` is active the agent collects the inventory of its own machine on the first poll and then every
`inventory_interval` seconds (default 6 hours), and posts it to `POST /agents/:id/inventory`. The server matches it
to the machine's asset (previous binding, then hardware UUID, then MachineGuid, then a physical-NIC MAC, then a unique
hostname, then a unique IP held by an asset with no MAC) or creates a new asset in Discovered. A candidate whose recorded
hardware UUID differs is never matched (a cloned VM keeps its MachineGuid, name and often its MACs, but not its
hardware UUID); such pairs show up under Duplicates for review. The server stores the facts and the machine
identifiers (`asset_identifiers`), moves the asset's address with the machine, marks its device type "confirmed by
agent" (a type set by hand is kept), recomputes criticality and syncs the software list. A network scan that sees
any NIC the agent listed (for example the Ethernet MAC of a laptop first seen on Wi-Fi) updates the same asset.

| Section | Source on Windows | Used in the system |
|---|---|---|
| Identity (hostname, domain, MachineGuid, SMBIOS UUID, serial) | registry, CIM | binding to the right asset, scan matching and duplicate detection (placeholder UUIDs ignored; serial shown only) |
| Hardware (model, form factor, CPU, RAM, disks, BIOS) | CIM, Storage module | asset detail; later: device-type classification |
| OS and patches (build, role, last update, pending restart) | CIM, Get-HotFix, registry | asset detail; later: criticality and posture |
| Security posture (firewall, antivirus, BitLocker, Secure Boot, TPM, UAC, RDP, SMBv1, local admins) | NetSecurity, Defender, SecurityCenter2, registry | asset detail; later: posture score and alerts |
| Interfaces and listening services (with process) | NetAdapter, NetTCPIP | binding (MACs); asset detail |
| Installed software | Uninstall registry keys (machine and user) | `asset_software` table, asset detail; later: CVE matching and drift |

BitLocker, TPM and SMBv1 need Administrator; without it they are reported as "needs Administrator". Settings:
`inventory` (on/off, `--no-inventory`) and `inventory_interval` (`--inventory-interval`, minimum 300 s).

**Linux** (`collectors/linux.py`) reports the same document from `/etc/os-release`, `/proc`, `/sys/class/dmi/id`,
`/etc/machine-id`, `ip -j addr`, `ss -tulnp`, `lsblk`, `dpkg-query` / `rpm` and `snap`: patches from the apt or dnf
history, firewall from ufw / firewalld / nftables, disk encryption from LUKS layers under `/`, `/home`, `/var`, `/srv`,
Secure Boot, TPM, xrdp, Samba SMBv1 and members of the sudo / wheel / admin groups. The SMBIOS UUID and serial need
root; run the agent with `sudo` (or as a root systemd service), otherwise they are reported as unavailable and the
server's VM-clone guard cannot use them. A machine without a desktop session reports the role "server".

**macOS** (`collectors/macos.py`) reports it from `system_profiler` (hardware, storage, apps with their code-signing
publisher), `sw_vers`, `ioreg` (hardware UUID and serial), `sysctl`, `scutil`, `dsconfigad`, `ifconfig` +
`networksetup`, `lsof` and Homebrew's Cellar: macOS updates from `/Library/Receipts/InstallHistory.plist` (only macOS
and security updates count, not the XProtect/MRT data files), FileVault (`fdesetup`), the application firewall
(`socketfilterfw`), XProtect (fresh when its data is under 45 days old) and other protection found by its app, Screen
Sharing / Remote Desktop listening, and the admin group (`dscl`). Secure Boot, the Secure Enclave, UAC and SMBv1 have
no readable equivalent and are reported as unknown (left out of the score). Apps under `/System` are macOS's own and
left out; apps in a user's folder only with `user_software`. Tested against recorded output
(`tests/test_macos_inventory.py`), not yet on a real Mac.

## Desktop app
`python -m eagleeye gui`, or `EagleEyeAgent.exe` from the installer. One copy runs per user; it keeps running in the
system tray when the window is closed (right-click the tray icon to quit).

It uses the dashboard's design (the repository's `DESIGN.md`): a navy rail with the logo and the pages in two groups
(Agent: Status, Log; Setup: Settings, Privacy, Dependencies), a header with the agent's live state, **Start/Stop** and a
dark / light / system theme switch (saved per Windows user; system follows the Windows app theme). The look lives in
`gui/theme.py` (colour tokens, stylesheet) and `gui/widgets.py` (rail, panels, circuit trace); the logo, the fonts
(Chakra Petch, Geist, Geist Mono; SIL OFL) are in `gui/assets/`, and the icons are Lucide's (`gui/icons.py`).

| Page | What it does |
|---|---|
| (first start) | Shows the data-collection notice with the choices below; the agent does not run until it is accepted. The acceptance date and notice version are saved (`consent_version`, `consent_at`); a new notice version is shown again |
| Status | Connection, last heartbeat, where passive listening listens (or why it is waiting), whether scans from this computer are allowed, what is running now, **Scan now** for a network, **Collect inventory now**, **Build SBOM now**, recent activity (with who started each run: dashboard, this computer, automatic, or "New device found") |
| Settings | Server URL, agent ID, API key (with **Test connection**), timing, active scanning, passive listening. Saving restarts the agent; saving new server details starts it |
| Privacy | Inventory on/off, interval, the two personal-data options, **Preview what would be sent** (collects and shows the inventory without sending it), SBOM on/off and extra folders, the notice |
| Dependencies | Nmap, Npcap, Python modules and Administrator rights; download buttons for Nmap and Npcap; **Restart as Administrator** |
| Log | Live log; also written to `%APPDATA%\EagleEye\logs\agent.log` (rotated, 5 x 1 MB) |

**Scan now.** Scans started on the machine ask the server for a scan record first (`POST /scans/agent-start`), so they
appear in the dashboard and upload exactly like dashboard scans. When the agent starts it calls `POST /scans/agent-reset`,
and the server marks any of its active scans still "running" from an earlier run (app closed or crashed mid-scan) as failed,
"Interrupted". A tenant's admin can turn scans started on agent computers off (dashboard Agents page > Scan Policy; off
by default for new tenants). Every heartbeat answer carries that policy (`policy.local_scans`): while it is off, **Scan
now** is greyed out with the reason, the Status page says so, schedules pause (they are not marked as run), and the
server refuses `agent-start` anyway for older agents. Scans the dashboard asks for always run. The buttons are
unavailable while that kind of run is busy, so repeated clicks start one run.

**What the dashboard can ask for.** The agent polls `GET /scans/pending` every poll interval and runs, one of each
kind at a time:
| Job | Started by | What the agent does |
|---|---|---|
| active scan | **New scan** on the dashboard | Nmap (or the built-in sweep) on the range, upload |
| active scan of one IP | the server, when passive listening heard a device for the first time and the tenant turned on **Investigate new devices automatically** | the same scan on that address only, a few minutes later; the server puts the open ports and OS guess on the device's new-device alert; recent activity shows "New device found" |
| inventory | **Collect inventory** on the asset page | collects and uploads this computer's inventory now; any inventory upload completes the job |
| SBOM | **Run SBOM scan** on the asset or SBOM page | a full SBOM run |

An automatic inventory that fails (typically at start-up, before Wi-Fi is up) is tried again after 5 minutes, then
10, 20... up to an hour, until one succeeds.

**Local schedules (switched off for now).** `schedule.py` can scan a network daily at a set time or every N hours, with
missed runs collapsed into one. Editing schedules crashed the desktop app under PySide6 6.12, so `SCHEDULES_ENABLED` in
`service.py` is `False`: the Schedules page is hidden and saved schedules are ignored. The logic stays covered by tests
so it can be switched back on once decided.

**Getting Nmap and Npcap.** They are not shipped (licences). On the Dependencies page the agent reads the official download
page (nmap.org, npcap.com), downloads the newest installer over HTTPS from that site only, checks its Authenticode signature
(must be valid and signed by Nmap Software LLC; tampered or unsigned files are refused), and opens it with the normal
Windows elevation prompt. You go through the official installer and accept its licence yourself.

## Privacy and data protection
The endpoint inventory describes the machine the agent is installed on. On an organisation-owned device that is
normal asset-management data; on a device a person uses, parts of it identify that person, which makes it personal
data under Malaysia's Personal Data Protection Act 2010. The agent is built to collect only what security needs.

**Collected:** hardware model and serial number, OS version and patches, security settings (firewall,
antivirus, encryption, Secure Boot, TPM, UAC, RDP, SMBv1), the **number** of local administrator accounts (never
their names), network interfaces and their addresses, network-reachable listening ports with the program behind
them, and the installed software: what is installed for all users and what each signed-in user installed for
themselves (on Windows every loaded user hive under `HKEY_USERS`; browser web-app shortcuts are skipped), because
out-of-date per-user programs (browsers, editors, chat apps) are a common way in. The dashboard's only inventory
settings for a computer are whether it reports one and how often.

**Never collected:** files or documents, browsing history, passwords or credentials, keystrokes, screenshots, email
or messages, location, and the contents of network traffic. For ports that only listen on the machine itself
(`127.0.0.1` / `::1`), which program owns them is not sent. Passive mode reads only broadcast discovery packets
(ARP, mDNS, NetBIOS, DHCP, SSDP/UPnP) to learn device names and addresses, and ignores the computer's own packets.

**Which network passive mode listens on:** with the interface left empty ("automatic"), the adapter the operating
system uses to reach the internet, re-checked every 30 seconds (so it follows Wi-Fi connecting after sign-in, a
switch to a cable, or a VPN, and never sits on a virtual adapter such as a GNS3/VMware loopback). The Status page
shows the choice, e.g. "Wi-Fi (192.168.1.20)", or why it is waiting: no route yet (Wi-Fi not connected), a route
through an address no adapter has, or Windows routing through a virtual adapter. With no route to the internet at
all (an isolated lab or OT network), the one real adapter that has an address is used; with several, it waits. Virtual means the *host's*
adapters for virtual machines and tunnels (KM-TEST loopback, VMware VMnet, Hyper-V vEthernet, VirtualBox host-only,
WSL, Docker); inside a VM its own card (e.g. "Microsoft Hyper-V Network Adapter") is its real network. A name typed
in Settings is used as it is. The same rule picks the computer's own address in the inventory (Windows and Linux):
never one on a virtual adapter, which before Wi-Fi was up once moved a laptop to its GNS3 loopback address.

**Notice and choice:** the desktop app shows this notice before the agent first runs, with the personal-data options
off, and the choices can be changed at any time on the Privacy page.

**Transparency:** the Privacy page's **Preview**, or `python -m eagleeye inventory`, shows exactly what would be sent, without sending it
(`--json file` saves the full document for review).

**Where it goes and for how long:** over HTTPS to the organisation's own EagleEye server only (no third parties),
stored with the matching asset in that organisation's tenant and visible only to its users. Only the latest
inventory is kept: each run replaces the previous one, and software that is uninstalled disappears at the next run.

**Removal:** an administrator can press **Clear inventory** on the asset page (recorded in the audit log), or delete
the asset. To stop collection on a machine, run the agent with `--no-inventory` or stop it; otherwise it sends a
new inventory at its next run.

## Running as a service (Windows, Linux and macOS)
Since 2.5.0 the agent runs as a system service: it starts with the computer, before anyone signs in, keeps
running when the desktop app is closed, and restarts after a crash. The desktop app is only its window: it shows
the service's state (over a local named pipe / Unix socket) and changes its settings after an administrator prompt.

| | Windows | Linux | macOS |
|---|---|---|---|
| Service | `EagleEye Agent` (LocalSystem, delayed automatic start) | systemd unit `eagleeye-agent` (root) | launchd daemon `com.umeagleeye.agent` (root) |
| Settings, state, logs | `%ProgramData%\EagleEye` (Users may read; only administrators change) | `/var/lib/eagleeye` | `/Library/Application Support/EagleEye` |
| Secrets | `secrets.dat`, DPAPI machine key, SYSTEM + Administrators only | `secrets.json`, mode 600 | `secrets.json`, mode 600 |

On a Mac, `packaging/macos/install-macos.sh` (in the source package) does it all: it finds Python 3.12+ (python.org
or Homebrew; macOS's own `python3` is too old), puts the agent in `/usr/local/eagleeye` with its own environment
(keyring, truststore, scapy, PySide6 unless `--no-gui`), adds the `eagleeye` command, connects it
(`--code-file`) and registers the daemon:
```bash
sudo bash packaging/macos/install-macos.sh eagleeye-agent-<version>.tar.gz --code-file ~/code.txt
eagleeye gui                                      # its window; settings changes ask for the administrator password
sudo bash packaging/macos/install-macos.sh --uninstall --purge
```
The daemon restarts after a crash (not after `eagleeye service stop`). Passive listening uses libpcap, which comes
with macOS; Syft, Grype and Nmap are found in Homebrew's folders (`brew install syft grype nmap`).

The Windows installer sets it up. By hand, as an administrator (Windows: an elevated PowerShell; Linux: sudo,
from the agent's folder):
```
eagleeye service install [--from-config <file>]   # moves this user's settings (and Credential Manager key) in, starts it
eagleeye service status                           # works for any user
eagleeye service stop | start
eagleeye service uninstall [--purge]              # --purge also deletes its settings, state and logs
```
From source use `python -m eagleeye ...` (on Linux `sudo .venv/bin/python -m eagleeye ...`). On Linux, `install`
replaces the hand-installed `eagleeye.service` of earlier versions (disabled; its file is kept) and moves root's
settings (`/root/.config/eagleeye/config.json`) in. Windows: `Stop-Service "EagleEye Agent"` / `Set-Service ...
-StartupType Disabled`; Linux: `systemctl stop|disable eagleeye-agent`, log: `journalctl -u eagleeye-agent` and
`/var/lib/eagleeye/logs/agent.log`. Closing the desktop app never stops the agent.

Without a service (development, or `EAGLEEYE_EMBEDDED=1`) the desktop app runs the agent itself, as before 2.5.0.

On Windows the service runs as LocalSystem, so Syft and Grype installed for one user (plain `winget install`, a download in your own folders) are invisible to it. Put `syft.exe` in `C:\Program Files\syft\` and `grype.exe` in `C:\Program Files\grype\`, or `winget install --scope machine Anchore.Syft` (and `Anchore.Grype`) as an administrator. The window's Setup page shows what the service finds, and the dashboard warns when SBOM is on without them. Grype's vulnerability database (about 3 GB) is kept in the agent's machine folder, `grype-db` (`C:\ProgramData\EagleEye\grype-db`, `/var/lib/eagleeye/grype-db`); `service uninstall --purge` removes it with the rest.

On Linux the tools come from the distribution: `sudo apt install nmap` (passive listening needs no libpcap), and
Syft + Grype for SBOMs:
```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
```
Grype's vulnerability database needs about 6 GB free on `/` (3.3 GB unpacked, plus room to update it).

## Installing on many computers (Intune, Group Policy, scripts)
A connection code belongs to one agent: every computer installed with it would be that same agent. For many
computers, make an **install code** on the dashboard (Agents → Install codes: valid 1–90 days, optionally for at
most N computers). Each computer exchanges it once, at `POST /enrolment/enrol`, for an agent of its own, named
after the computer. Only the code's SHA-256 is stored; withdrawing it stops new installs, not the agents it made.

```powershell
# Intune (Win32 app) or a script: silent, connected at once, no tray app
EagleEyeAgent-Setup-<version>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MERGETASKS="!autostart" /CONNECTIONCODE=EE2...
# Group Policy startup script: the code in a file on a share, so it is not on the command line
EagleEyeAgent-Setup-<version>.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /CONNECTIONCODEFILE=\\server\share\eagleeye-code.txt
```
- **Exit code 10:** installed, but it could not register (an expired, withdrawn or used-up code, or no connection
  to the server); add `/LOG="C:\Windows\Temp\eagleeye-setup.log"` to see why. 0 = installed and connected.
- **Intune detection rule:** the service `EagleEyeAgent` exists (or the file
  `%ProgramFiles%\EagleEye Agent\eagleeye.exe`). Uninstall: `"%ProgramFiles%\EagleEye Agent\unins000.exe" /VERYSILENT`.
- **Reinstalls and upgrades** keep the agent the computer already has (same server: its saved ID and key are
  reused), so the code can stay in the deployment.
- **By hand / Linux:** `eagleeye service enrol --connection-code-file code.txt` (as administrator / root) connects
  an installed service with either kind of code; `eagleeye config init --connection-code EE2...` and
  `eagleeye run` accept an install code too (a container registers once and keeps its agent in `/data`).
  `EAGLEEYE_AGENT_NAME` names the new agent instead of the computer name.

## Network agent
The network agent reads the routers and switches instead of looking after one computer: from their ARP
tables, MAC tables and CDP/LLDP neighbours it finds every device on the network and the switch port it is
plugged into, and sends that to the dashboard (Inventory, Discovery, the asset page's "Plugged into" and
"Network device"). A company runs one per site or management network, always on, next to the network
equipment. It needs UDP 161 to the devices and HTTPS out to the EagleEye server; nothing connects to it.

**1. On the network equipment (once, by the network team):** a read-only SNMPv3 user (authPriv: SHA or
SHA-2 with AES-128), allowed only from the agent's address. Cisco IOS:
```
ip access-list standard EAGLEEYE-SNMP
 permit host <agent address>
snmp-server view EAGLEEYE-RO iso included
snmp-server group EAGLEEYE-RO v3 priv read EAGLEEYE-RO access EAGLEEYE-SNMP
snmp-server user eagleeye EAGLEEYE-RO v3 auth sha <auth password> priv aes 128 <priv password>
```
SNMPv2c with a read-only community also works (`--snmp-version 2c`), but sends the community in clear text.

**2. On the dashboard:** Agents → Register agent → copy the connection code.

**3. Install it, either way:**
- Docker (any Linux host; build from `agent-gui/`; passwords as files, never in the environment):
  ```bash
  docker build -f packaging/network-agent/Dockerfile -t eagleeye-network-agent .
  # one file each: connection_code, snmp_auth, snmp_priv; readable only by the container's user (uid 10001)
  sudo install -d -m 700 -o 10001 /etc/eagleeye/secrets
  sudo chown 10001 /etc/eagleeye/secrets/* && sudo chmod 600 /etc/eagleeye/secrets/*
  docker run -d --name eagleeye-network-agent --restart unless-stopped \
    -e EAGLEEYE_CONNECTION_CODE_FILE=/run/secrets/connection_code -e EAGLEEYE_SNMP_USER=eagleeye \
    -e EAGLEEYE_SNMP_AUTH_KEY_FILE=/run/secrets/snmp_auth -e EAGLEEYE_SNMP_PRIV_KEY_FILE=/run/secrets/snmp_priv \
    -v /etc/eagleeye/secrets:/run/secrets:ro -v eagleeye-netagent:/data eagleeye-network-agent
  docker logs -f eagleeye-network-agent             # health: docker ps shows (healthy)
  ```
  The image holds only the agent, `cryptography` and `truststore` (`packaging/network-agent`), runs as an
  ordinary user, and keeps its state in the `/data` volume.
- A Linux service (systemd, as root; `pip install cryptography` first):
  ```bash
  sudo python3 -m eagleeye config init --config /root/netagent.json --connection-code <code> \
      --kind network --snmp-user eagleeye             # asks for the SNMP passwords
  sudo python3 -m eagleeye service install --from-config /root/netagent.json
  ```

**4. On the dashboard again:** the agent shows as a Network agent with the Collector role. In its Settings,
set **Start from** (the core routers/switches), **Allowed ranges** and the hops; it reads the network every
15 minutes, and **Run now** (the play button) reads it at once. The same can be given at install time with
`--network-seed` / `--network-range`, or `EAGLEEYE_NETWORK_SEEDS` / `_RANGES` (comma-separated).

### One crawl by hand (`netpoll`)
Reads routers and switches over SNMP (read only) with our own client (`eagleeye/netagent/`): v2c, or v3 with
MD5/SHA/SHA-2 authentication and AES-128 privacy (`pip install cryptography`, the `network` extra). From the seed
devices it follows CDP/LLDP neighbours, polling only addresses inside `--allow` ranges, at most `--depth` hops (3).

```bash
export EAGLEEYE_SNMP_USER=eagleeye        # passwords: EAGLEEYE_SNMP_AUTH_KEY / _PRIV_KEY, --credentials FILE, or a prompt
python3 -m eagleeye netpoll --seed 10.99.0.1 --allow 10.10.0.0/16 --allow 10.99.0.0/24 \
    --record lab-snmp/ --truth gns3-truth.csv --links gns3-links.csv --json netpoll.json
```
Per device it reads the system group, interfaces (name, description, MAC, state), addresses, ARP, routes,
CDP and LLDP, and on switches the MAC table (Q-BRIDGE, or Cisco's one table per VLAN), trunk state and access
VLANs. It then reports:
- **links**: one per cable, seen from one or both ends;
- **addresses**: every IP and MAC in the routers' ARP tables, with the VLAN, marking the polled devices' own;
- **locations**: the switch port a device is plugged into, from edge ports only (trunks and ports with a
  CDP/LLDP neighbour carry many MACs).

`--record DIR` keeps every answer as net-snmp text, one file per device; `--replay DIR` runs on them without a
network (`tests/fixtures/gns3` is the GNS3 lab). `--upload --config FILE` also sends the crawl to the server
in that file, through the same code the service runs. Passwords are never accepted on the command line.

## Testing against the staging environment
Use a fresh test tenant, never production.

```powershell
cd agent-gui
python -m eagleeye config init `
  --api-url https://umeagleeye-api-staging.syntaxch404.workers.dev/api/v1 `
  --agent-id <agent id from the staging Agents page> `
  --api-key  <api key shown once when the agent was registered>
python -m eagleeye config show
python -m eagleeye run          # add --passive in an Administrator terminal for passive mode
```
Then, in the staging dashboard, open Discovery or Agents and start a scan for this agent. The agent picks it up
within one poll interval (30 s by default).

## Building the Windows package
```powershell
cd agent-gui
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt pyinstaller
.\packaging\build.ps1
```
Produces `dist\EagleEyeAgent\` (`EagleEyeAgent.exe` and `eagleeye.exe`, one folder, about 130 MB) and, if Inno Setup 6
is installed, `dist\EagleEyeAgent-Setup-<version>.exe`. The installer can add a sign-in task that starts the agent with
Administrator rights (needed for passive listening and the BitLocker/TPM/SMBv1 checks) without a prompt each time.
`packaging/THIRD-PARTY-NOTICES.txt` lists the bundled components and their licences.

The Linux and network-agent download is the source package: `python packaging/make_source.py` writes
`dist/eagleeye-agent-<version>.tar.gz` (the package, `pyproject.toml`, this README, the systemd unit and the Docker
files; no tests). AGENT_SETUP_GUIDE.md, "Publishing a new version", uploads both for the dashboard's Install tab.

## Layout
```
eagleeye/
  cli.py, service.py, config.py, api.py, deps.py, netinfo.py
  keychain.py, schedule.py, installers.py, privacy.py
  gui/        desktop app: app (window, tray, single instance), pages, consent, controller
  pipeline/   HostRecord, events, runner (stages, optional stages, cancellation)
  stages/     scan_nmap (Nmap + built-in fallback), scan_own, passive, inventory, sbom, upload
  collectors/ endpoint inventory: windows_inventory.ps1 + windows.py normaliser; linux.py
  passive/    ARP, mDNS/NetBIOS and DHCP sniffers
  netagent/   the network agent: own SNMP client, one device's tables, CDP/LLDP crawl, ground-truth scoring
packaging/    PyInstaller spec, Inno Setup script, build.ps1, third-party notices, eagleeye.service (systemd)
tests/        pytest suite (recorded Nmap XML, packets built with scapy, fake systems for the collectors)
```

## Tests
```powershell
python -m pytest -q
```
`tests/test_gui.py` runs the desktop app without a display (Qt offscreen) and is skipped when PySide6 is not installed.
Until the original agent was retired (2.0.2), a parity test compared both agents' host data on recorded Nmap output;
they matched, so the Nmap parser tests in `tests/test_scan.py` now carry that guarantee.

## Behaviour changes from the original agent
- Scan targets must be an IPv4 address or CIDR range (what the dashboard already requires) and no larger than a /16.
  The value reaches the Nmap command line, so anything else is rejected before Nmap runs.
- A missing Nmap is reported and handled by the built-in sweep, instead of failing the scan.
- SBOMs describe only the agent's own computer: the folders come from its settings, never from the dashboard
  (the old agent accepted any Syft target, and defaulted to a fixed project folder on Windows). Grype's GHSA
  matches are reported with their CVE ID. Unsupported scan types are declined.
- Syft's readers for compiled programs (Go binaries, Windows .exe/.dll, Linux kernel images) are off by default
  (`sbom_include_binaries`, Privacy page > "Include compiled programs", `--sbom-include-binaries`). On a test PC
  they produced about 90% of the findings, almost all Go standard-library CVEs in Docker Desktop and WSL kernel
  matches that only those vendors can fix. Grype gets 20 minutes.
- Program Files, Program Files (x86) and ProgramData are scanned one program folder at a time (two at once),
  so one huge or unreadable folder costs only itself. Windows' own folders (WindowsApps, Windows Defender,
  ProgramData\Microsoft, Package Cache...) and links/junctions are not scanned. Ctrl+C or Cancel on the dashboard
  stops Syft/Grype within seconds.
- SBOM runs learn and adapt (2.2.6). A **full run** (the first, once a week, and every "Build SBOM now" or
  dashboard request) lists every folder and remembers per folder its packages, a fingerprint (files, size,
  newest change), how long Syft took and the limit it needs (twice that, from 10 up to 60 minutes; doubled after
  a timeout). A **daily run** fingerprints every folder and lists only those that changed, reusing the rest, so
  it takes minutes instead of the full run's 10-30. Grype always checks every package, so new CVEs in unchanged
  folders are still found. A folder that is not listed (timed out, failed, or out of time) keeps the packages of
  its last listing, so its CVE alerts stay open; the upload names such folders. Limits count awake time only:
  45 minutes for a daily run, 90 for a full one. What was learned is in `sbom-cache.json` next to the settings
  (`sbom-cache-<instance>.json` for EAGLEEYE_CONFIG instances); another Syft version or SBOM setting starts it
  over. Requests never move the daily or weekly times; one made during a daily run starts a full run after it,
  one made during a full run is answered by that run. Uploads after waking are retried for a few minutes.
- Syft keeps one version per package name from a Yarn lockfile and picks a different one each listing (pgAdmin 4's
  `web/yarn.lock` lists react 18.3.1 and 19.2.4). The agent re-reads every `yarn.lock` Syft used and adds the
  versions it left out (2.3.1; 141 on a test PC), so CVEs of either version are found and do not come and go.
- Failed scans always carry a reason, including passive scans on an agent that is not in passive mode.
- Uploads are retried (network errors and 5xx) before a scan is marked failed. When the server answered 5xx every
  time, the reason says "server error (HTTP 500) after 3 tries", not "could not reach the server".
- Sniffers can be stopped cleanly. SNMP left the computer's agent (2.5.x): routers and switches are read by the
  network agent ([Network agent](#network-agent)), with its own SNMP client.
- The default gateway lookup also works on macOS.
