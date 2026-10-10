# EagleEye Agent 2 (pipeline agent)

Command-line core of the new EagleEye agent. It does what the original agent in `../agent/` does
(network discovery and fingerprinting, passive sniffing, SNMPv3 polling, upload to the API), restructured as a
pipeline of stages that report progress, and adds an **endpoint inventory** of the machine it runs on
(hardware, OS, patches, security posture, interfaces, listening services, installed software).

The original agent is untouched and keeps working against the same API. SBOM scanning is not part of this
version: SBOM scans queued for this agent are declined with a visible reason.

## Requirements
- Python 3.12 or newer
- Nmap and, for passive sniffing, Npcap (Windows) / libpcap (Linux, macOS). They are **not** bundled
  (their licences restrict redistribution). `check-deps` tells you what is missing and where to get it.
  Without Nmap, scans fall back to a built-in sweep that finds hosts and open ports but not services or OS.

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
| `python -m eagleeye config init ...` | Writes the config file |
| `python -m eagleeye config show` | Prints the effective settings, secrets masked |
| `python -m eagleeye run` | The agent: heartbeat, poll the dashboard, run scans, upload results |

## Settings
Precedence: config file < `EAGLEEYE_*` environment variables < command-line flags. The variable names are the
same as the original agent's. Config file: `%APPDATA%\EagleEye\config.json` on Windows,
`~/Library/Application Support/EagleEye/config.json` on macOS, `~/.config/eagleeye/config.json` on Linux
(override with `EAGLEEYE_CONFIG`). It stores secrets in plain text for now; the GUI build moves them to the OS keychain.

## Endpoint inventory
While `run` is active the agent collects the inventory of its own machine on the first poll and then every
`inventory_interval` seconds (default 6 hours), and posts it to `POST /agents/:id/inventory`. The server matches it
to the machine's asset (previous binding, then physical-NIC MAC, then a unique hostname, then a unique IP held by an
asset with no MAC) or creates a new asset in Discovered, stores the facts on the asset and syncs its software list.

| Section | Source on Windows | Used in the system |
|---|---|---|
| Identity (hostname, domain, MachineGuid, SMBIOS UUID, serial) | registry, CIM | binding to the right asset; later: identity resolver and duplicates |
| Hardware (model, form factor, CPU, RAM, disks, BIOS) | CIM, Storage module | asset detail; later: device-type classification |
| OS and patches (build, role, last update, pending restart) | CIM, Get-HotFix, registry | asset detail; later: criticality and posture |
| Security posture (firewall, antivirus, BitLocker, Secure Boot, TPM, UAC, RDP, SMBv1, local admins) | NetSecurity, Defender, SecurityCenter2, registry | asset detail; later: posture score and alerts |
| Interfaces and listening services (with process) | NetAdapter, NetTCPIP | binding (MACs); asset detail |
| Installed software | Uninstall registry keys (machine and user) | `asset_software` table, asset detail; later: CVE matching and drift |

BitLocker, TPM and SMBv1 need Administrator; without it they are reported as "needs Administrator". Settings:
`inventory` (on/off, `--no-inventory`) and `inventory_interval` (`--inventory-interval`, minimum 300 s). Linux and
macOS collectors are not written yet; on those systems the agent reports that once and stops trying.

## Privacy and data protection
The endpoint inventory describes the machine the agent is installed on. On an organisation-owned device that is
normal asset-management data; on a device a person uses, parts of it identify that person, which makes it personal
data under Malaysia's Personal Data Protection Act 2010. The agent is built to collect only what security needs.

**Collected by default:** hardware model and serial number, OS version and patches, security settings (firewall,
antivirus, encryption, Secure Boot, TPM, UAC, RDP, SMBv1), the **number** of local administrator accounts, network
interfaces and their addresses, network-reachable listening ports with the program behind them, and software
installed for all users of the machine.

**Off unless switched on (personal data):**
| Setting | Flag / variable | What it adds |
|---|---|---|
| `inventory_user_software` | `--include-user-software`, `EAGLEEYE_INVENTORY_USER_SOFTWARE=1` | Software one user installed for themselves (Windows HKCU) |
| `inventory_admin_names` | `--include-admin-names`, `EAGLEEYE_INVENTORY_ADMIN_NAMES=1` | The names of the local administrator accounts |

**Never collected:** files or documents, browsing history, passwords or credentials, keystrokes, screenshots, email
or messages, location, and the contents of network traffic. For ports that only listen on the machine itself
(`127.0.0.1` / `::1`), which program owns them is not sent. Passive mode reads only broadcast discovery packets
(ARP, mDNS, NetBIOS, DHCP) to learn device names and addresses.

**Transparency:** `python -m eagleeye inventory` shows exactly what would be sent, without sending it
(`--json file` saves the full document for review).

**Where it goes and for how long:** over HTTPS to the organisation's own EagleEye server only (no third parties),
stored with the matching asset in that organisation's tenant and visible only to its users. Only the latest
inventory is kept: each run replaces the previous one, and software that is uninstalled disappears at the next run.

**Removal:** an administrator can press **Clear inventory** on the asset page (recorded in the audit log), or delete
the asset. To stop collection on a machine, run the agent with `--no-inventory` or stop it; otherwise it sends a
new inventory at its next run.

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

## Layout
```
eagleeye/
  cli.py, service.py, config.py, api.py, deps.py, netinfo.py
  pipeline/   HostRecord, events, runner (stages, optional stages, cancellation)
  stages/     scan_nmap (Nmap + built-in fallback), snmp_poll, passive, inventory, upload
  collectors/ endpoint inventory: windows_inventory.ps1 + windows.py normaliser
  passive/    ARP, mDNS/NetBIOS and DHCP sniffers
tests/        pytest suite, including side-by-side parity checks against ../agent/eagleeye_agent.py
```

## Tests
```powershell
python -m pytest -q
```
`tests/test_parity.py` loads the original agent and compares its output with this one on recorded Nmap data. It is
skipped automatically once the original agent is removed.

## Behaviour changes from the original agent
- Scan targets must be an IPv4 address or CIDR range (what the dashboard already requires) and no larger than a /16.
  The value reaches the Nmap command line, so anything else is rejected before Nmap runs.
- A missing Nmap is reported and handled by the built-in sweep, instead of failing the scan.
- SBOM scans are declined with a reason; unsupported scan types are declined too.
- Failed scans always carry a reason, including passive scans on an agent that is not in passive mode.
- Uploads are retried (network errors and 5xx) before a scan is marked failed.
- SNMP polling runs up to 8 hosts in parallel; sniffers can be stopped cleanly.
- The default gateway lookup also works on macOS.
