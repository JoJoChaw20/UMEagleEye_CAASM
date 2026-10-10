# EagleEye Agent 2 (pipeline agent)

Command-line core of the new EagleEye agent. It does what the original agent in `../agent/` does
(network discovery and fingerprinting, passive sniffing, SNMPv3 polling, upload to the API), restructured as a
pipeline of stages that report progress. The GUI, installer and enrichment collectors are built on top of this.

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
| `python -m eagleeye config init ...` | Writes the config file |
| `python -m eagleeye config show` | Prints the effective settings, secrets masked |
| `python -m eagleeye run` | The agent: heartbeat, poll the dashboard, run scans, upload results |

## Settings
Precedence: config file < `EAGLEEYE_*` environment variables < command-line flags. The variable names are the
same as the original agent's. Config file: `%APPDATA%\EagleEye\config.json` on Windows,
`~/Library/Application Support/EagleEye/config.json` on macOS, `~/.config/eagleeye/config.json` on Linux
(override with `EAGLEEYE_CONFIG`). It stores secrets in plain text for now; the GUI build moves them to the OS keychain.

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
  stages/     scan_nmap (Nmap + built-in fallback), snmp_poll, passive, upload
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
