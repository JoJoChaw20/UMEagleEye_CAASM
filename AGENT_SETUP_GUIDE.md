# EagleEye Agent — Setup Guide

This guide walks you through deploying an **EagleEye scanning agent** so that
UMEagleEye can discover and inventory devices on your network automatically.

**Time required:** ~20 minutes
**Skill required:** Basic command-line usage
**Dashboard:** https://umeagleeye.pages.dev

---

## What the Agent Does

The agent is a Python script you run on **any PC or laptop that is connected to
the network you want to scan**. Once running, it:

1. Checks in with the dashboard every 30 seconds (heartbeat — keeps the "Online" status green)
2. Polls for pending scan instructions from the dashboard
3. **Active scans** — runs Nmap on the target subnet and reports discovered hosts
4. **Passive scans** — silently sniffs ARP, mDNS/NetBIOS, and DHCP traffic to discover devices without sending any probe packets; flushes results every 60 seconds automatically

The agent never exposes any ports or listens for incoming connections — it only
makes outbound HTTPS calls to the cloud API.

---

## Scan Modes

| Mode | How it works | Requires |
|------|-------------|----------|
| **Active** | Nmap scan triggered from dashboard | nmap installed |
| **Passive** | ARP/mDNS/DHCP sniffing — runs continuously | scapy + Administrator/root |

Both modes can run simultaneously. Passive mode is recommended for continuous asset
visibility; active mode provides richer OS and port data on demand.

---

## Which Setup Applies to You?

| Your situation | Use |
|----------------|-----|
| The agent machine **has direct internet access** | **Option A — Direct** (most common) |
| The agent machine is **on an isolated LAN with no internet** | **Option B — Via Bridge** |

---

## Prerequisites

Install the following on the machine that will run the agent:

### 1. Python 3.10 or newer

- **Windows:** Download from https://python.org/downloads — tick **"Add Python to PATH"** during install
- **Ubuntu/Debian:** `sudo apt install python3 python3-pip`
- **macOS:** `brew install python` or download from python.org

Verify:
```
python --version
```
Expected: `Python 3.10.x` or higher.

### 2. Nmap (required for active scanning)

- **Windows:** Download installer from https://nmap.org/download.html (use the "Self-installer" `.exe`)
- **Ubuntu/Debian:** `sudo apt install nmap`
- **macOS:** `brew install nmap`

Verify:
```
nmap --version
```
Expected: `Nmap 7.x.x` or higher.

### 3. Syft (required for SBOM scanning)

- **Windows:** `winget install Anchore.Syft`
- **Linux / macOS:** `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh`

Verify:
```
syft --version
```

### 4. Agent files

Copy the `agent/` folder from the project to the target machine, then install dependencies:

```
cd agent
pip install -r requirements.txt
```

`requirements.txt` includes `requests`, `python-nmap`, and `scapy`. Scapy is used for passive sniffing and requires **Administrator (Windows)** or **root (Linux/macOS)** privileges.

---

## Step 1 — Register the Agent in the Dashboard

1. Open the dashboard: **https://umeagleeye.pages.dev**
2. Log in with your assigned account
3. In the left sidebar, click **Agents**
4. Click **Register Agent** (top right)
5. Fill in the form:

   | Field | What to enter |
   |-------|---------------|
   | **Agent Name** | A descriptive name, e.g. `home-network-agent-01` |
   | **Config (JSON)** | Edit the pre-filled template — at minimum change `"subnet"` to match your target network (e.g. `"192.168.0.0/24"`) |

6. Click **Register**
7. A dialog box will appear with your **API Key** and **Agent ID**

> **Important:** Copy both values now and save them somewhere safe.
> The API key is shown **only once** and cannot be retrieved again.

---

## Step 2 — Run the Agent

Open a terminal on the agent machine, navigate to the `agent/` folder, and run:

### Option A — Direct internet connection

#### Active-only (no passive sniffing)

```bash
python eagleeye_agent.py \
  --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key  PASTE_YOUR_API_KEY_HERE \
  --agent-id PASTE_YOUR_AGENT_UUID_HERE
```

#### Active + passive (recommended)

Run as **Administrator** on Windows or **root** on Linux (required for packet capture):

```bash
# Windows — run Command Prompt as Administrator
python eagleeye_agent.py ^
  --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 ^
  --api-key  PASTE_YOUR_API_KEY_HERE ^
  --agent-id PASTE_YOUR_AGENT_UUID_HERE ^
  --passive ^
  --passive-interval 60

# Linux / macOS
sudo python eagleeye_agent.py \
  --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key  PASTE_YOUR_API_KEY_HERE \
  --agent-id PASTE_YOUR_AGENT_UUID_HERE \
  --passive \
  --passive-interface eth0 \
  --passive-interval 60
```

You should see output like:

```
2026-05-28 19:23:21 [INFO] EagleEye Agent v1.3.0 starting
2026-05-28 19:23:21 [INFO] Passive mode : enabled
2026-05-28 19:23:21 [INFO]   Interface  : eth0
2026-05-28 19:23:21 [INFO]   Interval   : 60s
...
2026-05-28 19:24:21 [INFO] [AUTO] Flushing 8 passive host(s) (interval=60s)
2026-05-28 19:24:58 [INFO] Ingested passive (8 host(s)) — 8 hosts, 8 assets upserted
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--api-url` | — | Backend API base URL (required) |
| `--api-key` | — | Agent API key from dashboard (required) |
| `--agent-id` | — | Agent UUID from dashboard (required) |
| `--interval` | `30` | Active scan poll interval (seconds) |
| `--heartbeat-interval` | `30` | Heartbeat interval (seconds) |
| `--passive` | off | Enable passive sniffing (ARP + mDNS/NetBIOS + DHCP) |
| `--passive-interface` | auto | Network interface name for sniffers |
| `--passive-interval` | `60` | Seconds between autonomous ARP buffer flushes |
| `--fingerbank-key` | — | Fingerbank API key for enhanced DHCP fingerprinting |

### Option B — Isolated network via bridge

#### B.1 — Set up the bridge (on a machine that has internet)

```bash
cd agent
cp bridge.env.example bridge.env
```

Open `bridge.env` and fill in:

```env
WORKER_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
BRIDGE_ID=PASTE_BRIDGE_UUID_HERE
BRIDGE_API_KEY=PASTE_BRIDGE_API_KEY_HERE
LISTEN_PORT=8080
BUFFER_MODE=false
```

> To register a bridge: in the dashboard go to **Agents → Bridges → Register Bridge**, enter a name, and copy the API Key and Bridge ID shown.

Run the bridge:
```bash
python bridge.py
```

#### B.2 — Run the agent pointing to the bridge

```bash
python eagleeye_agent.py \
  --api-url  http://BRIDGE_MACHINE_IP:8080/api/v1 \
  --api-key  PASTE_AGENT_API_KEY_HERE \
  --agent-id PASTE_AGENT_UUID_HERE \
  --passive
```

Replace `BRIDGE_MACHINE_IP` with the LAN IP of the machine running `bridge.py`.

---

## Step 3 — Confirm the Agent is Online

1. Go to the dashboard → **Agents**
2. The agent should appear with a green **Online** status badge within 30 seconds

If it shows **Offline**, double-check:
- The API key and agent ID are correct (no extra spaces)
- The agent machine can reach the internet (or the bridge machine)
- Python is running without errors in the terminal

---

## Step 4 — Trigger a Scan

### Active scan (on-demand Nmap)

1. Go to **Discovery → New Scan → Active**
2. Select your registered agent
3. Enter the target subnet in CIDR notation (e.g. `192.168.0.0/24`)
4. Click **Scan**

The agent picks up the job within its next poll cycle (≤30 s), runs Nmap, and reports results. Scan history appears in the Discovery page.

### Passive scan (flush current buffer)

1. Go to **Discovery → New Scan → Passive**
2. Select the agent running with `--passive`
3. Click **Scan**

The agent drains its ARP buffer immediately and closes the scan record. If the buffer was recently auto-flushed it may complete with 0 hosts — this is normal. The autonomous flush runs every `--passive-interval` seconds regardless of dashboard triggers.

---

## Step 5 — View Discovered Assets

1. Go to **Assets → All Assets**
2. Discovered hosts appear automatically with hostname, IP, MAC vendor, OS hint, and open ports
3. To add a discovered host to the full asset registry: go to **My Assets → Add Asset** or use **Import CSV**

Passive-discovered assets appear with `source: scan_passive`; active-scanned assets with `source: scan_active`; manually added assets with `source: manual`.

---

## Optional — Keep the Agent Running After Logout

### Linux (systemd service)

Create `/etc/systemd/system/eagleeye-agent.service`:

```ini
[Unit]
Description=EagleEye Network Scanning Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/path/to/agent
Environment=EAGLEEYE_API_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
Environment=EAGLEEYE_API_KEY=PASTE_API_KEY_HERE
Environment=EAGLEEYE_AGENT_ID=PASTE_AGENT_UUID_HERE
Environment=EAGLEEYE_PASSIVE=true
Environment=EAGLEEYE_PASSIVE_INTERVAL=60
ExecStart=/usr/bin/python3 /path/to/agent/eagleeye_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now eagleeye-agent
sudo journalctl -u eagleeye-agent -f
```

### Windows (Task Scheduler)

1. Open **Task Scheduler** → **Create Basic Task**
2. Name: `EagleEye Agent`
3. Trigger: **When the computer starts**
4. Action: **Start a program**
   - Program: `python`
   - Arguments: `eagleeye_agent.py --api-url https://... --api-key ... --agent-id ... --passive --passive-interval 60`
   - Start in: full path to the `agent/` folder
5. Tick **Run whether user is logged on or not**
6. Tick **Run with highest privileges** (required for passive packet capture)

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Agent stays **Offline** | Wrong API key or agent ID | Re-check copied values; re-register if necessary |
| `python: command not found` | Python not installed or not in PATH | Re-install Python and tick "Add to PATH" |
| `nmap: command not found` | Nmap not installed | Install from nmap.org |
| `pip install` fails | No internet or pip not found | Run `python -m pip install -r requirements.txt` |
| Active scan returns 0 hosts | Wrong subnet or firewall blocking | Confirm subnet with `ipconfig` / `ip addr` |
| Passive scan shows **Failed** | Agent restarted without `--passive` flag | Restart agent with `--passive`; or the buffer was empty and an old scan record timed out |
| Passive scan shows **Completed / 0 hosts** | Buffer was just flushed by autonomous cycle | Normal behaviour — the next automatic flush will have data |
| `PermissionError` in passive mode | Not running as Administrator / root | Re-run as Administrator (Windows) or `sudo` (Linux) |
| `scapy not installed` | scapy missing from pip install | Run `pip install scapy` or re-run `pip install -r requirements.txt` |
| `syft not found` | Syft not installed | Install with `winget install Anchore.Syft` (Windows) or the install script (Linux/macOS) |
| `Connection refused` (bridge mode) | Bridge not running or wrong IP | Confirm `bridge.py` is running; check bridge machine LAN IP |
| `401 Unauthorized` | API key mismatch | Delete agent in dashboard, register again, use the new key |

---

## Quick Reference

```
Dashboard:   https://umeagleeye.pages.dev
API:         https://umeagleeye-api.syntaxch404.workers.dev/api/v1

Active-only:
  python eagleeye_agent.py \
    --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
    --api-key  <key> \
    --agent-id <uuid>

Active + passive (run as Administrator / root):
  python eagleeye_agent.py \
    --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
    --api-key  <key> \
    --agent-id <uuid> \
    --passive \
    --passive-interval 60

Environment variable alternative:
  EAGLEEYE_API_URL=https://...
  EAGLEEYE_API_KEY=<key>
  EAGLEEYE_AGENT_ID=<uuid>
  EAGLEEYE_PASSIVE=true
  EAGLEEYE_PASSIVE_INTERVAL=60
  python eagleeye_agent.py
```

---

*UMEagleEye 2.0 — Final Year Project, University of Malaya*
*For questions, contact the project team.*
