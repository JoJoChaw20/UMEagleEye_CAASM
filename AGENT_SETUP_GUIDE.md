# EagleEye Agent — Setup Guide

This guide walks you through deploying an **EagleEye scanning agent** so that
UMEagleEye can discover and inventory devices on your network automatically.

**Time required:** ~15 minutes  
**Skill required:** Basic command-line usage  
**Dashboard:** https://umeagleeye.pages.dev  

---

## What the Agent Does

The agent is a small Python script you run on **any PC or laptop that is
connected to the network you want to scan**. Once running, it:

1. Checks in with the dashboard every 30 seconds (heartbeat — keeps the "Online" status green)
2. Waits for a scan instruction from the dashboard
3. Runs **Nmap** on the target subnet you specify
4. Sends discovered hosts back to the dashboard, where they appear as assets

The agent never exposes any ports or listens for incoming connections — it only
makes outbound HTTPS calls to the cloud API.

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

Verify: open a terminal and run:
```
python --version
```
Expected: `Python 3.10.x` or higher.

### 2. Nmap

- **Windows:** Download installer from https://nmap.org/download.html (use the "Self-installer" `.exe`)
- **Ubuntu/Debian:** `sudo apt install nmap`
- **macOS:** `brew install nmap`

Verify:
```
nmap --version
```
Expected: `Nmap 7.x.x` or higher.

### 3. Agent files

Copy the `agent/` folder from the project to the target machine. It contains:

```
agent/
├── eagleeye_agent.py     ← main agent script
├── bridge.py             ← only needed for Option B
├── bridge.env.example    ← only needed for Option B
└── requirements.txt
```

Then install Python dependencies:
```
cd agent
pip install -r requirements.txt
```

---

## Step 1 — Register the Agent in the Dashboard

1. Open the dashboard: **https://umeagleeye.pages.dev**
2. Log in with your assigned account
3. In the left sidebar, click **Agents**
4. Click **Register Agent** (top right)
5. Fill in the form:

   | Field | What to enter |
   |-------|---------------|
   | **Agent Name** | A descriptive name, e.g. `fsktm-lab-agent-01` |
   | **Config (JSON)** | Edit the pre-filled template — at minimum change `"subnet"` to match your target network (e.g. `"192.168.10.0/24"`) |

6. Click **Register**
7. A dialog box will appear with your **API Key** and **Agent ID**

> **Important:** Copy both values now and save them somewhere safe.  
> The API key is shown **only once** and cannot be retrieved again.

---

## Step 2 — Run the Agent

Open a terminal on the agent machine, navigate to the `agent/` folder, and run:

### Option A — Direct internet connection

```bash
python eagleeye_agent.py \
  --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key  PASTE_YOUR_API_KEY_HERE \
  --agent-id PASTE_YOUR_AGENT_UUID_HERE
```

**Windows example** (Command Prompt):
```
python eagleeye_agent.py --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 --api-key ey... --agent-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### Option B — Isolated network via bridge

#### B.1 — Set up the bridge (on a machine that has internet)

```bash
cd agent
cp bridge.env.example bridge.env
```

Open `bridge.env` in any text editor and fill in these values:

```env
WORKER_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
BRIDGE_ID=PASTE_BRIDGE_UUID_HERE
BRIDGE_API_KEY=PASTE_BRIDGE_API_KEY_HERE
LISTEN_PORT=8080
BUFFER_MODE=false
```

> To register a bridge: in the dashboard go to **Agents → Bridges → Register Bridge**,
> enter a name (e.g. `fsktm-bridge`), and copy the API Key and Bridge ID shown.

Run the bridge:
```bash
python bridge.py
```

Leave this terminal open. The bridge is now relaying on port 8080.

#### B.2 — Run the agent pointing to the bridge

On the isolated agent machine:
```bash
python eagleeye_agent.py \
  --api-url  http://BRIDGE_MACHINE_IP:8080/api/v1 \
  --api-key  PASTE_AGENT_API_KEY_HERE \
  --agent-id PASTE_AGENT_UUID_HERE
```

Replace `BRIDGE_MACHINE_IP` with the **LAN IP address** of the machine running `bridge.py`
(e.g. `192.168.1.10`).

---

## Step 3 — Confirm the Agent is Online

1. Go back to the dashboard → **Agents**
2. The agent you registered should appear with a green **Online** status badge within 30 seconds

If it shows **Offline**, double-check:
- The API key and agent ID were pasted correctly (no extra spaces)
- The agent machine can reach the internet (or the bridge machine)
- Python is running without errors in the terminal

---

## Step 4 — Trigger a Scan

1. In the dashboard, go to **Discovery**
2. Click **New Scan**
3. Enter the **target subnet** in CIDR notation, for example:
   - `192.168.1.0/24` — scans all 254 addresses in 192.168.1.x
   - `10.30.1.0/24` — scans the 10.30.1.x subnet
4. Click **Scan**

The agent picks up the scan within its next poll cycle (at most 30 seconds), runs
Nmap, and reports results. Progress is visible in the **Discovery** page.

---

## Step 5 — View Discovered Assets

1. Go to **Assets → All Assets**
2. Newly discovered hosts appear automatically with hostname, IP address, open ports, and OS information
3. To promote a discovered host to the full asset registry: go to **Discovery**, find the host, and click **Add to Inventory**

---

## Optional — Keep the Agent Running After Logout

### Linux (systemd service)

Create the file `/etc/systemd/system/eagleeye-agent.service`:

```ini
[Unit]
Description=EagleEye Network Scanning Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/agent
Environment=EAGLEEYE_API_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
Environment=EAGLEEYE_API_KEY=PASTE_API_KEY_HERE
Environment=EAGLEEYE_AGENT_ID=PASTE_AGENT_UUID_HERE
ExecStart=/usr/bin/python3 /path/to/agent/eagleeye_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start it:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now eagleeye-agent

# Check logs
sudo journalctl -u eagleeye-agent -f
```

### Windows (Task Scheduler)

1. Open **Task Scheduler** → **Create Basic Task**
2. Name: `EagleEye Agent`
3. Trigger: **When the computer starts**
4. Action: **Start a program**
   - Program: `python`
   - Arguments: `eagleeye_agent.py --api-url https://... --api-key ... --agent-id ...`
   - Start in: full path to the `agent/` folder
5. Tick **Run whether user is logged on or not**

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| Agent stays **Offline** | Wrong API key or agent ID | Re-check the copied values; re-register if necessary |
| `python: command not found` | Python not installed or not in PATH | Re-install Python and tick "Add to PATH" |
| `nmap: command not found` | Nmap not installed | Install Nmap from nmap.org |
| `pip install` fails | No internet or pip not found | Run `python -m pip install -r requirements.txt` |
| Scan shows 0 hosts | Subnet is wrong or firewall blocking | Confirm the subnet with `ipconfig` / `ip addr`; check firewall rules |
| `Connection refused` (bridge mode) | Bridge not running or wrong IP | Confirm `bridge.py` is running; check bridge machine LAN IP |
| `401 Unauthorized` | API key mismatch | Delete the agent in the dashboard, register again, use the new key |

---

## Quick Reference

```
Dashboard:   https://umeagleeye.pages.dev
API:         https://umeagleeye-api.syntaxch404.workers.dev/api/v1

Run agent:
  python eagleeye_agent.py \
    --api-url  https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
    --api-key  <key-from-dashboard> \
    --agent-id <uuid-from-dashboard>

Environment variable alternative:
  EAGLEEYE_API_URL=https://...
  EAGLEEYE_API_KEY=<key>
  EAGLEEYE_AGENT_ID=<uuid>
  python eagleeye_agent.py
```

---

*UMEagleEye 2.0 — Final Year Project, University of Malaya*  
*For questions, contact the project team.*
