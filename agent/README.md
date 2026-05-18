# EagleEye Agent & Bridge

Lightweight components that connect physical network devices to the UMEagleEye CAASM platform.

- **Agent** (`eagleeye_agent.py`) — runs on any machine in the target network, polls for pending scans, runs Nmap, and POSTs results back.
- **Bridge** (`bridge.py`) — optional HTTP relay for isolated networks that cannot reach the internet directly. Agents talk to the bridge; the bridge forwards to the Cloudflare Worker.

---

## Architecture

The **bridge** and **agent** are Python processes that run on regular PCs/laptops.  
The **routers, switches, PCs, and servers** in the faculty network are the *scan targets* — they become Assets in the dashboard.

### Direct connection (internet-reachable network)

```
Faculty LAN devices (routers, switches, PCs, servers)
         ↑ scanned by nmap
  [Agent PC — Python + nmap]  ──HTTPS──▶  [Cloudflare Worker API]
```

### Via bridge (isolated / NAT'd faculty network)

```
Faculty LAN devices (routers, switches, PCs, servers)
         ↑ scanned by nmap
  [Agent PC — Python + nmap]
         │ HTTP :8080 (LAN)
         ↓
  [Bridge PC — Python, has internet]  ──HTTPS──▶  [Cloudflare Worker API]
```

- **Bridge PC**: any PC/laptop with internet access and Python 3.10+
- **Agent PC**: any PC/laptop in the same subnet as the devices to scan, with Python 3.10+ and nmap
- **Scan targets**: routers, switches, PCs, servers, printers, IoT — anything on the faculty LAN

The bridge machine needs internet access. The agent machine only needs LAN access to the bridge.

---

## Prerequisites

- Python 3.10+
- Nmap installed (`sudo apt install nmap` / `brew install nmap` / [nmap.org](https://nmap.org/download.html))

```bash
pip install -r requirements.txt
```

---

## Step 1 — Register in the dashboard

### If using a bridge

1. In the UMEagleEye dashboard, go to **Agents → Bridges** and click **Register Bridge**
2. Enter a name (e.g., `fsktm-bridge`) and click **Register**
3. **Copy the API key shown once** — you cannot retrieve it again
4. Note the Bridge ID shown in the table

### Register an agent

1. In the **Agents** table, click **Register Agent**
2. Enter a name (e.g., `fsktm-lab-01`), optionally select the bridge you just created
3. **Copy the API key shown once**
4. Note the Agent ID shown in the table

---

## Step 2 — Configure and run the bridge (skip if direct connection)

On the **bridge machine** (must have internet access):

```bash
# Clone or copy the agent/ folder to this machine
cd agent/

# Create the config file
cp bridge.env.example bridge.env
```

Edit `bridge.env`:

```env
WORKER_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
BRIDGE_ID=<paste-bridge-id-here>
BRIDGE_API_KEY=<paste-bridge-api-key-here>
LISTEN_PORT=8080
BUFFER_MODE=false
HEARTBEAT_INTERVAL=30
```

Set `BUFFER_MODE=true` if the internet link is unstable — scan results will be queued in SQLite and flushed when the link recovers.

Run the bridge:

```bash
python bridge.py
```

Expected output:
```
2026-05-18 10:00:00 [BRIDGE] INFO UMEagleEye Bridge v1.0.0 starting
2026-05-18 10:00:00 [BRIDGE] INFO   Worker URL   : https://umeagleeye-api.syntaxch404.workers.dev/api/v1
2026-05-18 10:00:00 [BRIDGE] INFO   Listen port  : 8080
2026-05-18 10:00:00 [BRIDGE] INFO   Mode         : relay
2026-05-18 10:00:00 [BRIDGE] INFO Bridge listening on 0.0.0.0:8080 — press Ctrl+C to stop
```

The bridge dashboard status will turn **Online** within 30 seconds.

---

## Step 3 — Run the agent

On the **agent machine** (must have network access to the target subnet):

### Direct connection to Cloudflare Worker

```bash
python eagleeye_agent.py \
  --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key <your-agent-api-key> \
  --agent-id <your-agent-uuid>
```

### Via bridge

```bash
python eagleeye_agent.py \
  --api-url http://<bridge-machine-ip>:8080/api/v1 \
  --api-key <your-agent-api-key> \
  --agent-id <your-agent-uuid>
```

Replace `<bridge-machine-ip>` with the LAN IP of the machine running `bridge.py`.

Expected output:
```
2026-05-18 10:00:05 [INFO] EagleEye Agent v1.1.0 starting
2026-05-18 10:00:05 [INFO] API URL     : http://192.168.1.10:8080/api/v1
2026-05-18 10:00:05 [INFO] Agent ID    : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
2026-05-18 10:00:05 [INFO] Gateway IP  : 192.168.1.50
2026-05-18 10:00:05 [INFO] Poll every  : 30s
2026-05-18 10:00:05 [INFO] Heartbeat   : 30s
2026-05-18 10:00:05 [INFO] Heartbeat thread started (interval=30s)
```

The agent status will turn **Online** in the dashboard within seconds.

---

## Step 4 — Trigger a scan

1. In the dashboard, go to **Agents**
2. Click **New Scan** (or use the scan button next to the agent)
3. Enter the target subnet (e.g., `192.168.100.0/24` for your faculty LAN)
4. Click **Scan**

The agent picks up the scan within its next poll cycle (≤30 seconds), runs Nmap, and ingests results. Discovered assets appear in the **Assets** page automatically.

---

## Running as a service (Linux)

Save as `/etc/systemd/system/eagleeye-agent.service`:

```ini
[Unit]
Description=EagleEye Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=eagleeye
WorkingDirectory=/opt/eagleeye-agent
Environment=EAGLEEYE_API_URL=http://192.168.1.10:8080/api/v1
Environment=EAGLEEYE_API_KEY=<your-api-key>
Environment=EAGLEEYE_AGENT_ID=<your-agent-uuid>
ExecStart=/usr/bin/python3 /opt/eagleeye-agent/eagleeye_agent.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now eagleeye-agent
sudo journalctl -u eagleeye-agent -f
```

Same pattern applies for `bridge.py` — create `eagleeye-bridge.service`.

---

## Options reference

### eagleeye_agent.py

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--api-url` | `EAGLEEYE_API_URL` | — | Worker or bridge API base URL |
| `--api-key` | `EAGLEEYE_API_KEY` | — | Agent API key from dashboard |
| `--agent-id` | `EAGLEEYE_AGENT_ID` | — | Agent UUID from dashboard |
| `--interval` | `EAGLEEYE_POLL_INTERVAL` | `30` | Scan poll interval (seconds) |
| `--heartbeat-interval` | `EAGLEEYE_HEARTBEAT_INTERVAL` | `30` | Heartbeat interval (seconds) |

### bridge.env

| Key | Default | Description |
|-----|---------|-------------|
| `WORKER_URL` | — | Cloudflare Worker API URL (required) |
| `BRIDGE_ID` | — | Bridge UUID from dashboard |
| `BRIDGE_API_KEY` | — | Bridge API key from dashboard |
| `LISTEN_PORT` | `8080` | Port agents connect to |
| `BUFFER_MODE` | `false` | Queue scan results in SQLite when offline |
| `FLUSH_INTERVAL` | `60` | Buffer flush interval (seconds) |
| `HEARTBEAT_INTERVAL` | `30` | Bridge heartbeat interval (seconds) |

---

## Notes

- Nmap requires root/administrator privileges for SYN scans and OS detection. Run with `sudo` if needed.
- If `python-nmap` is unavailable, the agent falls back to the nmap CLI directly (`-sn` ping sweep).
- The bridge `/health` endpoint (`GET http://bridge-ip:8080/health`) returns queue depth and mode — useful for monitoring.
- The agent sends a heartbeat immediately on start, then every `--heartbeat-interval` seconds via a background thread, independent of scan activity. This keeps the dashboard status green at all times.
