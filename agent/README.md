# EagleEye Agent

Lightweight network scanner that polls UMEagleEye for pending scans, runs Nmap, and POSTs results back.

## Prerequisites

- Python 3.10+
- Nmap installed on the system (`apt install nmap` / `brew install nmap` / [nmap.org](https://nmap.org/download.html))

## Setup

```bash
pip install -r requirements.txt
```

## Usage

1. In the UMEagleEye dashboard, go to **Agents** and click **Register Agent**
2. Copy the API key shown once at registration, and note the Agent ID
3. Run the agent:

```bash
python eagleeye_agent.py \
  --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
  --api-key <your-api-key> \
  --agent-id <your-agent-uuid>
```

Or with environment variables:

```bash
export EAGLEEYE_API_URL=https://umeagleeye-api.syntaxch404.workers.dev/api/v1
export EAGLEEYE_API_KEY=<your-api-key>
export EAGLEEYE_AGENT_ID=<your-agent-uuid>
python eagleeye_agent.py
```

## Options

| Flag | Env var | Default | Description |
|------|---------|---------|-------------|
| `--api-url` | `EAGLEEYE_API_URL` | — | Backend API base URL |
| `--api-key` | `EAGLEEYE_API_KEY` | — | Agent API key from dashboard |
| `--agent-id` | `EAGLEEYE_AGENT_ID` | — | Agent UUID from dashboard |
| `--interval` | `EAGLEEYE_POLL_INTERVAL` | `30` | Poll interval in seconds |

## Workflow

1. Agent polls `GET /scans/pending` every `--interval` seconds
2. For each pending scan it finds: runs `nmap -sV -T4` on the configured subnet
3. POSTs discovered hosts to `POST /scans/ingest`
4. The backend upserts assets and queues AI advisory generation

## Notes

- Nmap requires root/administrator privileges for OS detection (`-O`). Run with `sudo` if needed.
- If `python-nmap` is unavailable, the agent falls back to the nmap CLI directly.
- The agent sends a heartbeat on every poll, keeping its status `online` in the dashboard.
