#!/usr/bin/env python3
"""
EagleEye Agent — network scanner for UMEagleEye CAASM platform.

Polls the backend for pending scans, runs Nmap, and POSTs results.

Usage:
    python eagleeye_agent.py \
        --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
        --api-key <key-from-dashboard> \
        --agent-id <uuid-from-dashboard>

Or via environment variables:
    EAGLEEYE_API_URL, EAGLEEYE_API_KEY, EAGLEEYE_AGENT_ID, EAGLEEYE_POLL_INTERVAL
"""

import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import time
from typing import Any

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("eagleeye")

VERSION = "1.0.0"


# ── Nmap runner ───────────────────────────────────────────────────────────────

def run_nmap(subnet: str) -> list[dict[str, Any]]:
    """Run nmap -sV on subnet, return list of host dicts."""
    log.info(f"Running nmap on {subnet}")
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sV -T4 --open -p 22,80,443,3389,8080,8443,3306,5432,6379,27017")
        hosts = []
        for ip in nm.all_hosts():
            host = nm[ip]
            if host.state() != "up":
                continue
            ports = []
            for proto in host.all_protocols():
                for port_num, port_info in host[proto].items():
                    if port_info.get("state") == "open":
                        ports.append({
                            "port": port_num,
                            "protocol": proto,
                            "service": port_info.get("name", ""),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                        })
            os_info = {}
            if "osmatch" in host and host["osmatch"]:
                best = host["osmatch"][0]
                os_info = {"name": best.get("name", ""), "accuracy": best.get("accuracy", "")}
            hostname = ""
            if host.hostname():
                hostname = host.hostname()
            hosts.append({
                "ip": ip,
                "hostname": hostname or None,
                "mac": host.get("addresses", {}).get("mac") or None,
                "ports": ports,
                "os": os_info or None,
            })
        log.info(f"Nmap found {len(hosts)} hosts on {subnet}")
        return hosts
    except ImportError:
        log.warning("python-nmap not installed — falling back to ping sweep")
        return _ping_sweep(subnet)


def _ping_sweep(subnet: str) -> list[dict[str, Any]]:
    """Fallback: use nmap CLI directly for simple host discovery."""
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", subnet, "--oX", "-"],
            capture_output=True, text=True, timeout=120,
        )
        hosts = []
        import re
        # Very simple XML parse without xml library dependency
        for ip_match in re.finditer(r'addr="([\d.]+)"', result.stdout):
            ip = ip_match.group(1)
            if not ip.startswith("0."):
                hosts.append({"ip": ip, "hostname": None, "mac": None, "ports": [], "os": None})
        log.info(f"Ping sweep found {len(hosts)} hosts")
        return hosts
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error(f"nmap not available: {e}")
        return []


# ── API client ────────────────────────────────────────────────────────────────

class AgentClient:
    def __init__(self, api_url: str, api_key: str, agent_id: str):
        self.api_url = api_url.rstrip("/")
        self.agent_id = agent_id
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "X-Agent-ID": agent_id,
            "Content-Type": "application/json",
            "User-Agent": f"EagleEye-Agent/{VERSION}",
        })

    def get_pending_scans(self) -> list[dict]:
        try:
            resp = self.session.get(f"{self.api_url}/scans/pending", timeout=15)
            resp.raise_for_status()
            return resp.json().get("scans", [])
        except requests.RequestException as e:
            log.error(f"Failed to fetch pending scans: {e}")
            return []

    def ingest_results(self, scan_id: str, hosts: list[dict]) -> bool:
        payload = {
            "agent_id": self.agent_id,
            "scan_id": scan_id,
            "hosts": hosts,
        }
        try:
            resp = self.session.post(
                f"{self.api_url}/scans/ingest",
                data=json.dumps(payload),
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(
                f"Ingested scan {scan_id[:8]}… — "
                f"{data.get('hosts_discovered', 0)} hosts, "
                f"{data.get('assets_upserted', 0)} assets upserted"
            )
            return True
        except requests.RequestException as e:
            log.error(f"Failed to ingest scan results: {e}")
            return False


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EagleEye network scanning agent")
    parser.add_argument("--api-url",    default=os.getenv("EAGLEEYE_API_URL", ""),  help="Backend API base URL")
    parser.add_argument("--api-key",    default=os.getenv("EAGLEEYE_API_KEY", ""),  help="Agent API key (from dashboard)")
    parser.add_argument("--agent-id",   default=os.getenv("EAGLEEYE_AGENT_ID", ""), help="Agent UUID (from dashboard)")
    parser.add_argument("--interval",   type=int, default=int(os.getenv("EAGLEEYE_POLL_INTERVAL", "30")), help="Poll interval in seconds (default: 30)")
    args = parser.parse_args()

    if not args.api_url or not args.api_key or not args.agent_id:
        parser.error("--api-url, --api-key, and --agent-id are required (or set env vars)")

    log.info(f"EagleEye Agent v{VERSION} starting")
    log.info(f"API URL  : {args.api_url}")
    log.info(f"Agent ID : {args.agent_id}")
    log.info(f"Hostname : {socket.gethostname()}")
    log.info(f"Polling every {args.interval}s")

    client = AgentClient(args.api_url, args.api_key, args.agent_id)

    while True:
        try:
            pending = client.get_pending_scans()
            if pending:
                log.info(f"Found {len(pending)} pending scan(s)")
                for scan in pending:
                    scan_id = scan.get("scan_id") or scan.get("scanId")
                    subnet = scan.get("subnet", "192.168.1.0/24")
                    log.info(f"Processing scan {scan_id[:8]}… subnet={subnet}")
                    hosts = run_nmap(subnet)
                    client.ingest_results(scan_id, hosts)
            else:
                log.debug("No pending scans")
        except KeyboardInterrupt:
            log.info("Shutting down")
            sys.exit(0)
        except Exception as e:
            log.error(f"Unexpected error: {e}", exc_info=True)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
