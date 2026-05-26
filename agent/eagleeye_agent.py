#!/usr/bin/env python3
"""
EagleEye Agent — active + passive network scanner for UMEagleEye CAASM platform.

Active mode  : polls the backend for pending scans, runs Nmap, and POSTs results.
Passive mode : sniffs ARP broadcasts continuously; discovered hosts are ingested
               every --passive-interval seconds without requiring a prior scan dispatch.

A background thread sends heartbeats every --heartbeat-interval seconds so the
dashboard shows the agent as online even between scans.

Usage:
    python eagleeye_agent.py \
        --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \
        --api-key <key-from-dashboard> \
        --agent-id <uuid-from-dashboard>

    # With passive ARP sniffing enabled:
    python eagleeye_agent.py \
        --api-url ... --api-key ... --agent-id ... \
        --passive [--passive-interface eth0] [--passive-interval 60]

Or via environment variables:
    EAGLEEYE_API_URL, EAGLEEYE_API_KEY, EAGLEEYE_AGENT_ID,
    EAGLEEYE_POLL_INTERVAL, EAGLEEYE_HEARTBEAT_INTERVAL,
    EAGLEEYE_PASSIVE, EAGLEEYE_PASSIVE_INTERFACE, EAGLEEYE_PASSIVE_INTERVAL
"""

import argparse
import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Optional

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("eagleeye")

VERSION = "1.2.0"


# ── Active scanning: Nmap ─────────────────────────────────────────────────────

def run_nmap(subnet: str) -> list[dict[str, Any]]:
    """Run nmap -sV on subnet, return list of host dicts."""
    log.info(f"Running nmap on {subnet}")
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments="-sV -T4 --open -p 22,23,80,161,443,3389,8080,8443,3306,5432,6379,27017")
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
            hostname = host.hostname() or None
            hosts.append({
                "ip": ip,
                "hostname": hostname,
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
        for ip_match in re.finditer(r'addr="([\d.]+)"', result.stdout):
            ip = ip_match.group(1)
            if not ip.startswith("0."):
                hosts.append({"ip": ip, "hostname": None, "mac": None, "ports": [], "os": None})
        log.info(f"Ping sweep found {len(hosts)} hosts")
        return hosts
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error(f"nmap not available: {e}")
        return []


# ── Passive scanning: ARP sniffer ─────────────────────────────────────────────

class ArpSniffer:
    """
    Listens for ARP requests/replies on the local network and records the
    source IP + MAC of every active host — no probes sent.

    Requires scapy and root/Administrator privileges.
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface
        self._lock = threading.Lock()
        self._seen: dict[str, dict[str, Any]] = {}   # ip -> {mac, last_seen}
        self._running = False

    def start(self) -> bool:
        """Start sniffing in a background daemon thread. Returns False if scapy unavailable."""
        try:
            from scapy.all import sniff, ARP  # type: ignore  # noqa: F401
        except ImportError:
            log.warning("scapy not installed — passive ARP disabled. Run: pip install scapy")
            return False

        self._running = True
        t = threading.Thread(target=self._sniff_loop, daemon=True, name="arp-sniffer")
        t.start()
        iface_label = self.interface or "default"
        log.info(f"Passive ARP sniffer started on interface={iface_label}")
        return True

    def _sniff_loop(self) -> None:
        try:
            from scapy.all import sniff, ARP  # type: ignore

            def handle(pkt: Any) -> None:
                # Capture both ARP requests (op=1) and replies (op=2)
                if not pkt.haslayer(ARP):
                    return
                ip  = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                if not ip or ip.startswith("0.") or ip == "0.0.0.0":
                    return
                with self._lock:
                    self._seen[ip] = {"mac": mac, "last_seen": time.time()}

            kwargs: dict[str, Any] = {"filter": "arp", "prn": handle, "store": False}
            if self.interface:
                kwargs["iface"] = self.interface

            sniff(**kwargs)  # blocks until process exits
        except PermissionError:
            log.error("Passive ARP requires root/Administrator privileges — sniffer stopped")
        except Exception as exc:
            log.error(f"ARP sniffer error: {exc}")

    def drain(self) -> list[dict[str, Any]]:
        """Return all discovered hosts since last drain and clear the buffer."""
        with self._lock:
            snapshot = dict(self._seen)
            self._seen.clear()

        hosts = []
        for ip, info in snapshot.items():
            # Best-effort reverse DNS — gives the LLM/backend a hostname hint
            hostname: Optional[str] = None
            try:
                result = socket.gethostbyaddr(ip)
                hostname = result[0] if result[0] != ip else None
            except (socket.herror, socket.gaierror, OSError):
                pass  # non-fatal — leave hostname as None

            hosts.append({
                "ip":       ip,
                "mac":      info["mac"],
                "hostname": hostname,
                "ports":    [],
                "os":       None,
            })
        return hosts


# ── Local IP helper ───────────────────────────────────────────────────────────

def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


# ── API client ────────────────────────────────────────────────────────────────

class AgentClient:
    def __init__(self, api_url: str, api_key: str, agent_id: str):
        self.api_url  = api_url.rstrip("/")
        self.agent_id = agent_id
        self.session  = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "X-Agent-ID":    agent_id,
            "Content-Type":  "application/json",
            "User-Agent":    f"EagleEye-Agent/{VERSION}",
        })

    def send_heartbeat(self) -> bool:
        payload = {"version": VERSION, "gateway_ip": _local_ip()}
        try:
            resp = self.session.post(
                f"{self.api_url}/agents/{self.agent_id}/heartbeat",
                data=json.dumps(payload), timeout=10,
            )
            resp.raise_for_status()
            return True
        except requests.RequestException as e:
            log.warning(f"Heartbeat failed: {e}")
            return False

    def get_pending_scans(self) -> list[dict]:
        try:
            resp = self.session.get(f"{self.api_url}/scans/pending", timeout=15)
            resp.raise_for_status()
            return resp.json().get("scans", [])
        except requests.RequestException as e:
            log.error(f"Failed to fetch pending scans: {e}")
            return []

    def ingest_results(self, scan_id: str, hosts: list[dict]) -> bool:
        """Ingest results for an active scan dispatched from the dashboard."""
        payload = {
            "agent_id":  self.agent_id,
            "scan_id":   scan_id,
            "scan_type": "active",
            "hosts":     hosts,
        }
        return self._post_ingest(payload, label=f"active scan {scan_id[:8]}…", scan_id=scan_id)

    def ingest_passive(self, hosts: list[dict]) -> bool:
        """Ingest passively discovered hosts — backend auto-creates the scan record."""
        if not hosts:
            return True
        payload = {
            "agent_id":  self.agent_id,
            "scan_type": "passive",
            "hosts":     hosts,
        }
        return self._post_ingest(payload, label=f"passive ({len(hosts)} host(s))")

    def _post_ingest(self, payload: dict, label: str, scan_id: str = None) -> bool:
        try:
            resp = self.session.post(
                f"{self.api_url}/scans/ingest",
                data=json.dumps(payload), timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(
                f"Ingested {label} — "
                f"{data.get('hosts_discovered', 0)} hosts, "
                f"{data.get('assets_upserted', 0)} assets upserted"
            )
            return True
        except requests.RequestException as e:
            log.error(f"Failed to ingest {label}: {e}")
            if scan_id:
                try:
                    self.session.post(
                        f"{self.api_url}/scans/fail",
                        data=json.dumps({"agent_id": self.agent_id, "scan_id": scan_id}),
                        timeout=10,
                    )
                except Exception:
                    pass
            return False


# ── Background threads ────────────────────────────────────────────────────────

def _heartbeat_thread(client: AgentClient, interval: int) -> None:
    log.info(f"Heartbeat thread started (interval={interval}s)")
    while True:
        time.sleep(interval)
        client.send_heartbeat()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="EagleEye network scanning agent")

    # ── Existing args (unchanged) ──
    parser.add_argument("--api-url",            default=os.getenv("EAGLEEYE_API_URL", ""),
                        help="Backend or bridge API base URL")
    parser.add_argument("--api-key",            default=os.getenv("EAGLEEYE_API_KEY", ""),
                        help="Agent API key (from dashboard)")
    parser.add_argument("--agent-id",           default=os.getenv("EAGLEEYE_AGENT_ID", ""),
                        help="Agent UUID (from dashboard)")
    parser.add_argument("--interval",           type=int,
                        default=int(os.getenv("EAGLEEYE_POLL_INTERVAL", "30")),
                        help="Active scan poll interval in seconds (default: 30)")
    parser.add_argument("--heartbeat-interval", type=int,
                        default=int(os.getenv("EAGLEEYE_HEARTBEAT_INTERVAL", "30")),
                        help="Heartbeat interval in seconds (default: 30)")

    # ── Passive scanning args (new, all optional) ──
    parser.add_argument("--passive",            action="store_true",
                        default=os.getenv("EAGLEEYE_PASSIVE", "").lower() in ("1", "true", "yes"),
                        help="Enable passive ARP sniffing (requires root/Administrator + scapy)")
    parser.add_argument("--passive-interface",  default=os.getenv("EAGLEEYE_PASSIVE_INTERFACE", ""),
                        help="Network interface for ARP sniffing (default: auto-detect)")
    parser.add_argument("--passive-interval",   type=int,
                        default=int(os.getenv("EAGLEEYE_PASSIVE_INTERVAL", "60")),
                        help="Seconds between passive discovery flushes (default: 60)")

    args = parser.parse_args()

    if not args.api_url or not args.api_key or not args.agent_id:
        parser.error("--api-url, --api-key, and --agent-id are required (or set env vars)")

    log.info(f"EagleEye Agent v{VERSION} starting")
    log.info(f"API URL      : {args.api_url}")
    log.info(f"Agent ID     : {args.agent_id}")
    log.info(f"Hostname     : {socket.gethostname()}")
    log.info(f"Gateway IP   : {_local_ip()}")
    log.info(f"Active poll  : {args.interval}s")
    log.info(f"Heartbeat    : {args.heartbeat_interval}s")
    log.info(f"Passive ARP  : {'enabled' if args.passive else 'disabled'}")

    client = AgentClient(args.api_url, args.api_key, args.agent_id)

    # Initial heartbeat so agent appears online immediately
    client.send_heartbeat()

    # Heartbeat background thread
    threading.Thread(
        target=_heartbeat_thread,
        args=(client, args.heartbeat_interval),
        daemon=True, name="heartbeat",
    ).start()

    # Passive ARP thread (only if --passive is set)
    if args.passive:
        sniffer = ArpSniffer(interface=args.passive_interface or None)
        started = sniffer.start()
        if not started:
            log.warning("Passive ARP could not start — running in active-only mode")

    # Active scan poll loop
    while True:
        try:
            pending = client.get_pending_scans()
            if pending:
                log.info(f"Found {len(pending)} pending scan(s)")
                for scan in pending:
                    scan_id   = scan.get("scan_id") or scan.get("scanId")
                    subnet    = scan.get("subnet", "192.168.1.0/24")
                    scan_type = scan.get("scan_type") or scan.get("scanType") or "active"

                    if scan_type == "passive":
                        # Passive scan: flush whatever ARP has seen so far
                        log.info(f"Processing PASSIVE scan {scan_id[:8]}… draining ARP sniffer")
                        if args.passive and 'sniffer' in dir():
                            hosts = sniffer.drain()
                            if hosts:
                                log.info(f"Flushed {len(hosts)} ARP host(s) for passive scan")
                                client.ingest_results(scan_id, hosts)
                            else:
                                log.warning(
                                    f"Passive scan {scan_id[:8]}: ARP sniffer has no hosts yet — "
                                    "wait for devices to broadcast ARP or try again later"
                                )
                        else:
                            log.warning(
                                f"Passive scan {scan_id[:8]} requested but agent is not running "
                                "in passive mode. Restart the agent with --passive to enable ARP sniffing."
                            )
                    else:
                        # Active scan: run nmap
                        log.info(f"Processing ACTIVE scan {scan_id[:8]}… subnet={subnet}")
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
