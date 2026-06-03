#!/usr/bin/env python3
"""
EagleEye Agent v1.3.0 — active + passive network scanner for UMEagleEye CAASM platform.

Active mode  : polls the backend for pending scans, runs Nmap (with NSE scripts for
               richer OS/service identification), and POSTs results.

Passive mode : runs three parallel sniffers — ARP (host discovery), mDNS/NetBIOS-NS
               (hostname resolution), DHCP (device fingerprinting) — all non-blocking
               daemon threads with separate BPF filters.  Discovered hosts are enriched
               and ingested every --passive-interval seconds.

Merge priority (never downgrades existing data):
  hostname : mDNS/NetBIOS > DHCP option-12 > reverse-DNS
  os hint  : Fingerbank device > DHCP vendor class hint (merged additive, never replace)

Usage:
    python eagleeye_agent.py \\
        --api-url https://umeagleeye-api.syntaxch404.workers.dev/api/v1 \\
        --api-key <key-from-dashboard> \\
        --agent-id <uuid-from-dashboard>

    # With full passive suite enabled:
    python eagleeye_agent.py \\
        --api-url ... --api-key ... --agent-id ... \\
        --passive [--passive-interface eth0] [--passive-interval 60] \\
        [--fingerbank-key <free-key-from-fingerbank.org>]

Or via environment variables:
    EAGLEEYE_API_URL, EAGLEEYE_API_KEY, EAGLEEYE_AGENT_ID,
    EAGLEEYE_POLL_INTERVAL, EAGLEEYE_HEARTBEAT_INTERVAL,
    EAGLEEYE_PASSIVE, EAGLEEYE_PASSIVE_INTERFACE, EAGLEEYE_PASSIVE_INTERVAL,
    EAGLEEYE_FINGERBANK_KEY
"""

import argparse
import json
import logging
import os
import platform
import re
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

VERSION = "1.3.0"


# ── Active scanning: Nmap + NSE scripts ──────────────────────────────────────

def _parse_smb_os_discovery(script_output: str) -> dict:
    """Extract OS/hostname fields from the smb-os-discovery NSE script output."""
    result: dict[str, str] = {}
    if not script_output:
        return result
    for line in script_output.splitlines():
        line = line.strip()
        if line.startswith("OS:"):
            result["name"] = line[3:].strip()
        elif line.startswith("Computer name:"):
            result["smb_computer_name"] = line[14:].strip()
        elif line.startswith("Domain name:"):
            result["smb_domain"] = line[12:].strip()
        elif line.startswith("FQDN:"):
            result["smb_fqdn"] = line[5:].strip()
    return result


def run_nmap(subnet: str) -> list[dict[str, Any]]:
    """
    Run nmap -sV + NSE scripts on subnet; return list of host dicts.

    Enhancements over previous version:
    - Port 139/445 added → enables smb-os-discovery (Windows exact version)
    - --script smb-os-discovery → most accurate Windows OS name via SMB
    - --script banner → raw service banner for any open port
    - --script-timeout 10s → scripts never block the whole scan
    - SMB computer name promoted to hostname when nmap DNS has nothing
    """
    log.info(f"Running nmap on {subnet}")
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        nm.scan(
            hosts=subnet,
            arguments=(
                "-sV -T4 --open "
                "-p 22,23,80,139,161,443,445,3389,8080,8443,3306,5432,6379,27017 "
                "--script smb-os-discovery,banner "
                "--script-timeout 10s"
            ),
        )
        hosts = []
        for ip in nm.all_hosts():
            host = nm[ip]
            if host.state() != "up":
                continue

            ports = []
            for proto in host.all_protocols():
                for port_num, port_info in host[proto].items():
                    if port_info.get("state") == "open":
                        port_entry: dict[str, Any] = {
                            "port":     port_num,
                            "protocol": proto,
                            "service":  port_info.get("name", ""),
                            "version":  port_info.get("version", ""),
                            "product":  port_info.get("product", ""),
                        }
                        # Attach raw banner (truncated) when available
                        script_out = port_info.get("script", {})
                        if "banner" in script_out:
                            port_entry["banner"] = script_out["banner"][:200]
                        ports.append(port_entry)

            # OS info: smb-os-discovery (most accurate) → nmap osmatch fallback
            os_info: dict[str, Any] = {}
            smb_script = (
                host.get("tcp", {}).get(445, {}).get("script", {}).get("smb-os-discovery")
                or host.get("tcp", {}).get(139, {}).get("script", {}).get("smb-os-discovery")
            )
            if smb_script:
                os_info = _parse_smb_os_discovery(smb_script)
                log.debug(f"SMB OS for {ip}: {os_info.get('name', '?')}")
            elif "osmatch" in host and host["osmatch"]:
                best = host["osmatch"][0]
                os_info = {
                    "name":     best.get("name", ""),
                    "accuracy": best.get("accuracy", ""),
                }

            # Hostname: SMB computer name (most reliable) → nmap reverse-DNS
            # DNS is skipped when it returns Docker-internal artefacts
            smb_computer_name = os_info.get("smb_computer_name") or None
            dns_hostname = host.hostname() or None
            if dns_hostname and ("docker.internal" in dns_hostname or dns_hostname.startswith("docker")):
                dns_hostname = None
            hostname = smb_computer_name or dns_hostname

            hosts.append({
                "ip":       ip,
                "hostname": hostname,
                "mac":      host.get("addresses", {}).get("mac") or None,
                "ports":    ports,
                "os":       os_info or None,
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
        for ip_match in re.finditer(r'addr="([\d.]+)"', result.stdout):
            ip = ip_match.group(1)
            if not ip.startswith("0."):
                hosts.append({"ip": ip, "hostname": None, "mac": None, "ports": [], "os": None})
        log.info(f"Ping sweep found {len(hosts)} hosts")
        return hosts
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error(f"nmap not available: {e}")
        return []


# ── Passive scanning: ARP (primary host discovery) ────────────────────────────

class ArpSniffer:
    """
    Listens for ARP requests/replies — primary host discovery mechanism.
    Records ip → {mac, last_seen} for every host seen on the segment.

    BPF filter: "arp"
    Thread:     arp-sniffer (daemon)
    Requires:   scapy + root/Administrator
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface
        self._lock = threading.Lock()
        self._seen: dict[str, dict[str, Any]] = {}  # ip → {mac, last_seen}

    def start(self) -> bool:
        try:
            from scapy.all import sniff, ARP  # type: ignore  # noqa: F401
        except ImportError:
            log.warning("scapy not installed — passive ARP disabled. Run: pip install scapy")
            return False
        t = threading.Thread(target=self._sniff_loop, daemon=True, name="arp-sniffer")
        t.start()
        log.info(f"ARP sniffer started on interface={self.interface or 'default'}")
        return True

    def _sniff_loop(self) -> None:
        try:
            from scapy.all import sniff, ARP  # type: ignore

            def handle(pkt: Any) -> None:
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
            sniff(**kwargs)
        except PermissionError:
            log.error("ARP sniffer requires root/Administrator — stopped")
        except Exception as exc:
            log.error(f"ARP sniffer error: {exc}")

    def drain(self) -> list[dict[str, Any]]:
        """Return snapshot of discovered hosts (with best-effort reverse DNS) and clear buffer."""
        with self._lock:
            snapshot = dict(self._seen)
            self._seen.clear()

        hosts = []
        for ip, info in snapshot.items():
            hostname: Optional[str] = None
            try:
                result = socket.gethostbyaddr(ip)
                hostname = result[0] if result[0] != ip else None
            except (socket.herror, socket.gaierror, OSError):
                pass
            hosts.append({
                "ip":       ip,
                "mac":      info["mac"],
                "hostname": hostname,
                "ports":    [],
                "os":       None,
            })
        return hosts


# ── Passive scanning: mDNS + NetBIOS-NS (hostname enrichment) ────────────────

class MdnsNetbiosSniffer:
    """
    Listens for mDNS (UDP 5353) and NetBIOS Name Service (UDP 137) announcements
    to build a continuous ip → hostname map.

    mDNS  : parses DNS A-record answers from multicast packets.
             Devices announce themselves as "<name>.local" when joining the network.
    NetBIOS: parses NBNS registration/query packets and decodes the nibble-encoded name.
             Windows machines announce as "DESKTOP-XXXXX" or their NetBIOS name.

    This sniffer ACCUMULATES — it never fully clears.  Use get_hostname() to peek.
    BPF filter: "udp port 5353 or udp port 137"
    Thread:     mdns-sniffer (daemon)
    Requires:   scapy + root/Administrator
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface
        self._lock = threading.Lock()
        self._hostnames: dict[str, str] = {}  # ip → hostname

    def start(self) -> bool:
        try:
            from scapy.all import sniff, DNS  # type: ignore  # noqa: F401
        except ImportError:
            log.warning("scapy not available — mDNS/NetBIOS sniffer disabled")
            return False
        t = threading.Thread(target=self._sniff_loop, daemon=True, name="mdns-sniffer")
        t.start()
        log.info(f"mDNS/NetBIOS sniffer started on interface={self.interface or 'default'}")
        return True

    def _sniff_loop(self) -> None:
        try:
            from scapy.all import sniff, DNS, DNSRR, IP  # type: ignore

            def handle(pkt: Any) -> None:
                try:
                    if not pkt.haslayer(IP):
                        return
                    src_ip = pkt[IP].src
                    if not src_ip or src_ip.startswith("0.") or src_ip == "0.0.0.0":
                        return

                    # ── mDNS: parse DNS A-record answers (dst port 5353) ──
                    if pkt.haslayer(DNS):
                        dns = pkt[DNS]
                        if dns.ancount and dns.an:
                            rr = dns.an
                            while rr:
                                if hasattr(rr, "type") and rr.type == 1:  # A record
                                    try:
                                        raw_name = rr.rrname
                                        name = (raw_name.decode() if isinstance(raw_name, bytes) else raw_name).rstrip(".")
                                        rdata = rr.rdata
                                        ip = rdata if isinstance(rdata, str) else str(rdata)
                                        if name and ip and not ip.startswith("0.") and ip != "0.0.0.0":
                                            # Strip .local, keep first label as clean hostname
                                            clean = name.replace(".local", "").split(".")[0]
                                            if clean and 2 <= len(clean) <= 63:
                                                with self._lock:
                                                    self._hostnames[ip] = clean
                                    except Exception:
                                        pass
                                rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None

                    # ── NetBIOS-NS: decode nibble-encoded name from UDP 137 ──
                    else:
                        try:
                            raw = bytes(pkt[IP].payload)  # includes UDP header (8 bytes)
                            udp_payload = raw[8:] if len(raw) > 8 else b""
                            # NBNS encoded name starts at offset 12 in NBNS payload
                            # Each character encoded as two nibble bytes + 0x41 bias
                            if len(udp_payload) >= 34:
                                encoded = udp_payload[12:42]
                                decoded = ""
                                for i in range(0, min(len(encoded) - 1, 30), 2):
                                    hi = encoded[i] - 0x41
                                    lo = encoded[i + 1] - 0x41
                                    c = chr((hi << 4) | lo)
                                    if c == " ":  # padding — stop here
                                        break
                                    if c.isprintable():
                                        decoded += c
                                decoded = decoded.strip()
                                if decoded and 2 <= len(decoded) <= 20:
                                    with self._lock:
                                        # Only record if we don't already have a better mDNS name
                                        if src_ip not in self._hostnames:
                                            self._hostnames[src_ip] = decoded
                        except Exception:
                            pass
                except Exception:
                    pass

            kwargs: dict[str, Any] = {
                "filter": "udp port 5353 or udp port 137",
                "prn":    handle,
                "store":  False,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            sniff(**kwargs)
        except PermissionError:
            log.error("mDNS/NetBIOS sniffer requires root/Administrator — stopped")
        except Exception as exc:
            log.error(f"mDNS/NetBIOS sniffer error: {exc}")

    def get_hostname(self, ip: str) -> Optional[str]:
        """Return best known hostname for ip (non-destructive peek)."""
        with self._lock:
            return self._hostnames.get(ip)


# ── Passive scanning: DHCP fingerprinting ─────────────────────────────────────

class DhcpSniffer:
    """
    Listens for DHCP Discover/Request packets (UDP 67/68) to fingerprint devices.

    Per-IP data collected:
    - dhcp_hostname     : DHCP option 12 (client-supplied hostname — very reliable)
    - dhcp_vendor_class : DHCP option 60 (e.g. "MSFT 5.0"=Windows, "android-dhcp-13"=Android)
    - dhcp_device_hint  : Human-readable label derived from vendor class prefix
    - dhcp_param_list   : DHCP option 55 as CSV string (used for Fingerbank)
    - fingerbank_device : Device name from Fingerbank API (only if key is configured)
    - fingerbank_score  : Confidence score from Fingerbank (0-100)

    Fingerbank is OPTIONAL — if no key is set, hostname + vendor class alone add
    significant classification signal.  Free key at: https://fingerbank.org

    This sniffer ACCUMULATES — it never fully clears.  Use get_info() to peek.
    BPF filter: "udp port 67 or udp port 68"
    Thread:     dhcp-sniffer (daemon)
    Requires:   scapy + root/Administrator
    """

    # Known vendor class prefixes → human-readable label
    _VENDOR_HINTS: dict[str, str] = {
        "MSFT":          "Windows",
        "android":       "Android",
        "dhcpcd":        "Linux",
        "udhcp":         "Linux/Embedded",
        "OpenBSD":       "OpenBSD",
        "FreeBSD":       "FreeBSD",
        "Cisco":         "Cisco Network Device",
        "Aruba":         "Aruba Network Device",
        "Ubiquiti":      "Ubiquiti Device",
        "ArubaOS":       "Aruba AP",
        "Apple":         "Apple Device",
        "iPhone":        "Apple iPhone",
        "iPad":          "Apple iPad",
    }

    def __init__(
        self,
        interface: Optional[str] = None,
        fingerbank_key: Optional[str] = None,
    ) -> None:
        self.interface      = interface
        self.fingerbank_key = fingerbank_key
        self._lock          = threading.Lock()
        self._info: dict[str, dict[str, Any]] = {}  # ip → fingerprint info

    def start(self) -> bool:
        try:
            from scapy.all import sniff, BOOTP, DHCP  # type: ignore  # noqa: F401
        except ImportError:
            log.warning("scapy not available — DHCP fingerprint sniffer disabled")
            return False
        t = threading.Thread(target=self._sniff_loop, daemon=True, name="dhcp-sniffer")
        t.start()
        log.info(f"DHCP fingerprint sniffer started on interface={self.interface or 'default'}")
        return True

    def _sniff_loop(self) -> None:
        try:
            from scapy.all import sniff, BOOTP, DHCP, IP  # type: ignore

            def handle(pkt: Any) -> None:
                try:
                    if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
                        return

                    dhcp = pkt[DHCP]

                    # Parse DHCP options into a dict
                    options: dict[int, Any] = {}
                    for opt in dhcp.options:
                        if opt == "end":
                            break
                        if isinstance(opt, tuple) and len(opt) == 2:
                            options[int(opt[0]) if not isinstance(opt[0], int) else opt[0]] = opt[1]

                    # Only process DHCP Discover (1) and Request (3) — client-side only
                    msg_type = options.get(53)
                    if msg_type not in (1, 3):
                        return

                    # Client IP from IP layer
                    ip: Optional[str] = None
                    if pkt.haslayer(IP):
                        ip = pkt[IP].src
                    if not ip or ip in ("0.0.0.0", "255.255.255.255"):
                        return

                    # Extract option values, decode bytes → str
                    def _decode(v: Any) -> str:
                        if isinstance(v, (bytes, bytearray)):
                            return v.decode("ascii", errors="ignore").strip()
                        return str(v).strip() if v else ""

                    hostname     = _decode(options.get(12, b""))
                    vendor_class = _decode(options.get(60, b""))
                    param_bytes  = options.get(55, b"")
                    param_list   = ",".join(str(b) for b in (param_bytes if isinstance(param_bytes, (bytes, bytearray)) else b""))

                    # Map vendor class prefix to a human-readable label
                    vendor_hint: Optional[str] = None
                    for prefix, label in self._VENDOR_HINTS.items():
                        if vendor_class.startswith(prefix):
                            vendor_hint = label
                            break

                    entry: dict[str, Any] = {}
                    if hostname:
                        entry["dhcp_hostname"]     = hostname
                    if vendor_class:
                        entry["dhcp_vendor_class"] = vendor_class
                    if vendor_hint:
                        entry["dhcp_device_hint"]  = vendor_hint
                    if param_list:
                        entry["dhcp_param_list"]   = param_list

                    if entry:
                        with self._lock:
                            existing = self._info.get(ip, {})
                            existing.update(entry)
                            self._info[ip] = existing

                        # Fingerbank lookup in a separate daemon thread (non-blocking)
                        already_looked_up = self._info.get(ip, {}).get("fingerbank_device")
                        if self.fingerbank_key and param_list and not already_looked_up:
                            threading.Thread(
                                target=self._fingerbank_lookup,
                                args=(ip, param_list, vendor_class),
                                daemon=True,
                            ).start()

                except Exception:
                    pass  # always non-fatal

            kwargs: dict[str, Any] = {
                "filter": "udp port 67 or udp port 68",
                "prn":    handle,
                "store":  False,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            sniff(**kwargs)

        except PermissionError:
            log.error("DHCP sniffer requires root/Administrator — stopped")
        except Exception as exc:
            log.error(f"DHCP sniffer error: {exc}")

    def _fingerbank_lookup(self, ip: str, param_list: str, vendor_class: str) -> None:
        """POST to Fingerbank API; store device type result when confident."""
        try:
            resp = requests.post(
                "https://api.fingerbank.org/api/v2/combinations/interrogate",
                params={"key": self.fingerbank_key},
                json={"dhcp_fingerprint": param_list, "vendor_class_identifier": vendor_class},
                timeout=8,
            )
            if resp.ok:
                data   = resp.json()
                device = data.get("device", {})
                name   = device.get("name")
                score  = data.get("score", 0)
                if name and score >= 30:  # only trust reasonably confident matches
                    with self._lock:
                        info = self._info.get(ip, {})
                        info["fingerbank_device"] = name
                        info["fingerbank_score"]  = score
                        self._info[ip] = info
                    log.debug(f"Fingerbank: {ip} → '{name}' (score={score})")
        except Exception as e:
            log.debug(f"Fingerbank lookup failed for {ip}: {e}")  # non-fatal

    def get_info(self, ip: str) -> dict[str, Any]:
        """Return DHCP fingerprint info for ip (non-destructive peek)."""
        with self._lock:
            return dict(self._info.get(ip, {}))


# ── Host enrichment ───────────────────────────────────────────────────────────

def enrich_passive_hosts(
    hosts: list[dict[str, Any]],
    mdns_sniffer:  Optional[MdnsNetbiosSniffer],
    dhcp_sniffer:  Optional[DhcpSniffer],
) -> list[dict[str, Any]]:
    """
    Enrich ARP-discovered hosts with mDNS/NetBIOS hostname and DHCP fingerprint.

    Priority rules — can only ADD or IMPROVE, never downgrade:
      hostname : mDNS/NetBIOS > DHCP option-12 > existing reverse-DNS (already in host)
      os dict  : DHCP fingerprint fields merged additively; active-scan nmap fields win
    """
    for host in hosts:
        ip = host["ip"]

        # ── Hostname: best available source ──
        mdns_name = mdns_sniffer.get_hostname(ip) if mdns_sniffer else None
        dhcp_info = dhcp_sniffer.get_info(ip)      if dhcp_sniffer else {}
        dhcp_name = dhcp_info.get("dhcp_hostname")

        # mDNS/NetBIOS is most accurate (device self-announces),
        # then DHCP option-12, then keep the reverse-DNS already in host
        best_hostname = mdns_name or dhcp_name or host.get("hostname")
        host["hostname"] = best_hostname

        # ── OS / device hint: merge DHCP data additively ──
        if dhcp_info:
            existing_os = host.get("os") or {}
            merged_os   = dict(existing_os) if isinstance(existing_os, dict) else {}
            # Active-scan (nmap) fields take priority — only fill keys that are absent
            for k, v in dhcp_info.items():
                if k not in merged_os and k != "dhcp_hostname":
                    merged_os[k] = v
            host["os"] = merged_os if merged_os else None

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
        for attempt in range(2):
            try:
                resp = self.session.post(
                    f"{self.api_url}/agents/{self.agent_id}/heartbeat",
                    data=json.dumps(payload), timeout=15,
                )
                resp.raise_for_status()
                return True
            except requests.RequestException as e:
                if attempt == 0:
                    time.sleep(5)  # brief pause before retry
                else:
                    log.warning(f"Heartbeat failed: {e}")
        return False

    def get_pending_scans(self) -> list[dict]:
        try:
            resp = self.session.get(f"{self.api_url}/scans/pending", timeout=30)
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

    def ingest_passive(self, hosts: list[dict], scan_id: Optional[str] = None) -> bool:
        """Ingest passively discovered hosts.
        If scan_id is given (dashboard-triggered), links results to that record.
        If scan_id is None (autonomous flush), backend auto-creates the scan record.
        Empty hosts with a scan_id still POSTs so the dashboard record is closed as Completed(0).
        """
        if not hosts and not scan_id:
            return True  # autonomous flush: nothing new — skip silently
        payload: dict = {
            "agent_id":  self.agent_id,
            "scan_type": "passive",
            "hosts":     hosts,
        }
        if scan_id:
            payload["scan_id"] = scan_id
        label = f"passive scan {scan_id[:8]}…" if scan_id else f"passive ({len(hosts)} host(s))"
        return self._post_ingest(payload, label=label)

    def ingest_sbom(self, scan_id: str, sbom_json: dict) -> bool:
        """POST a CycloneDX SBOM JSON to the /sboms/ingest endpoint."""
        payload = {
            "agent_id": self.agent_id,
            "scan_id":  scan_id,
            "sbom":     sbom_json,
        }
        try:
            resp = self.session.post(
                f"{self.api_url}/sboms/ingest",
                data=json.dumps(payload), timeout=300,
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(f"SBOM ingested — sbom_id={data.get('sbom_id', '?')}, "
                     f"{data.get('dependencies_inserted', 0)} dependencies")
            return True
        except requests.RequestException as e:
            log.error(f"Failed to ingest SBOM: {e}")
            return False

    def ingest_cve_findings(self, scan_id: str, findings: list[dict]) -> bool:
        """POST Grype CVE findings to /sboms/ingest-cve for alert generation."""
        payload = {
            "agent_id": self.agent_id,
            "scan_id":  scan_id,
            "findings": findings,
        }
        try:
            resp = self.session.post(
                f"{self.api_url}/sboms/ingest-cve",
                data=json.dumps(payload), timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            log.info(f"CVE findings ingested — {data.get('events_created', 0)} new alerts, "
                     f"{data.get('events_updated', 0)} updated")
            return True
        except requests.RequestException as e:
            log.error(f"Failed to ingest CVE findings: {e}")
            return False

    def _post_ingest(self, payload: dict, label: str, scan_id: Optional[str] = None) -> bool:
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



# ── SBOM scanning via Syft ────────────────────────────────────────────────────

def run_cve_scan(scan_id: str, sbom_json: dict, client: AgentClient) -> None:
    """Run Grype against the SBOM JSON and POST findings for alert generation."""
    import tempfile
    log.info(f"Starting CVE scan (scan_id={scan_id})")
    sbom_tmp: Optional[str] = None
    out_tmp:  Optional[str] = None
    try:
        # Write SBOM as UTF-8 bytes — avoids Windows pipe encoding issues
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".json", delete=False) as f:
            f.write(json.dumps(sbom_json).encode("utf-8"))
            sbom_tmp = f.name

        # Pre-create output file so we can open it as a binary write handle
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_tmp = f.name

        # Redirect stdout directly to a binary file — bypasses Windows cp1252 pipe encoding
        with open(out_tmp, "wb") as out_fh:
            result = subprocess.run(
                ["grype", f"sbom:{sbom_tmp}", "-o", "json", "--quiet"],
                stdout=out_fh,
                stderr=subprocess.PIPE,
                timeout=300,
            )

        # Grype exits 1 when vulnerabilities are found — that is normal
        if result.returncode not in (0, 1):
            log.warning(f"Grype exited {result.returncode}: {result.stderr.decode('utf-8', errors='replace')[:500]}")
            return

        with open(out_tmp, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        matches = data.get("matches", [])

        findings = []
        for match in matches:
            vuln     = match.get("vulnerability", {})
            artifact = match.get("artifact", {})

            cvss_score = 0.0
            for cvss in vuln.get("cvss", []):
                score = cvss.get("metrics", {}).get("baseScore", 0)
                if score > cvss_score:
                    cvss_score = score

            findings.append({
                "cve_id":          vuln.get("id", ""),
                "severity":        vuln.get("severity", "Unknown"),
                "description":     vuln.get("description", "")[:500],
                "cvss_base_score": cvss_score,
                "package_name":    artifact.get("name", ""),
                "package_version": artifact.get("version", ""),
                "fix_versions":    vuln.get("fix", {}).get("versions", []),
                "cwe_ids":         [],
            })

        log.info(f"Grype found {len(findings)} vulnerabilities")
        if findings:
            client.ingest_cve_findings(scan_id, findings)
        else:
            log.info("No vulnerabilities found — no alerts generated")

    except FileNotFoundError:
        log.warning("grype not found — CVE scanning skipped. "
                    "Install: winget install Anchore.Grype  (Windows) "
                    "or: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh")
    except subprocess.TimeoutExpired:
        log.error("Grype scan timed out (>300 s)")
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse Grype output: {e}")
    except Exception as e:
        log.error(f"CVE scan error: {e}", exc_info=True)
    finally:
        for path in (sbom_tmp, out_tmp):
            if path and os.path.exists(path):
                os.unlink(path)


def run_sbom_scan(scan: dict, client: AgentClient) -> None:
    """Run Syft on this machine to generate a CycloneDX SBOM, then POST it."""
    scan_id  = scan.get("scan_id") or scan.get("scanId")
    raw      = scan.get("raw_results") or scan.get("rawResults") or []

    # Optional Syft target hint embedded in the scan record
    target: Optional[str] = None
    if isinstance(raw, list) and raw and isinstance(raw[0], dict):
        target = raw[0].get("target")

    if not target:
        target = "dir:C:\\FYP\\UMEagleEye2.0" if platform.system() == "Windows" else "dir:/usr"

    log.info(f"Starting SBOM scan (scan_id={scan_id}) — target={target}")
    success = False
    sbom_json: Optional[dict] = None
    syft_out_tmp: Optional[str] = None
    try:
        import tempfile as _tf
        with _tf.NamedTemporaryFile(suffix=".json", delete=False) as f:
            syft_out_tmp = f.name

        # Redirect stdout to a binary file — avoids Windows cp1252 pipe encoding crash
        with open(syft_out_tmp, "wb") as out_fh:
            result = subprocess.run(
                ["syft", target, "-o", "cyclonedx-json"],
                stdout=out_fh,
                stderr=subprocess.PIPE,
                timeout=600,
            )
        if result.returncode != 0:
            log.error(f"Syft exited {result.returncode}: {result.stderr.decode('utf-8', errors='replace')[:500]}")
        else:
            with open(syft_out_tmp, "r", encoding="utf-8", errors="replace") as f:
                sbom_json = json.load(f)
            success = client.ingest_sbom(scan_id, sbom_json)
    except FileNotFoundError:
        log.error("syft not found — install with: winget install Anchore.Syft  (Windows) "
                  "or: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh  (Linux/macOS)")
    except subprocess.TimeoutExpired:
        log.error("Syft scan timed out (>600 s)")
    except json.JSONDecodeError as e:
        log.error(f"Failed to parse Syft output as JSON: {e}")
    except Exception as e:
        log.error(f"SBOM scan error: {e}", exc_info=True)
    finally:
        if syft_out_tmp and os.path.exists(syft_out_tmp):
            os.unlink(syft_out_tmp)
        if not success and scan_id:
            try:
                client.session.post(
                    f"{client.api_url}/scans/fail",
                    data=json.dumps({"agent_id": client.agent_id, "scan_id": scan_id}),
                    timeout=10,
                )
                log.info(f"SBOM scan {scan_id[:8]}… marked as failed")
            except Exception:
                pass

    # Run CVE correlation immediately after successful SBOM ingest
    if success and sbom_json and scan_id:
        run_cve_scan(scan_id, sbom_json, client)


# ── Background threads ────────────────────────────────────────────────────────

def _heartbeat_thread(client: AgentClient, interval: int) -> None:
    log.info(f"Heartbeat thread started (interval={interval}s)")
    while True:
        time.sleep(interval)
        client.send_heartbeat()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"EagleEye network scanning agent v{VERSION}"
    )

    parser.add_argument("--api-url",            default=os.getenv("EAGLEEYE_API_URL", ""),
                        help="Backend API base URL")
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

    # Passive sniffing
    parser.add_argument("--passive",            action="store_true",
                        default=os.getenv("EAGLEEYE_PASSIVE", "").lower() in ("1", "true", "yes"),
                        help="Enable passive sniffing suite: ARP + mDNS/NetBIOS + DHCP")
    parser.add_argument("--passive-interface",  default=os.getenv("EAGLEEYE_PASSIVE_INTERFACE", ""),
                        help="Network interface for all passive sniffers (default: auto)")
    parser.add_argument("--passive-interval",   type=int,
                        default=int(os.getenv("EAGLEEYE_PASSIVE_INTERVAL", "60")),
                        help="Seconds between passive flush cycles (default: 60)")
    parser.add_argument("--fingerbank-key",     default=os.getenv("EAGLEEYE_FINGERBANK_KEY", ""),
                        help="Fingerbank API key for DHCP device fingerprinting (optional, free at fingerbank.org)")

    args = parser.parse_args()

    if not args.api_url or not args.api_key or not args.agent_id:
        parser.error("--api-url, --api-key, and --agent-id are required (or set env vars)")

    iface = args.passive_interface or None

    log.info(f"EagleEye Agent v{VERSION} starting")
    log.info(f"API URL      : {args.api_url}")
    log.info(f"Agent ID     : {args.agent_id}")
    log.info(f"Hostname     : {socket.gethostname()}")
    log.info(f"Gateway IP   : {_local_ip()}")
    log.info(f"Active poll  : {args.interval}s")
    log.info(f"Heartbeat    : {args.heartbeat_interval}s")
    log.info(f"Passive mode : {'enabled' if args.passive else 'disabled'}")
    if args.passive:
        log.info(f"  Interface  : {iface or 'auto'}")
        log.info(f"  Interval   : {args.passive_interval}s")
        log.info(f"  Fingerbank : {'enabled' if args.fingerbank_key else 'disabled (set --fingerbank-key to enable)'}")

    client = AgentClient(args.api_url, args.api_key, args.agent_id)
    client.send_heartbeat()

    # Heartbeat background thread
    threading.Thread(
        target=_heartbeat_thread,
        args=(client, args.heartbeat_interval),
        daemon=True, name="heartbeat",
    ).start()

    # Passive sniffers — all optional, all non-fatal if unavailable
    arp_sniffer:  Optional[ArpSniffer]          = None
    mdns_sniffer: Optional[MdnsNetbiosSniffer]  = None
    dhcp_sniffer: Optional[DhcpSniffer]         = None

    if args.passive:
        arp_sniffer = ArpSniffer(interface=iface)
        if not arp_sniffer.start():
            log.warning("ARP sniffer could not start — passive host discovery disabled")
            arp_sniffer = None

        mdns_sniffer = MdnsNetbiosSniffer(interface=iface)
        if not mdns_sniffer.start():
            log.warning("mDNS/NetBIOS sniffer could not start — hostname enrichment disabled")
            mdns_sniffer = None

        dhcp_sniffer = DhcpSniffer(
            interface=iface,
            fingerbank_key=args.fingerbank_key or None,
        )
        if not dhcp_sniffer.start():
            log.warning("DHCP sniffer could not start — DHCP fingerprinting disabled")
            dhcp_sniffer = None

    # ── Main loop ──
    # Initialise flush timer so the first autonomous flush fires after one full interval
    last_passive_flush = time.time()

    while True:
        try:
            pending = client.get_pending_scans()
            if pending:
                log.info(f"Found {len(pending)} pending scan(s)")
                for scan in pending:
                    scan_id   = scan.get("scan_id") or scan.get("scanId")
                    subnet    = scan.get("subnet", "192.168.1.0/24")
                    scan_type = scan.get("scan_type") or scan.get("scanType") or "active"
                    status    = scan.get("status", "pending")
                    if status == "cancelled":
                        log.info(f"Skipping cancelled scan {scan_id[:8] if scan_id else '?'}…")
                        continue

                    if scan_type == "passive":
                        log.info(f"Processing PASSIVE scan {scan_id[:8]}… draining sniffers")
                        if arp_sniffer:
                            hosts = arp_sniffer.drain()
                            hosts = enrich_passive_hosts(hosts, mdns_sniffer, dhcp_sniffer)
                            if hosts:
                                log.info(f"Flushed {len(hosts)} enriched host(s) for passive scan")
                            else:
                                log.info(
                                    f"Passive scan {scan_id[:8]}: ARP buffer empty "
                                    "(autonomous flush ran recently) — completing with 0 hosts"
                                )
                            # Always POST so the dashboard record closes as Completed, not Failed.
                            # ingest_passive handles empty hosts gracefully when scan_id is set.
                            client.ingest_passive(hosts, scan_id=scan_id)
                            if hosts:
                                last_passive_flush = time.time()  # reset autonomous timer only when data flushed
                        else:
                            log.warning(
                                f"Passive scan {scan_id[:8]}: agent not in passive mode — "
                                "marking as failed. Restart with --passive to enable sniffing."
                            )
                            try:
                                client.session.post(
                                    f"{client.api_url}/scans/fail",
                                    data=json.dumps({"agent_id": client.agent_id, "scan_id": scan_id}),
                                    timeout=10,
                                )
                            except Exception:
                                pass
                    elif scan_type == "sbom":
                        log.info(f"Processing SBOM scan {scan_id[:8]}…")
                        run_sbom_scan(scan, client)
                    else:
                        # Active scan: run nmap with enhanced NSE scripts
                        log.info(f"Processing ACTIVE scan {scan_id[:8]}… subnet={subnet}")
                        hosts = run_nmap(subnet)
                        client.ingest_results(scan_id, hosts)
            else:
                log.debug("No pending scans")

            # ── Autonomous periodic passive flush ──────────────────────────────
            # Runs every --passive-interval seconds regardless of dashboard triggers.
            # Backend auto-creates a scan record for each flush (no scan_id needed).
            if args.passive and arp_sniffer:
                elapsed = time.time() - last_passive_flush
                if elapsed >= args.passive_interval:
                    hosts = arp_sniffer.drain()
                    if hosts:
                        hosts = enrich_passive_hosts(hosts, mdns_sniffer, dhcp_sniffer)
                        log.info(
                            f"[AUTO] Flushing {len(hosts)} passive host(s) "
                            f"(interval={args.passive_interval}s)"
                        )
                        client.ingest_passive(hosts)
                    else:
                        log.debug("[AUTO] Passive flush: ARP buffer empty, nothing to ingest")
                    last_passive_flush = time.time()

        except KeyboardInterrupt:
            log.info("Shutting down")
            sys.exit(0)
        except Exception as e:
            log.error(f"Unexpected error: {e}", exc_info=True)

        time.sleep(args.interval)


if __name__ == "__main__":
    main()
