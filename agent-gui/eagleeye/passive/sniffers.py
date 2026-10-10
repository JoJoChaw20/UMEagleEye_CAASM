"""Passive network observation: ARP (host discovery), mDNS/NetBIOS-NS (hostnames) and
DHCP (device fingerprints). Packet handling is ported unchanged from the original
agent; what is new is a shared base class and a clean stop().

All three need scapy and, for capture, Administrator/root plus Npcap/libpcap.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Optional

import requests

from ..pipeline.record import HostRecord

log = logging.getLogger("eagleeye.passive")

_SNIFF_SLICE_SECONDS = 5   # sniff() is restarted this often so stop() takes effect


class _Sniffer:
    bpf = ""
    thread_name = "sniffer"
    label = "sniffer"

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.error: Optional[str] = None

    def _make_handler(self) -> Any:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def start(self) -> bool:
        try:
            import scapy.all  # noqa: F401
        except ImportError:
            log.warning("scapy not installed - %s disabled. Run: pip install scapy", self.label)
            self.error = "scapy not installed"
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name=self.thread_name)
        self._thread.start()
        log.info("%s started on interface=%s", self.label, self.interface or "default")
        return True

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        try:
            from scapy.all import sniff  # type: ignore

            kwargs: dict[str, Any] = {
                "filter": self.bpf,
                "prn": self._make_handler(),
                "store": False,
                "stop_filter": lambda _pkt: self._stop.is_set(),
                "timeout": _SNIFF_SLICE_SECONDS,
            }
            if self.interface:
                kwargs["iface"] = self.interface
            while not self._stop.is_set():
                sniff(**kwargs)
        except PermissionError:
            self.error = "requires Administrator/root"
            log.error("%s requires Administrator/root - stopped", self.label)
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
            log.error("%s error: %s", self.label, exc)


def _valid_ip(ip: Optional[str]) -> bool:
    return bool(ip) and not ip.startswith("0.") and ip != "0.0.0.0"


# ── ARP: primary host discovery ──────────────────────────────────────────────

class ArpSniffer(_Sniffer):
    """Records ip -> {mac, last_seen} for every host seen ARPing on the segment."""

    bpf = "arp"
    thread_name = "arp-sniffer"
    label = "ARP sniffer"

    def __init__(self, interface: Optional[str] = None) -> None:
        super().__init__(interface)
        self._seen: dict[str, dict[str, Any]] = {}

    def _make_handler(self) -> Any:
        from scapy.all import ARP  # type: ignore

        def handle(pkt: Any) -> None:
            if not pkt.haslayer(ARP):
                return
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            if not _valid_ip(ip):
                return
            with self._lock:
                self._seen[ip] = {"mac": mac, "last_seen": time.time()}

        return handle

    def drain(self) -> list[HostRecord]:
        """Snapshot of discovered hosts (with best-effort reverse DNS); clears the buffer."""
        with self._lock:
            snapshot = dict(self._seen)
            self._seen.clear()

        hosts = []
        for ip, info in snapshot.items():
            hostname: Optional[str] = None
            try:
                name = socket.gethostbyaddr(ip)[0]
                hostname = name if name != ip else None
            except (socket.herror, socket.gaierror, OSError):
                pass
            hosts.append(HostRecord(ip=ip, hostname=hostname, mac=info["mac"]))
        return hosts


# ── mDNS + NetBIOS-NS: hostname enrichment ───────────────────────────────────

class MdnsNetbiosSniffer(_Sniffer):
    """Builds a continuous ip -> hostname map from mDNS A records (devices announce
    "<name>.local") and NetBIOS name-service packets (Windows "DESKTOP-XXXXX").
    It accumulates; use get_hostname() to peek."""

    bpf = "udp port 5353 or udp port 137"
    thread_name = "mdns-sniffer"
    label = "mDNS/NetBIOS sniffer"

    def __init__(self, interface: Optional[str] = None) -> None:
        super().__init__(interface)
        self._hostnames: dict[str, str] = {}

    def _make_handler(self) -> Any:
        from scapy.all import DNS, DNSRR, IP  # type: ignore

        def handle(pkt: Any) -> None:
            try:
                if not pkt.haslayer(IP):
                    return
                src_ip = pkt[IP].src
                if not _valid_ip(src_ip):
                    return

                # mDNS: DNS A-record answers
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
                                    if name and _valid_ip(ip):
                                        clean = name.replace(".local", "").split(".")[0]
                                        if clean and 2 <= len(clean) <= 63:
                                            with self._lock:
                                                self._hostnames[ip] = clean
                                except Exception:  # noqa: BLE001
                                    pass
                            rr = rr.payload if hasattr(rr, "payload") and isinstance(rr.payload, DNSRR) else None

                # NetBIOS-NS: nibble-encoded name from UDP 137
                else:
                    try:
                        raw = bytes(pkt[IP].payload)           # includes the 8-byte UDP header
                        udp_payload = raw[8:] if len(raw) > 8 else b""
                        if len(udp_payload) >= 34:
                            encoded = udp_payload[12:42]
                            decoded = ""
                            for i in range(0, min(len(encoded) - 1, 30), 2):
                                hi = encoded[i] - 0x41
                                lo = encoded[i + 1] - 0x41
                                c = chr((hi << 4) | lo)
                                if c == " ":                   # padding
                                    break
                                if c.isprintable():
                                    decoded += c
                            decoded = decoded.strip()
                            if decoded and 2 <= len(decoded) <= 20:
                                with self._lock:
                                    # never replace a better mDNS name
                                    if src_ip not in self._hostnames:
                                        self._hostnames[src_ip] = decoded
                    except Exception:  # noqa: BLE001
                        pass
            except Exception:  # noqa: BLE001
                pass

        return handle

    def get_hostname(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._hostnames.get(ip)


# ── DHCP: device fingerprinting ──────────────────────────────────────────────

class DhcpSniffer(_Sniffer):
    """Fingerprints devices from DHCP Discover/Request packets: option 12 hostname,
    option 60 vendor class, option 55 parameter list, optionally resolved to a device
    name through Fingerbank (free key at https://fingerbank.org). It accumulates."""

    bpf = "udp port 67 or udp port 68"
    thread_name = "dhcp-sniffer"
    label = "DHCP fingerprint sniffer"

    _VENDOR_HINTS: dict[str, str] = {
        "MSFT":     "Windows",
        "android":  "Android",
        "dhcpcd":   "Linux",
        "udhcp":    "Linux/Embedded",
        "OpenBSD":  "OpenBSD",
        "FreeBSD":  "FreeBSD",
        "Cisco":    "Cisco Network Device",
        "Aruba":    "Aruba Network Device",
        "Ubiquiti": "Ubiquiti Device",
        "ArubaOS":  "Aruba AP",
        "Apple":    "Apple Device",
        "iPhone":   "Apple iPhone",
        "iPad":     "Apple iPad",
    }

    def __init__(self, interface: Optional[str] = None, fingerbank_key: Optional[str] = None) -> None:
        super().__init__(interface)
        self.fingerbank_key = fingerbank_key
        self._info: dict[str, dict[str, Any]] = {}

    def _make_handler(self) -> Any:
        from scapy.all import BOOTP, DHCP, IP  # type: ignore

        def _decode(v: Any) -> str:
            if isinstance(v, (bytes, bytearray)):
                return v.decode("ascii", errors="ignore").strip()
            return str(v).strip() if v else ""

        def handle(pkt: Any) -> None:
            try:
                if not pkt.haslayer(BOOTP) or not pkt.haslayer(DHCP):
                    return

                options: dict[int, Any] = {}
                for opt in pkt[DHCP].options:
                    if opt == "end":
                        break
                    if isinstance(opt, tuple) and len(opt) == 2:
                        options[int(opt[0]) if not isinstance(opt[0], int) else opt[0]] = opt[1]

                if options.get(53) not in (1, 3):       # client Discover/Request only
                    return

                ip: Optional[str] = pkt[IP].src if pkt.haslayer(IP) else None
                if not ip or ip in ("0.0.0.0", "255.255.255.255"):
                    return

                hostname = _decode(options.get(12, b""))
                vendor_class = _decode(options.get(60, b""))
                param_bytes = options.get(55, b"")
                param_list = ",".join(
                    str(b) for b in (param_bytes if isinstance(param_bytes, (bytes, bytearray)) else b"")
                )

                vendor_hint: Optional[str] = None
                for prefix, label in self._VENDOR_HINTS.items():
                    if vendor_class.startswith(prefix):
                        vendor_hint = label
                        break

                entry: dict[str, Any] = {}
                if hostname:
                    entry["dhcp_hostname"] = hostname
                if vendor_class:
                    entry["dhcp_vendor_class"] = vendor_class
                if vendor_hint:
                    entry["dhcp_device_hint"] = vendor_hint
                if param_list:
                    entry["dhcp_param_list"] = param_list

                if entry:
                    with self._lock:
                        existing = self._info.get(ip, {})
                        existing.update(entry)
                        self._info[ip] = existing
                        already_looked_up = existing.get("fingerbank_device")

                    if self.fingerbank_key and param_list and not already_looked_up:
                        threading.Thread(
                            target=self._fingerbank_lookup, args=(ip, param_list, vendor_class), daemon=True,
                        ).start()
            except Exception:  # noqa: BLE001 - always non-fatal
                pass

        return handle

    def _fingerbank_lookup(self, ip: str, param_list: str, vendor_class: str) -> None:
        try:
            resp = requests.post(
                "https://api.fingerbank.org/api/v2/combinations/interrogate",
                params={"key": self.fingerbank_key},
                json={"dhcp_fingerprint": param_list, "vendor_class_identifier": vendor_class},
                timeout=8,
            )
            if resp.ok:
                data = resp.json()
                name = data.get("device", {}).get("name")
                score = data.get("score", 0)
                if name and score >= 30:                # only trust reasonably confident matches
                    with self._lock:
                        info = self._info.get(ip, {})
                        info["fingerbank_device"] = name
                        info["fingerbank_score"] = score
                        self._info[ip] = info
                    log.debug("Fingerbank: %s -> '%s' (score=%s)", ip, name, score)
        except Exception as exc:  # noqa: BLE001
            log.debug("Fingerbank lookup failed for %s: %s", ip, exc)

    def get_info(self, ip: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._info.get(ip, {}))


# ── The three together ───────────────────────────────────────────────────────

class PassiveSuite:
    """Starts and stops the three sniffers as a unit. Each one is optional: a sniffer
    that cannot start is left as None and the rest keep working."""

    def __init__(self, interface: Optional[str] = None, fingerbank_key: Optional[str] = None) -> None:
        self.interface = interface
        self.fingerbank_key = fingerbank_key
        self.arp: Optional[ArpSniffer] = None
        self.mdns: Optional[MdnsNetbiosSniffer] = None
        self.dhcp: Optional[DhcpSniffer] = None

    def start(self) -> bool:
        """True when ARP discovery (the primary source) is running."""
        arp = ArpSniffer(self.interface)
        if arp.start():
            self.arp = arp
        else:
            log.warning("ARP sniffer could not start - passive host discovery disabled")

        mdns = MdnsNetbiosSniffer(self.interface)
        if mdns.start():
            self.mdns = mdns
        else:
            log.warning("mDNS/NetBIOS sniffer could not start - hostname enrichment disabled")

        dhcp = DhcpSniffer(self.interface, self.fingerbank_key or None)
        if dhcp.start():
            self.dhcp = dhcp
        else:
            log.warning("DHCP sniffer could not start - DHCP fingerprinting disabled")
        return self.arp is not None

    def stop(self) -> None:
        for sniffer in (self.arp, self.mdns, self.dhcp):
            if sniffer:
                sniffer.stop()

    def problems(self) -> list[str]:
        """Why a sniffer is not working (for display)."""
        out = []
        for sniffer in (self.arp, self.mdns, self.dhcp):
            if sniffer and sniffer.error:
                out.append(f"{sniffer.label}: {sniffer.error}")
        return out
