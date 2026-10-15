"""Passive network observation: ARP (host discovery), mDNS/NetBIOS-NS (hostnames and
announced services) and DHCP (device fingerprints).

ARP handling is ported from the original agent. The mDNS, NetBIOS and DHCP parsers were
rewritten in Phase C because the originals extracted nothing from real traffic: mDNS
ignored IPv6 and the additional section, NetBIOS decoded from the wrong byte, and DHCP
looked options up by number (scapy names them) and dropped every 0.0.0.0 sender.

All three need scapy and, for capture, Administrator/root plus Npcap/libpcap.

Where they listen is decided by InterfaceChooser (2.0.1): the adapter the operating
system really uses for the network, re-checked while running, never scapy's default,
which scapy picks once at start-up and can be a virtual adapter (a GNS3 KM-TEST loopback
with a default gateway was chosen over Wi-Fi). Packets from this computer's own adapters
are ignored: the computer itself is reported by its inventory.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Any, Callable, Optional


from .. import httpclient
from ..pipeline.record import HostRecord

log = logging.getLogger("eagleeye.passive")

_SNIFF_SLICE_SECONDS = 5     # sniff() is restarted this often so stop() takes effect
_IFACE_REFRESH_SECONDS = 30  # how often "automatic" re-checks which adapter to use


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    hexdigits = "".join(ch for ch in str(mac).lower() if ch in "0123456789abcdef")
    return ":".join(hexdigits[i:i + 2] for i in range(0, 12, 2)) if len(hexdigits) == 12 else None


def _probe_interfaces() -> tuple[str, list[dict[str, Any]]]:
    """(the source address the OS uses to reach the internet, every capture adapter as
    {name, description, ips, mac}). scapy's adapter list is reloaded, since it otherwise
    keeps what it read when it was first imported."""
    from scapy.all import conf  # type: ignore

    from ..netinfo import local_ip

    try:
        conf.ifaces.reload()
    except Exception as exc:  # noqa: BLE001 - an old scapy without reload keeps its list
        log.debug("could not reload the adapter list: %s", exc)
    adapters = []
    for iface in conf.ifaces.values():
        ips = list((getattr(iface, "ips", None) or {}).get(4, []) or [])
        if not ips and getattr(iface, "ip", None):
            ips = [iface.ip]
        adapters.append({"name": iface.name, "description": getattr(iface, "description", "") or iface.name,
                         "ips": ips, "mac": getattr(iface, "mac", None)})
    return local_ip(), adapters


class InterfaceChooser:
    """Which adapter passive listening uses, shared by the three sniffers.

    A fixed interface from the settings is used as it is. "Automatic" is the adapter that
    holds the address the operating system uses to reach the internet (its own route
    choice, the same one that carries the agent's traffic). It is re-checked every 30 s,
    so it follows Wi-Fi connecting after sign-in, a switch to a cable or a VPN, and it
    waits instead of listening on a wrong adapter while there is no network yet.

    It also knows the MACs of all of this computer's adapters, virtual ones included, so
    the sniffers can ignore the computer's own packets."""

    def __init__(self, fixed: Optional[str] = None,
                 probe: Callable[[], tuple[str, list[dict[str, Any]]]] = _probe_interfaces,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.fixed = fixed or None
        self._probe = probe
        self._clock = clock
        self._lock = threading.Lock()
        self._checked_at: Optional[float] = None
        self.name: Optional[str] = self.fixed
        self.label = f"{self.fixed} (set in Settings)" if self.fixed else "checking..."
        self._own_macs: frozenset[str] = frozenset()

    def refresh(self, force: bool = False) -> Optional[str]:
        """The interface to listen on now (None = no network yet: wait and ask again)."""
        with self._lock:
            now = self._clock()
            if not force and self._checked_at is not None and now - self._checked_at < _IFACE_REFRESH_SECONDS:
                return self.name
            self._checked_at = now
            try:
                route_ip, adapters = self._probe()
            except Exception as exc:  # noqa: BLE001 - keep the last good choice
                log.warning("Could not list network adapters: %s", exc)
                return self.name
            self._own_macs = frozenset(m for m in (_norm_mac(a.get("mac")) for a in adapters) if m)
            if self.fixed:
                return self.name
            match = None
            if route_ip and not route_ip.startswith("127."):
                match = next((a for a in adapters if route_ip in (a.get("ips") or [])), None)
            name = match["name"] if match else None
            label = f"{match['name']} ({route_ip})" if match else "waiting for a network connection"
            if name != self.name or label != self.label:
                log.info("Passive listening on %s", label)
            self.name, self.label = name, label
            return name

    def is_own(self, mac: Optional[str]) -> bool:
        """True for a packet sent by one of this computer's adapters."""
        m = _norm_mac(mac)
        return m is not None and m in self._own_macs


class _Sniffer:
    bpf = ""
    thread_name = "sniffer"
    label = "sniffer"

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        self.interface = interface
        self.chooser = chooser
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
        where = "automatic" if self.chooser is not None and self.chooser.fixed is None else (self.interface or "default")
        log.info("%s started (interface: %s)", self.label, where)
        return True

    def stop(self) -> None:
        self._stop.set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _own(self, mac: Optional[str]) -> bool:
        """A packet from this computer itself (ignored)."""
        return self.chooser is not None and self.chooser.is_own(mac)

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
            failed_on: Optional[str] = None
            while not self._stop.is_set():
                iface = self.chooser.refresh() if self.chooser is not None else self.interface
                if self.chooser is not None and iface is None:
                    self._stop.wait(_SNIFF_SLICE_SECONDS)          # no network yet
                    continue
                if iface:
                    kwargs["iface"] = iface
                else:
                    kwargs.pop("iface", None)
                try:
                    sniff(**kwargs)
                    failed_on = None
                except PermissionError:
                    raise
                except OSError as exc:
                    # The adapter went away (unplugged, Wi-Fi off, VPN down): wait, then
                    # let the chooser look again instead of stopping for good.
                    if failed_on != iface:
                        log.warning("%s: cannot listen on %s (%s); trying again", self.label, iface or "default", exc)
                        failed_on = iface
                    self._stop.wait(_SNIFF_SLICE_SECONDS)
                    if self.chooser is not None:
                        self.chooser.refresh(force=True)
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

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self._seen: dict[str, dict[str, Any]] = {}

    def _make_handler(self) -> Any:
        from scapy.all import ARP  # type: ignore

        def handle(pkt: Any) -> None:
            if not pkt.haslayer(ARP):
                return
            ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            if not _valid_ip(ip) or self._own(mac):
                return
            with self._lock:
                self._seen[ip] = {"mac": mac, "last_seen": time.time()}

        return handle

    def pending(self) -> int:
        """Hosts heard since the last drain."""
        with self._lock:
            return len(self._seen)

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

_MAX_SERVICES = 24
_SERVICE_SUFFIXES = ("._tcp.local", "._udp.local")


def _text(value: Any) -> str:
    """bytes or str -> str; NUL padding of fixed-width NetBIOS names becomes spaces."""
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="ignore")
    return str(value).replace("\x00", " ") if value is not None else ""


def _records(section: Any) -> list[Any]:
    """DNS records of one section. scapy >= 2.5 gives a list; older versions chain
    records through .payload."""
    if section is None:
        return []
    if isinstance(section, list):
        return section
    out, rr = [], section
    while rr is not None and hasattr(rr, "rrname"):
        out.append(rr)
        nxt = getattr(rr, "payload", None)
        rr = nxt if nxt is not None and hasattr(nxt, "rrname") else None
    return out


def _service_type(name: str) -> Optional[str]:
    """'_companion-link._tcp.local' (also from 'X._sub._googlecast._tcp.local' or an
    instance name like 'Jo's iPad._device-info._tcp.local') -> '_companion-link._tcp'."""
    name = name.rstrip(".")
    if not name.endswith(_SERVICE_SUFFIXES):
        return None
    labels = name.split(".")
    stype = f"{labels[-3]}.{labels[-2]}" if len(labels) >= 3 else None
    if not stype or not stype.startswith("_") or name.startswith("_services._dns-sd."):
        return None
    return stype


def _mac_of(pkt: Any) -> Optional[str]:
    try:
        from scapy.all import Ether  # type: ignore
        return pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
    except Exception:  # noqa: BLE001
        return None


class MdnsNetbiosSniffer(_Sniffer):
    """Learns device names and the services devices offer or look for.

    mDNS (IPv4 and IPv6): A records in the answer AND additional sections give
    ip -> name; a device announcing its own name (the A record's address is the
    sender's, or an AAAA record for the same name is) also gives mac -> name. The
    service types a device announces or queries (e.g. _companion-link._tcp, only
    used by Apple devices) are kept per sender MAC.
    NetBIOS-NS: only names a machine claims for itself count (registrations,
    refreshes, positive query responses, node-status responses), never the name
    in a query, which belongs to the machine being looked for.
    Everything accumulates; read it with get_hostname(ip) / get_mac_info(mac)."""

    bpf = "udp port 5353 or udp port 137"
    thread_name = "mdns-sniffer"
    label = "mDNS/NetBIOS sniffer"

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self._hostnames: dict[str, str] = {}             # ip -> name
        self._mdns_ips: set[str] = set()                  # ips whose name came from mDNS
        self._by_mac: dict[str, dict[str, Any]] = {}      # mac -> {mdns_name, netbios_name, services}

    # -- recording (lock held by callers) --
    def _mac_entry(self, mac: str) -> dict[str, Any]:
        return self._by_mac.setdefault(mac, {"services": set()})

    def _set_name(self, ip: str, name: str, from_mdns: bool) -> None:
        if not _valid_ip(ip) or not name:
            return
        if from_mdns:
            self._hostnames[ip] = name
            self._mdns_ips.add(ip)
        elif ip not in self._mdns_ips:            # never replace a better mDNS name
            self._hostnames[ip] = name

    @staticmethod
    def _clean_mdns(name: str) -> str:
        clean = name.rstrip(".")
        clean = clean[:-6] if clean.lower().endswith(".local") else clean
        clean = clean.split(".")[0]
        return clean if 2 <= len(clean) <= 63 else ""

    def _handle_mdns(self, dns: Any, src_ip: Optional[str], src_ip6: Optional[str], mac: Optional[str]) -> None:
        records = _records(dns.an) + _records(dns.ar)
        aaaa_by_name: dict[str, set[str]] = {}
        for rr in records:
            if getattr(rr, "type", None) == 28:
                aaaa_by_name.setdefault(_text(rr.rrname).rstrip(".").lower(), set()).add(str(rr.rdata))
        services: set[str] = set()
        with self._lock:
            for rr in records:
                rtype = getattr(rr, "type", None)
                rrname = _text(rr.rrname)
                if rtype == 1:                                     # A
                    ip = str(rr.rdata)
                    clean = self._clean_mdns(rrname)
                    if not clean or not _valid_ip(ip):
                        continue
                    self._set_name(ip, clean, from_mdns=True)
                    own = (src_ip is not None and ip == src_ip) or \
                          (src_ip6 is not None and src_ip6 in aaaa_by_name.get(rrname.rstrip(".").lower(), set()))
                    if mac and own:
                        self._mac_entry(mac)["mdns_name"] = clean
                elif rtype in (12, 33, 16):                        # PTR / SRV / TXT
                    candidates = [rrname] + ([_text(getattr(rr, "rdata", ""))] if rtype == 12 else [])
                    for candidate in candidates:
                        stype = _service_type(candidate)
                        if stype:
                            services.add(stype)
            for q in _records(getattr(dns, "qd", None)):           # what the device looks for
                stype = _service_type(_text(getattr(q, "qname", "")))
                if stype:
                    services.add(stype)
            if mac and services:
                known = self._mac_entry(mac)["services"]
                for stype in sorted(services):
                    if len(known) >= _MAX_SERVICES:
                        break
                    known.add(stype)

    def _handle_netbios(self, pkt: Any, src_ip: Optional[str], mac: Optional[str]) -> None:
        from scapy.layers.netbios import NBNSHeader  # type: ignore

        if not pkt.haslayer(NBNSHeader):
            return
        hdr = pkt[NBNSHeader]
        layer = hdr.payload
        owned: list[tuple[str, str]] = []                          # (ip, name)

        def unique_name(raw: Any, suffix: Any, group: Any) -> str:
            # Workstation <00> and server <20> names only (scapy keeps the suffix in its
            # encoded form, 0x4141 / 0x4341); group names such as WORKGROUP never.
            if group not in (0, None) or suffix not in (0x4141, 0x4341):
                return ""
            name = _text(raw).strip()
            return name if 2 <= len(name) <= 15 else ""

        kind = layer.__class__.__name__
        if kind == "NBNSRegistrationRequest" and hdr.RESPONSE == 0 and hdr.OPCODE in (5, 8, 9):
            name = unique_name(layer.QUESTION_NAME, layer.SUFFIX, getattr(layer, "G", 0))
            if name:
                owned.append((str(getattr(layer, "NB_ADDRESS", "") or src_ip or ""), name))
        elif kind == "NBNSQueryResponse" and hdr.RESPONSE == 1 and hdr.RCODE == 0:
            for entry in getattr(layer, "ADDR_ENTRY", None) or []:
                name = unique_name(layer.RR_NAME, layer.SUFFIX, getattr(entry, "G", 0))
                if name:
                    owned.append((str(entry.NB_ADDRESS), name))
        elif kind == "NBNSNodeStatusResponse" and src_ip:
            for entry in getattr(layer, "NODE_NAME", None) or []:
                if getattr(entry, "SUFFIX", None) == 0x00 and not (getattr(entry, "NAME_FLAGS", 0) & 0x80):
                    name = _text(entry.NETBIOS_NAME).strip()
                    if 2 <= len(name) <= 15:
                        owned.append((src_ip, name))
                        break
        if not owned:
            return
        with self._lock:
            for ip, name in owned:
                self._set_name(ip, name, from_mdns=False)
                if mac and ip == src_ip:
                    self._mac_entry(mac)["netbios_name"] = name

    def _make_handler(self) -> Any:
        from scapy.all import DNS, IP, UDP, IPv6  # type: ignore

        def handle(pkt: Any) -> None:
            try:
                if not pkt.haslayer(UDP):
                    return
                src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                src_ip6 = pkt[IPv6].src if pkt.haslayer(IPv6) else None
                if src_ip is not None and not _valid_ip(src_ip):
                    src_ip = None
                mac = _mac_of(pkt)
                if self._own(mac):
                    return
                ports = {pkt[UDP].sport, pkt[UDP].dport}
                if 5353 in ports and pkt.haslayer(DNS):
                    self._handle_mdns(pkt[DNS], src_ip, src_ip6, mac)
                elif 137 in ports:
                    self._handle_netbios(pkt, src_ip, mac)
            except Exception as exc:  # noqa: BLE001 - one bad packet never stops the sniffer
                log.debug("mDNS/NetBIOS packet skipped: %s", exc)

        return handle

    def get_hostname(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._hostnames.get(ip)

    def get_mac_info(self, mac: Optional[str]) -> dict[str, Any]:
        """{hostname, mdns_name, netbios_name, mdns_services} seen from this MAC."""
        if not mac:
            return {}
        with self._lock:
            entry = self._by_mac.get(mac.lower())
            if not entry:
                return {}
            out: dict[str, Any] = {k: v for k, v in entry.items() if k != "services"}
            if entry["services"]:
                out["mdns_services"] = sorted(entry["services"])
        name = out.get("mdns_name") or out.get("netbios_name")
        if name:
            out["hostname"] = name
        return out


# ── DHCP: device fingerprinting ──────────────────────────────────────────────

# scapy names the DHCP options; the original code looked them up by number.
_DHCP_OPTION_NUMBERS = {"message-type": 53, "hostname": 12, "vendor_class_id": 60,
                        "param_req_list": 55, "requested_addr": 50}


class DhcpSniffer(_Sniffer):
    """Fingerprints devices from DHCP Discover/Request packets: option 12 hostname,
    option 60 vendor class, option 55 parameter list, optionally resolved to a device
    name through Fingerbank (free key at https://fingerbank.org). It accumulates.

    A client asking for an address sends from 0.0.0.0, so packets are keyed by the
    client MAC (BOOTP chaddr); the IP comes from option 50 (requested address), the
    client address or the source, and from the server's ACK (assigned address).
    On Wi-Fi the access point may not pass other clients' DHCP to this machine."""

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

    def __init__(self, interface: Optional[str] = None, fingerbank_key: Optional[str] = None,
                 chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self.fingerbank_key = fingerbank_key
        self._info: dict[str, dict[str, Any]] = {}       # ip -> fingerprint (same dicts as _by_mac)
        self._by_mac: dict[str, dict[str, Any]] = {}     # mac -> fingerprint

    @staticmethod
    def _options(pkt: Any) -> dict[int, Any]:
        from scapy.all import DHCP  # type: ignore

        options: dict[int, Any] = {}
        for opt in pkt[DHCP].options:
            if opt == "end":
                break
            if isinstance(opt, tuple) and len(opt) >= 2:
                key = opt[0]
                num = key if isinstance(key, int) else _DHCP_OPTION_NUMBERS.get(str(key))
                if num is not None:
                    options[num] = opt[1]
        return options

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
                options = self._options(pkt)
                bootp = pkt[BOOTP]
                mac = ":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6])
                if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or self._own(mac):
                    return
                mtype = options.get(53)

                if mtype == 5:                                    # ACK: the address the server assigned
                    assigned = str(bootp.yiaddr or "")
                    if _valid_ip(assigned):
                        with self._lock:
                            entry = self._by_mac.get(mac)
                            if entry is not None:
                                self._info[assigned] = entry
                    return
                if mtype not in (1, 3):                           # client Discover/Request only
                    return

                candidates = [str(options.get(50) or ""), str(bootp.ciaddr or ""),
                              pkt[IP].src if pkt.haslayer(IP) else ""]
                ip = next((c for c in candidates if _valid_ip(c) and c != "255.255.255.255"), None)

                hostname = _decode(options.get(12, b""))
                vendor_class = _decode(options.get(60, b""))
                params = options.get(55, b"")
                if isinstance(params, (bytes, bytearray)):
                    params = list(params)
                param_list = ",".join(str(int(b)) for b in params) if isinstance(params, (list, tuple)) else ""

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
                if not entry:
                    return

                with self._lock:
                    existing = self._by_mac.setdefault(mac, {})
                    existing.update(entry)
                    if ip:
                        self._info[ip] = existing
                    already_looked_up = existing.get("fingerbank_device")

                if self.fingerbank_key and param_list and not already_looked_up:
                    threading.Thread(
                        target=self._fingerbank_lookup, args=(mac, param_list, vendor_class), daemon=True,
                    ).start()
            except Exception as exc:  # noqa: BLE001 - always non-fatal
                log.debug("DHCP packet skipped: %s", exc)

        return handle

    def _fingerbank_lookup(self, mac: str, param_list: str, vendor_class: str) -> None:
        try:
            resp = httpclient.Session().post(
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
                        info = self._by_mac.setdefault(mac, {})
                        info["fingerbank_device"] = name
                        info["fingerbank_score"] = score
                    log.debug("Fingerbank: %s -> '%s' (score=%s)", mac, name, score)
        except Exception as exc:  # noqa: BLE001
            log.debug("Fingerbank lookup failed for %s: %s", mac, exc)

    def get_info(self, ip: str) -> dict[str, Any]:
        with self._lock:
            return dict(self._info.get(ip, {}))

    def get_info_by_mac(self, mac: Optional[str]) -> dict[str, Any]:
        if not mac:
            return {}
        with self._lock:
            return dict(self._by_mac.get(mac.lower(), {}))


# ── The three together ───────────────────────────────────────────────────────

class PassiveSuite:
    """Starts and stops the three sniffers as a unit. Each one is optional: a sniffer
    that cannot start is left as None and the rest keep working."""

    def __init__(self, interface: Optional[str] = None, fingerbank_key: Optional[str] = None,
                 chooser: Optional[InterfaceChooser] = None) -> None:
        self.interface = interface
        self.fingerbank_key = fingerbank_key
        self.chooser = chooser or InterfaceChooser(interface)
        self.arp: Optional[ArpSniffer] = None
        self.mdns: Optional[MdnsNetbiosSniffer] = None
        self.dhcp: Optional[DhcpSniffer] = None

    def start(self) -> bool:
        """True when ARP discovery (the primary source) is running."""
        arp = ArpSniffer(self.interface, self.chooser)
        if arp.start():
            self.arp = arp
        else:
            log.warning("ARP sniffer could not start - passive host discovery disabled")

        mdns = MdnsNetbiosSniffer(self.interface, self.chooser)
        if mdns.start():
            self.mdns = mdns
        else:
            log.warning("mDNS/NetBIOS sniffer could not start - hostname enrichment disabled")

        dhcp = DhcpSniffer(self.interface, self.fingerbank_key or None, self.chooser)
        if dhcp.start():
            self.dhcp = dhcp
        else:
            log.warning("DHCP sniffer could not start - DHCP fingerprinting disabled")
        return self.arp is not None

    def stop(self) -> None:
        for sniffer in (self.arp, self.mdns, self.dhcp):
            if sniffer:
                sniffer.stop()

    @property
    def listening_on(self) -> str:
        """Where passive listening listens, for display (e.g. "Wi-Fi (192.168.1.20)")."""
        return self.chooser.label

    def problems(self) -> list[str]:
        """Why a sniffer is not working (for display)."""
        out = []
        for sniffer in (self.arp, self.mdns, self.dhcp):
            if sniffer and sniffer.error:
                out.append(f"{sniffer.label}: {sniffer.error}")
        return out
