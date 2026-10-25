"""Passive network observation: ARP and broadcast/multicast senders (host discovery),
mDNS/NetBIOS-NS (hostnames and announced services), DHCP (device fingerprints) and
SSDP/UPnP (what smart TVs, media boxes, printers and routers say they are).

ARP handling is ported from the original agent. The mDNS, NetBIOS and DHCP parsers were
rewritten in Phase C because the originals extracted nothing from real traffic: mDNS
ignored IPv6 and the additional section, NetBIOS decoded from the wrong byte, and DHCP
looked options up by number (scapy names them) and dropped every 0.0.0.0 sender.

All of them need scapy and, for capture, Administrator/root plus Npcap/libpcap.

Where they listen is decided by InterfaceChooser (2.0.1): the adapter the operating
system really uses for the network, re-checked while running, never scapy's default,
which scapy picks once at start-up and can be a virtual adapter (a GNS3 KM-TEST loopback
with a default gateway was chosen over Wi-Fi). Packets from this computer's own adapters
are ignored: the computer itself is reported by its inventory.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from typing import Any, Callable, Optional


from .. import httpclient
from ..pipeline.record import HostRecord

log = logging.getLogger("eagleeye.passive")

_SNIFF_SLICE_SECONDS = 5     # sniff() is restarted this often so stop() takes effect
_IFACE_REFRESH_SECONDS = 30  # how often "automatic" re-checks which adapter to use
# How long what the enrichment sniffers heard is kept. An address-keyed entry expires
# sooner: DHCP hands a free address to another device, which must not inherit the old
# owner's name. MAC-keyed entries belong to the device, and only expire to bound memory.
_IP_TTL_SECONDS = 4 * 3600
_MAC_TTL_SECONDS = 24 * 3600
_PRUNE_EVERY_SECONDS = 600
_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")


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
    the sniffers can ignore the computer's own packets, and the network the adapter is on
    ({local_ip, subnet, gateway_ip}): hosts are tagged with it when heard, so a batch
    heard before a move to another network is uploaded with the network it came from,
    and addresses outside the subnet (a laptop announcing the hotspot address it just
    left) are not taken for hosts of this one."""

    def __init__(self, fixed: Optional[str] = None,
                 probe: Callable[[], tuple[str, list[dict[str, Any]]]] = _probe_interfaces,
                 clock: Callable[[], float] = time.monotonic,
                 network_of: Optional[Callable[[str], dict[str, Optional[str]]]] = None) -> None:
        self.fixed = fixed or None
        self._probe = probe
        self._clock = clock
        self._network_of = network_of or _local_network
        self._lock = threading.Lock()
        self._checked_at: Optional[float] = None
        self.name: Optional[str] = self.fixed
        self.label = f"{self.fixed} (set in Settings)" if self.fixed else "checking..."
        self._own_macs: frozenset[str] = frozenset()
        # Replaced (never changed in place) when the network changes, so a host's tag
        # keeps describing the network it was heard on.
        self.network: Optional[dict[str, Optional[str]]] = None
        self._net: Optional[ipaddress.IPv4Network] = None

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
                fixed = next((a for a in adapters if a.get("name") == self.fixed), None)
                ips = [ip for ip in (fixed or {}).get("ips") or [] if not ip.startswith(("127.", "169.254."))]
                self._set_network(ips[0] if ips else None)
                return self.name
            match = None
            if route_ip and not route_ip.startswith("127."):
                match = next((a for a in adapters if route_ip in (a.get("ips") or [])), None)
            name = match["name"] if match else None
            label = f"{match['name']} ({route_ip})" if match else "waiting for a network connection"
            if name != self.name or label != self.label:
                log.info("Passive listening on %s", label)
            self.name, self.label = name, label
            self._set_network(route_ip if match else None)
            return name

    def _set_network(self, ip: Optional[str]) -> None:
        """Look up the network of `ip` (lock held); log and replace it when it changed."""
        network: Optional[dict[str, Optional[str]]] = None
        if ip:
            try:
                network = dict(self._network_of(ip))
            except Exception as exc:  # noqa: BLE001 - keep the last good answer
                log.debug("Could not read the network of %s: %s", ip, exc)
                return
        if network == self.network:
            return
        self.network = network
        try:
            self._net = ipaddress.ip_network(network["subnet"], strict=False) if network and network.get("subnet") else None
        except ValueError:
            self._net = None
        if network:
            log.info("Network: subnet %s, gateway %s", network.get("subnet") or "unknown",
                     network.get("gateway_ip") or "unknown")

    def accepts(self, ip: str) -> bool:
        """False for an address that cannot be a host of the network listened on: a
        self-assigned 169.254.x.x, or one outside the subnet (when it is known)."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            return False
        if addr in _LINK_LOCAL:
            return False
        net = self._net
        return net is None or addr in net

    def is_own(self, mac: Optional[str]) -> bool:
        """True for a packet sent by one of this computer's adapters."""
        m = _norm_mac(mac)
        return m is not None and m in self._own_macs


def _local_network(ip: str) -> dict[str, Optional[str]]:
    from ..netinfo import local_network
    return local_network(ip)


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
        self._clock: Callable[[], float] = time.time
        self._pruned_at = 0.0

    def _make_handler(self) -> Any:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def _maybe_prune(self) -> None:
        """Drop expired entries every few minutes (lock held by the caller)."""
        now = self._clock()
        if now - self._pruned_at >= _PRUNE_EVERY_SECONDS:
            self._pruned_at = now
            self._prune(now)

    def _prune(self, now: float) -> None:
        """Remove what is older than its TTL; sniffers that keep nothing do nothing."""

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


def _is_multicast_mac(mac: str) -> bool:
    try:
        return bool(int(mac.split(":")[0], 16) & 1)
    except (ValueError, IndexError):
        return True


# ── ARP + broadcast/multicast: primary host discovery ────────────────────────

class ArpSniffer(_Sniffer):
    """Records ip -> {mac, last_seen} for every host heard on the segment: its ARP, and
    any IPv4 broadcast or multicast it sends (mDNS, NetBIOS, SSDP, LLMNR, ...).

    ARP alone hears almost nothing on a quiet Wi-Fi network: devices keep their ARP
    caches warm, so in practice only the router ARPs, and everything else appeared only
    after an active scan made it answer. Broadcast and multicast never leave the segment,
    so their sender is a neighbour, and the frame's source MAC is the sender's own."""

    bpf = "arp or (ip and (ether broadcast or ether multicast))"
    thread_name = "arp-sniffer"
    label = "ARP/broadcast sniffer"

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self._seen: dict[str, dict[str, Any]] = {}

    def _make_handler(self) -> Any:
        from scapy.all import ARP, IP, Ether  # type: ignore

        def handle(pkt: Any) -> None:
            if pkt.haslayer(ARP):
                ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
            elif pkt.haslayer(IP) and pkt.haslayer(Ether):
                ip, mac = pkt[IP].src, pkt[Ether].src.lower()
                if ip == "255.255.255.255" or _is_multicast_mac(mac):
                    return
            else:
                return
            if not _valid_ip(ip) or self._own(mac):
                return
            if self.chooser is not None and not self.chooser.accepts(ip):
                return                      # 169.254.x.x, or an address from another network
            network = self.chooser.network if self.chooser is not None else None
            with self._lock:
                self._seen[ip] = {"mac": mac, "last_seen": time.time(), "network": network}

        return handle

    def pending(self) -> int:
        """Hosts heard since the last drain."""
        with self._lock:
            return len(self._seen)

    def drain_batches(self) -> list[tuple[Optional[dict[str, Optional[str]]], list[HostRecord]]]:
        """What was heard since the last drain, one batch per network it was heard on
        (oldest network first), as (network, hosts); clears the buffer. Names are added
        later by the enrichment stage."""
        with self._lock:
            snapshot = dict(self._seen)
            self._seen.clear()
        batches: dict[int, tuple[Optional[dict[str, Optional[str]]], list[HostRecord]]] = {}
        for ip, info in snapshot.items():
            network = info.get("network")
            key = id(network)                       # one dict per network (see InterfaceChooser)
            batches.setdefault(key, (network, []))[1].append(HostRecord(ip=ip, mac=info["mac"]))
        return list(batches.values())

    def drain(self) -> list[HostRecord]:
        """Every host heard since the last drain, whatever network; clears the buffer."""
        return [host for _network, hosts in self.drain_batches() for host in hosts]

    def restore(self, network: Optional[dict[str, Optional[str]]], hosts: list[HostRecord]) -> None:
        """Put hosts whose upload failed back, for the next flush. A host heard again
        meanwhile keeps its newer entry."""
        with self._lock:
            for host in hosts:
                if host.ip not in self._seen:
                    self._seen[host.ip] = {"mac": host.mac, "last_seen": time.time(), "network": network}


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
    Read it with get_hostname(ip) / get_mac_info(mac). It accumulates, but an address's
    name expires after 4 hours without being heard again (the address may have gone to
    another device) and a device's entry after 24 hours."""

    bpf = "udp port 5353 or udp port 137"
    thread_name = "mdns-sniffer"
    label = "mDNS/NetBIOS sniffer"

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self._hostnames: dict[str, tuple[str, bool, float]] = {}   # ip -> (name, from mDNS, heard at)
        self._by_mac: dict[str, dict[str, Any]] = {}      # mac -> {mdns_name, netbios_name, services, _t}

    # -- recording (lock held by callers) --
    def _mac_entry(self, mac: str) -> dict[str, Any]:
        entry = self._by_mac.setdefault(mac, {"services": set(), "offered": set()})
        entry["_t"] = self._clock()
        self._maybe_prune()
        return entry

    def _set_name(self, ip: str, name: str, from_mdns: bool) -> None:
        if not _valid_ip(ip) or not name:
            return
        now = self._clock()
        current = self._hostnames.get(ip)
        fresh = current is not None and now - current[2] < _IP_TTL_SECONDS
        if from_mdns or not (fresh and current[1]):         # never replace a live mDNS name
            self._hostnames[ip] = (name, from_mdns, now)
        self._maybe_prune()

    def _prune(self, now: float) -> None:
        self._hostnames = {ip: v for ip, v in self._hostnames.items() if now - v[2] < _IP_TTL_SECONDS}
        self._by_mac = {m: e for m, e in self._by_mac.items() if now - e.get("_t", now) < _MAC_TTL_SECONDS}

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
        offered: set[str] = set()          # in the device's own answers: it provides them
        is_answer = bool(getattr(dns, "qr", 0))
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
                            if is_answer:
                                offered.add(stype)
            for q in _records(getattr(dns, "qd", None)):           # what the device looks for
                stype = _service_type(_text(getattr(q, "qname", "")))
                if stype:
                    services.add(stype)
            if mac and services:
                entry = self._mac_entry(mac)
                for key, found in (("services", services), ("offered", offered)):
                    known = entry[key]
                    for stype in sorted(found):
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
            entry = self._hostnames.get(ip)
            if entry is None or self._clock() - entry[2] >= _IP_TTL_SECONDS:
                return None
            return entry[0]

    def name_source(self, ip: str) -> Optional[str]:
        """'mdns' or 'netbios' for the name get_hostname(ip) gives."""
        with self._lock:
            entry = self._hostnames.get(ip)
            if entry is None or self._clock() - entry[2] >= _IP_TTL_SECONDS:
                return None
            return "mdns" if entry[1] else "netbios"

    def get_mac_info(self, mac: Optional[str]) -> dict[str, Any]:
        """{hostname, mdns_name, netbios_name, mdns_services, mdns_offered} seen from this
        MAC. mdns_services: every service type it announced or looked for; mdns_offered:
        only the ones it announced (a phone looking for a Chromecast is not one)."""
        if not mac:
            return {}
        with self._lock:
            entry = self._by_mac.get(mac.lower())
            if not entry or self._clock() - entry.get("_t", 0) >= _MAC_TTL_SECONDS:
                return {}
            out: dict[str, Any] = {k: v for k, v in entry.items() if k not in ("services", "offered", "_t")}
            if entry["services"]:
                out["mdns_services"] = sorted(entry["services"])
            if entry.get("offered"):
                out["mdns_offered"] = sorted(entry["offered"])
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
        self._info_t: dict[str, float] = {}              # ip -> when it was linked to that fingerprint
        self._by_mac: dict[str, dict[str, Any]] = {}     # mac -> fingerprint (with _t: last heard)

    def _link_ip(self, ip: str, entry: dict[str, Any]) -> None:
        """Record that `ip` belongs to the device of `entry` (lock held)."""
        self._info[ip] = entry
        self._info_t[ip] = self._clock()
        self._maybe_prune()

    def _prune(self, now: float) -> None:
        self._info_t = {ip: t for ip, t in self._info_t.items() if now - t < _IP_TTL_SECONDS}
        self._info = {ip: e for ip, e in self._info.items() if ip in self._info_t}
        self._by_mac = {m: e for m, e in self._by_mac.items() if now - e.get("_t", now) < _MAC_TTL_SECONDS}

    @staticmethod
    def _public(entry: Optional[dict[str, Any]]) -> dict[str, Any]:
        return {k: v for k, v in (entry or {}).items() if k != "_t"}

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
            # UTF-8 first: a device named in Chinese, Malay or any accented language
            # sends its DHCP name that way, and reading it as ASCII dropped those
            # characters. Bytes that are not UTF-8 are read as Latin-1, never lost.
            if isinstance(v, (bytes, bytearray)):
                raw = bytes(v).replace(b"\x00", b"")
                try:
                    return raw.decode("utf-8").strip()
                except UnicodeDecodeError:
                    return raw.decode("latin-1").strip()
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
                                self._link_ip(assigned, entry)
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
                    existing["_t"] = self._clock()
                    if ip:
                        self._link_ip(ip, existing)
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
            if self._clock() - self._info_t.get(ip, float("-inf")) >= _IP_TTL_SECONDS:
                return {}
            return self._public(self._info.get(ip))

    def get_info_by_mac(self, mac: Optional[str]) -> dict[str, Any]:
        if not mac:
            return {}
        with self._lock:
            entry = self._by_mac.get(mac.lower())
            if not entry or self._clock() - entry.get("_t", 0) >= _MAC_TTL_SECONDS:
                return {}
            return self._public(entry)


# ── SSDP / UPnP: what devices say they are ─────────────────────────────────────

_SSDP_MAX_TYPES = 16
_SSDP_MAX_SERVER = 200


def _ssdp_type(value: str) -> Optional[str]:
    """'urn:schemas-upnp-org:device:MediaRenderer:1' -> 'device:MediaRenderer:1',
    'urn:dial-multiscreen-org:service:dial:1' -> 'dial-multiscreen-org:service:dial:1'.
    Instance ids (uuid:...) and the generic upnp:rootdevice say nothing and are dropped."""
    v = value.strip()
    low = v.lower()
    if not v or low.startswith("uuid:") or low == "upnp:rootdevice" or low == "ssdp:all":
        return None
    if low.startswith("urn:schemas-upnp-org:"):
        v = v[len("urn:schemas-upnp-org:"):]
    elif low.startswith("urn:"):
        v = v[4:]
    return v[:80] or None


def parse_ssdp(payload: bytes) -> Optional[tuple[str, dict[str, str]]]:
    """('notify' | 'response' | 'search', lower-case headers) of one SSDP message."""
    text = payload.decode("utf-8", errors="ignore")
    lines = text.replace("\r\n", "\n").split("\n")
    start = lines[0].strip().upper() if lines else ""
    if start.startswith("NOTIFY"):
        kind = "notify"
    elif start.startswith("HTTP/1.1 200") or start.startswith("HTTP/1.0 200"):
        kind = "response"
    elif start.startswith("M-SEARCH"):
        kind = "search"
    else:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers.setdefault(key.strip().lower(), value.strip())
    return kind, headers


class SsdpSniffer(_Sniffer):
    """Learns what UPnP devices are from SSDP (UDP 1900): the announcements they multicast
    every few minutes (NOTIFY) and their answers to this computer's own searches, which
    Windows sends regularly. Kept per sender MAC:
      ssdp_server  the SERVER header, e.g. "Linux/4.4 UPnP/1.0 Samsung TV" or "miniupnpd/2.1"
      ssdp_types   the device and service types it provides, e.g. device:MediaRenderer:1
    Searches (M-SEARCH) are ignored: what a device looks for is not what it is.
    Nothing is fetched from the devices; only what they broadcast is read."""

    bpf = "udp port 1900"
    thread_name = "ssdp-sniffer"
    label = "SSDP/UPnP sniffer"

    def __init__(self, interface: Optional[str] = None, chooser: Optional[InterfaceChooser] = None) -> None:
        super().__init__(interface, chooser)
        self._by_mac: dict[str, dict[str, Any]] = {}
        self._mac_by_ip: dict[str, tuple[str, float]] = {}     # ip -> (mac, heard at)

    def _record(self, mac: str, ip: Optional[str], headers: dict[str, str], type_header: str) -> None:
        with self._lock:
            now = self._clock()
            entry = self._by_mac.setdefault(mac, {"types": set()})
            entry["_t"] = now
            server = headers.get("server", "")
            if server and "ssdp_server" not in entry:
                entry["ssdp_server"] = server[:_SSDP_MAX_SERVER]
            stype = _ssdp_type(headers.get(type_header, ""))
            if stype and len(entry["types"]) < _SSDP_MAX_TYPES:
                entry["types"].add(stype)
            if ip and _valid_ip(ip):
                self._mac_by_ip[ip] = (mac, now)
            self._maybe_prune()

    def _prune(self, now: float) -> None:
        self._mac_by_ip = {ip: v for ip, v in self._mac_by_ip.items() if now - v[1] < _IP_TTL_SECONDS}
        self._by_mac = {m: e for m, e in self._by_mac.items() if now - e.get("_t", now) < _MAC_TTL_SECONDS}

    def _make_handler(self) -> Any:
        from scapy.all import IP, UDP  # type: ignore

        def handle(pkt: Any) -> None:
            try:
                if not pkt.haslayer(UDP):
                    return
                mac = _mac_of(pkt)
                if not mac or self._own(mac):
                    return
                parsed = parse_ssdp(bytes(pkt[UDP].payload))
                if not parsed:
                    return
                kind, headers = parsed
                if kind == "search":
                    return
                ip = pkt[IP].src if pkt.haslayer(IP) else None
                self._record(mac, ip, headers, "nt" if kind == "notify" else "st")
            except Exception as exc:  # noqa: BLE001 - one bad packet never stops the sniffer
                log.debug("SSDP packet skipped: %s", exc)

        return handle

    def get_mac_info(self, mac: Optional[str]) -> dict[str, Any]:
        """{ssdp_server, ssdp_types} seen from this MAC."""
        if not mac:
            return {}
        with self._lock:
            entry = self._by_mac.get(mac.lower())
            if not entry or self._clock() - entry.get("_t", 0) >= _MAC_TTL_SECONDS:
                return {}
            out: dict[str, Any] = {k: v for k, v in entry.items() if k not in ("types", "_t")}
            if entry["types"]:
                out["ssdp_types"] = sorted(entry["types"])
        return out

    def get_info(self, ip: str) -> dict[str, Any]:
        with self._lock:
            found = self._mac_by_ip.get(ip)
            mac = found[0] if found and self._clock() - found[1] < _IP_TTL_SECONDS else None
        return self.get_mac_info(mac)


# ── Reverse DNS: the last resort for a name ──────────────────────────────────

_RDNS_TTL_SECONDS = 3600
_RDNS_WORKERS = 16
_RDNS_BUDGET_SECONDS = 3.0


def _gethostbyaddr(ip: str) -> Optional[str]:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None
    return name if name and name != ip else None


class ReverseDnsCache:
    """Reverse DNS (PTR) names, asked only for hosts no sniffer named.

    On an office LAN the DNS server knows domain-joined PCs, servers, switches and
    printers that never announce themselves over mDNS or NetBIOS. Where no PTR records
    exist (a campus Wi-Fi), each lookup waits for a timeout of several seconds: asked one
    by one, 45 hosts took over six minutes per flush. So lookups run in parallel, a flush
    waits at most a few seconds for them (an answer that comes later is kept for the next
    flush), and every answer, found or not, is remembered for an hour."""

    def __init__(self, lookup: Callable[[str], Optional[str]] = _gethostbyaddr,
                 ttl: float = _RDNS_TTL_SECONDS, budget: float = _RDNS_BUDGET_SECONDS,
                 workers: int = _RDNS_WORKERS, clock: Callable[[], float] = time.monotonic) -> None:
        self._lookup = lookup
        self._ttl = ttl
        self._budget = budget
        self._clock = clock
        self._lock = threading.RLock()       # a done lookup runs its callback right away
        self._cache: dict[str, tuple[Optional[str], float]] = {}    # ip -> (name or None, answered at)
        self._inflight: dict[str, Future[Optional[str]]] = {}
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")

    def _store(self, ip: str, fut: Future[Optional[str]]) -> None:
        try:
            name = fut.result()
        except Exception:  # noqa: BLE001
            name = None
        with self._lock:
            self._cache[ip] = (name, self._clock())
            self._inflight.pop(ip, None)

    def resolve(self, ips: list[str]) -> dict[str, Optional[str]]:
        """ip -> name for the addresses answered within the time budget (None = no name)."""
        now = self._clock()
        out: dict[str, Optional[str]] = {}
        waiting: list[Future[Optional[str]]] = []
        with self._lock:
            self._cache = {ip: v for ip, v in self._cache.items() if now - v[1] < self._ttl}
            for ip in dict.fromkeys(ips):
                if ip in self._cache:
                    out[ip] = self._cache[ip][0]
                    continue
                fut = self._inflight.get(ip)
                if fut is None:
                    try:
                        fut = self._pool.submit(self._lookup, ip)
                    except RuntimeError:                    # shut down
                        continue
                    self._inflight[ip] = fut
                    fut.add_done_callback(lambda f, ip=ip: self._store(ip, f))
                waiting.append(fut)
        if waiting:
            wait(waiting, timeout=self._budget)
        with self._lock:
            for ip in ips:
                if ip not in out and ip in self._cache:
                    out[ip] = self._cache[ip][0]
        return out

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


# ── All of them together ─────────────────────────────────────────────────────

class PassiveSuite:
    """Starts and stops the sniffers as a unit. Each one is optional: a sniffer that
    cannot start is left as None and the rest keep working."""

    def __init__(self, interface: Optional[str] = None, fingerbank_key: Optional[str] = None,
                 chooser: Optional[InterfaceChooser] = None) -> None:
        self.interface = interface
        self.fingerbank_key = fingerbank_key
        self.chooser = chooser or InterfaceChooser(interface)
        self.arp: Optional[ArpSniffer] = None
        self.mdns: Optional[MdnsNetbiosSniffer] = None
        self.dhcp: Optional[DhcpSniffer] = None
        self.ssdp: Optional[SsdpSniffer] = None
        self.rdns = ReverseDnsCache()

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

        ssdp = SsdpSniffer(self.interface, self.chooser)
        if ssdp.start():
            self.ssdp = ssdp
        else:
            log.warning("SSDP sniffer could not start - UPnP device details disabled")
        return self.arp is not None

    def stop(self) -> None:
        for sniffer in (self.arp, self.mdns, self.dhcp, self.ssdp):
            if sniffer:
                sniffer.stop()
        self.rdns.shutdown()

    @property
    def listening_on(self) -> str:
        """Where passive listening listens, for display (e.g. "Wi-Fi (192.168.1.20)")."""
        return self.chooser.label

    def problems(self) -> list[str]:
        """Why a sniffer is not working (for display)."""
        out = []
        for sniffer in (self.arp, self.mdns, self.dhcp, self.ssdp):
            if sniffer and sniffer.error:
                out.append(f"{sniffer.label}: {sniffer.error}")
        return out
