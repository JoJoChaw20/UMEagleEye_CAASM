"""One device over SNMP: what it is, its ports and addresses, and what it knows about the network
(ARP, routes, MAC table, CDP/LLDP neighbours).

Standard MIBs first (MIB-II, IF-MIB, IP-MIB, IP-FORWARD-MIB, BRIDGE-MIB, Q-BRIDGE-MIB, LLDP-MIB);
Cisco's own where the standard ones are missing on Cisco (CDP, VTP VLANs, trunk state, access
VLAN, the VLAN of a routed subinterface, one MAC table per VLAN).
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from ..engine.udp import ENTERPRISES
from .snmp import Oid, SnmpAuthError, SnmpError, to_oid

# ── OIDs ──
SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME = (to_oid("1.3.6.1.2.1.1.1.0"), to_oid("1.3.6.1.2.1.1.2.0"),
                                                  to_oid("1.3.6.1.2.1.1.3.0"), to_oid("1.3.6.1.2.1.1.5.0"))
IF_DESCR, IF_PHYS, IF_OPER = to_oid("1.3.6.1.2.1.2.2.1.2"), to_oid("1.3.6.1.2.1.2.2.1.6"), to_oid("1.3.6.1.2.1.2.2.1.8")
IF_NAME, IF_ALIAS = to_oid("1.3.6.1.2.1.31.1.1.1.1"), to_oid("1.3.6.1.2.1.31.1.1.1.18")
IP_AD_IFINDEX, IP_AD_MASK = to_oid("1.3.6.1.2.1.4.20.1.2"), to_oid("1.3.6.1.2.1.4.20.1.3")
NET_TO_MEDIA = to_oid("1.3.6.1.2.1.4.22.1.2")                     # ipNetToMediaPhysAddress
NET_TO_PHYS = to_oid("1.3.6.1.2.1.4.35.1.4")                      # ipNetToPhysicalPhysAddress
CIDR_ROUTE_IFINDEX, CIDR_ROUTE_TYPE = to_oid("1.3.6.1.2.1.4.24.4.1.5"), to_oid("1.3.6.1.2.1.4.24.4.1.6")
IP_ROUTE_IFINDEX, IP_ROUTE_NEXTHOP, IP_ROUTE_MASK = (to_oid("1.3.6.1.2.1.4.21.1.2"), to_oid("1.3.6.1.2.1.4.21.1.7"),
                                                     to_oid("1.3.6.1.2.1.4.21.1.11"))
BRIDGE_ADDRESS = to_oid("1.3.6.1.2.1.17.1.1.0")
BASE_PORT_IFINDEX = to_oid("1.3.6.1.2.1.17.1.4.1.2")
TP_FDB_PORT = to_oid("1.3.6.1.2.1.17.4.3.1.2")
Q_FDB_PORT = to_oid("1.3.6.1.2.1.17.7.1.2.2.1.2")
LLDP_LOC_PORT_ID = to_oid("1.0.8802.1.1.2.1.3.7.1.3")
LLDP_REM = to_oid("1.0.8802.1.1.2.1.4.1.1")                       # .4 chassis subtype .5 chassis .6/.7 port .8 descr .9 name
LLDP_REM_MAN_ADDR = to_oid("1.0.8802.1.1.2.1.4.2.1.3")
CDP_CACHE = to_oid("1.3.6.1.4.1.9.9.23.1.2.1.1")                  # .3 address type .4 address .6 id .7 port .8 platform
VTP_VLAN_STATE = to_oid("1.3.6.1.4.1.9.9.46.1.3.1.1.2")
TRUNK_STATUS = to_oid("1.3.6.1.4.1.9.9.46.1.6.1.1.14")            # vlanTrunkPortDynamicStatus: 1 trunking
VM_VLAN = to_oid("1.3.6.1.4.1.9.9.68.1.2.2.1.2")                  # access VLAN of a port
ROUTED_VLAN = to_oid("1.3.6.1.4.1.9.9.128.1.1.1.1.3")             # cviRoutedVlanIfIndex: vlan.port -> subinterface

ROUTE_TYPES = {1: "other", 2: "reject", 3: "local", 4: "remote"}
RESERVED_VLANS = range(1002, 1006)                                 # Cisco's FDDI/Token Ring VLANs


@dataclass
class Interface:
    index: int
    name: str = ""
    alias: str = ""                             # the description an administrator gave the port
    mac: Optional[str] = None
    up: Optional[bool] = None
    trunk: Optional[bool] = None                # None: the device does not say
    vlan: Optional[int] = None                  # access VLAN, or the VLAN a subinterface / SVI routes


@dataclass
class Neighbor:
    protocol: str                               # cdp | lldp
    local_if: Optional[int]
    local_port: str
    name: str
    port: str
    address: Optional[str] = None
    platform: str = ""
    chassis: str = ""


@dataclass
class Device:
    address: str                                # the address it was polled at
    name: str = ""
    descr: str = ""
    object_id: str = ""
    vendor: str = ""
    os: str = ""
    version: str = ""
    uptime_seconds: Optional[int] = None
    found_via: str = "seed"
    depth: int = 0
    bridge_mac: Optional[str] = None
    interfaces: dict[int, Interface] = field(default_factory=dict)
    addresses: list[dict] = field(default_factory=list)    # {ip, prefix, network, if_index}
    arp: list[dict] = field(default_factory=list)          # {ip, mac, if_index}
    routes: list[dict] = field(default_factory=list)       # {network, next_hop, if_index, type}
    fdb: list[dict] = field(default_factory=list)          # {mac, vlan, if_index}
    neighbors: list[Neighbor] = field(default_factory=list)
    vlans: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    requests: int = 0
    bytes_received: int = 0
    seconds: float = 0.0

    @property
    def label(self) -> str:
        return base_name(self.name) or self.address

    @property
    def own_ips(self) -> set[str]:
        return {a["ip"] for a in self.addresses} | {self.address}

    @property
    def own_macs(self) -> set[str]:
        return {i.mac for i in self.interfaces.values() if i.mac} | ({self.bridge_mac} if self.bridge_mac else set())

    def port_name(self, if_index: Optional[int]) -> str:
        iface = self.interfaces.get(if_index) if if_index is not None else None
        return iface.name if iface and iface.name else (f"ifIndex {if_index}" if if_index is not None else "")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["interfaces"] = [asdict(i) for i in sorted(self.interfaces.values(), key=lambda i: i.index)]
        d["label"] = self.label
        return d


# ── text helpers ──
def text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").replace("\x00", "").strip()
    return "" if value is None else str(value).strip()


def mac_text(value: Any) -> Optional[str]:
    if isinstance(value, bytes) and len(value) == 6 and any(value):
        return ":".join(f"{b:02X}" for b in value)
    return None


def ip_from(parts: tuple[int, ...]) -> str:
    return ".".join(map(str, parts))


_PORT_PREFIXES = [                              # long name -> the short name IOS shows
    ("twentyfivegige", "Twe"), ("hundredgige", "Hu"), ("fortygigabitethernet", "Fo"),
    ("tengigabitethernet", "Te"), ("gigabitethernet", "Gi"), ("fastethernet", "Fa"),
    ("ethernet", "Et"), ("port-channel", "Po"), ("vlan", "Vl"), ("loopback", "Lo"),
    ("serial", "Se"), ("tunnel", "Tu"),
]
_PORT = re.compile(r"^([A-Za-z-]+)\s*(\d[\d/.:]*)$")


def short_port(name: str) -> str:
    """'GigabitEthernet0/1', 'Gig 0/1' and 'Gi0/1' are the same port: 'Gi0/1'."""
    name = (name or "").strip()
    m = _PORT.match(name)
    if not m:
        return name
    word, number = m.group(1).lower(), m.group(2)
    for long, short in _PORT_PREFIXES:
        if word == long or (len(word) >= 2 and long.startswith(word) and word not in ("e", "et")):
            return short + number
    return m.group(1) + number


def cable_port(name: str) -> str:
    """The physical port a cable is plugged into: a router sends LLDP from each subinterface
    (Gi0/1.10, Gi0/1.20 ...), all over the one cable on Gi0/1."""
    return re.sub(r"\.\d+$", "", short_port(name))


def base_name(name: str) -> str:
    """A device's name without its domain or serial: 'SW2.lab.local' -> 'SW2',
    'N5K(FOC123)' -> 'N5K'. An IP address stays as it is."""
    name = (name or "").strip()
    if not name:
        return ""
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        pass
    name = name.split("(", 1)[0]
    return name.split(".", 1)[0].strip()


def describe(descr: str) -> tuple[str, str]:
    """(operating system, version) from sysDescr."""
    m = re.search(r"Version ([^\s,]+)", descr)
    version = m.group(1) if m else ""
    for marker, os_name in (("IOS-XE", "Cisco IOS XE"), ("IOS XE", "Cisco IOS XE"), ("NX-OS", "Cisco NX-OS"),
                            ("Adaptive Security Appliance", "Cisco ASA"), ("Cisco IOS", "Cisco IOS"),
                            ("JUNOS", "Junos"), ("RouterOS", "MikroTik RouterOS"), ("Linux", "Linux")):
        if marker in descr:
            if os_name == "Junos" and not version:
                jm = re.search(r"JUNOS ([\w.\-]+)", descr)
                version = jm.group(1) if jm else ""
            return os_name, version
    return (descr.splitlines()[0][:80] if descr else ""), version


# ── parsers: walk results -> tables ──
def _by_index(walk: list[tuple[Oid, Any]], base: Oid) -> dict[tuple[int, ...], Any]:
    return {oid[len(base):]: value for oid, value in walk if oid[:len(base)] == base}


def parse_interfaces(names, aliases, macs, oper, descrs=()) -> dict[int, Interface]:
    out: dict[int, Interface] = {}

    def iface(idx: tuple[int, ...]) -> Interface:
        return out.setdefault(idx[0], Interface(idx[0]))

    for idx, v in _by_index(list(descrs), IF_DESCR).items():
        iface(idx).name = text(v)
    for idx, v in _by_index(list(names), IF_NAME).items():
        if text(v):
            iface(idx).name = text(v)
    for idx, v in _by_index(list(aliases), IF_ALIAS).items():
        iface(idx).alias = text(v)
    for idx, v in _by_index(list(macs), IF_PHYS).items():
        iface(idx).mac = mac_text(v)
    for idx, v in _by_index(list(oper), IF_OPER).items():
        iface(idx).up = v == 1
    return out


def parse_addresses(ifindex_walk, mask_walk) -> list[dict]:
    masks = {idx: v for idx, v in _by_index(mask_walk, IP_AD_MASK).items()}
    out = []
    for idx, if_index in _by_index(ifindex_walk, IP_AD_IFINDEX).items():
        if len(idx) != 4:
            continue
        ip = ip_from(idx)
        mask = masks.get(idx)
        try:
            net = ipaddress.ip_network(f"{ip}/{mask}", strict=False) if isinstance(mask, str) else None
        except ValueError:
            net = None
        out.append({"ip": ip, "prefix": net.prefixlen if net else None,
                    "network": str(net) if net else None, "if_index": if_index})
    return sorted(out, key=lambda a: ipaddress.ip_address(a["ip"]))


def parse_arp(walk) -> list[dict]:
    """ipNetToMediaPhysAddress: index ifIndex.a.b.c.d."""
    out = []
    for idx, v in _by_index(walk, NET_TO_MEDIA).items():
        mac = mac_text(v)
        if len(idx) == 5 and mac and mac != "FF:FF:FF:FF:FF:FF":
            out.append({"ip": ip_from(idx[1:]), "mac": mac, "if_index": idx[0]})
    return out


def parse_arp_phys(walk) -> list[dict]:
    """ipNetToPhysicalPhysAddress (newer IP-MIB): index ifIndex.type.length.address; IPv4 only."""
    out = []
    for idx, v in _by_index(walk, NET_TO_PHYS).items():
        mac = mac_text(v)
        if len(idx) == 7 and idx[1] == 1 and idx[2] == 4 and mac and mac != "FF:FF:FF:FF:FF:FF":
            out.append({"ip": ip_from(idx[3:]), "mac": mac, "if_index": idx[0]})
    return out


def _route(dest: tuple, mask: Any, next_hop: str, if_index: Any, kind: str) -> Optional[dict]:
    try:
        net = ipaddress.ip_network(f"{ip_from(dest)}/{mask}", strict=False)
    except ValueError:
        return None
    return {"network": str(net), "next_hop": None if next_hop == "0.0.0.0" else next_hop,
            "if_index": if_index or None, "type": kind}


def parse_cidr_routes(ifindex_walk, type_walk) -> list[dict]:
    """ipCidrRouteTable: index dest(4).mask(4).tos.nexthop(4)."""
    types = _by_index(type_walk, CIDR_ROUTE_TYPE)
    out = []
    for idx, if_index in _by_index(ifindex_walk, CIDR_ROUTE_IFINDEX).items():
        if len(idx) != 13:
            continue
        r = _route(idx[:4], ip_from(idx[4:8]), ip_from(idx[9:13]), if_index, ROUTE_TYPES.get(types.get(idx), "other"))
        if r:
            out.append(r)
    return out


def parse_rfc1213_routes(ifindex_walk, nexthop_walk, mask_walk) -> list[dict]:
    """The old ipRouteTable: index dest(4); type unknown, so 'remote' when there is a next hop."""
    masks, hops = _by_index(mask_walk, IP_ROUTE_MASK), _by_index(nexthop_walk, IP_ROUTE_NEXTHOP)
    out = []
    for idx, if_index in _by_index(ifindex_walk, IP_ROUTE_IFINDEX).items():
        hop = hops.get(idx) if isinstance(hops.get(idx), str) else "0.0.0.0"
        r = _route(idx, masks.get(idx, "255.255.255.255"), hop, if_index, "local" if hop == "0.0.0.0" else "remote")
        if r:
            out.append(r)
    return out


def parse_base_ports(walk) -> dict[int, int]:
    return {idx[0]: v for idx, v in _by_index(walk, BASE_PORT_IFINDEX).items() if len(idx) == 1 and isinstance(v, int)}


def parse_fdb(walk, port_ifindex: dict[int, int], vlan: Optional[int]) -> list[dict]:
    """dot1dTpFdbPort: index mac(6) -> bridge port (0: the device itself / unknown)."""
    out = []
    for idx, port in _by_index(walk, TP_FDB_PORT).items():
        if len(idx) == 6 and port:
            out.append({"mac": mac_text(bytes(idx)), "vlan": vlan, "if_index": port_ifindex.get(port)})
    return [e for e in out if e["mac"]]


def parse_qbridge_fdb(walk, port_ifindex: dict[int, int]) -> list[dict]:
    """dot1qTpFdbPort: index fdbId.mac(6); the filtering database ID is the VLAN on most switches."""
    out = []
    for idx, port in _by_index(walk, Q_FDB_PORT).items():
        if len(idx) == 7 and port:
            out.append({"mac": mac_text(bytes(idx[1:])), "vlan": idx[0], "if_index": port_ifindex.get(port)})
    return [e for e in out if e["mac"]]


def parse_cdp(walk, interfaces: dict[int, Interface]) -> list[Neighbor]:
    """cdpCacheTable: index ifIndex.deviceIndex; columns 3 address type, 4 address, 6 device ID,
    7 its port, 8 platform."""
    rows: dict[tuple[int, int], dict[int, Any]] = {}
    for idx, v in _by_index(walk, CDP_CACHE).items():
        if len(idx) == 3:
            rows.setdefault((idx[1], idx[2]), {})[idx[0]] = v
    out = []
    for (if_index, _dev), cols in sorted(rows.items()):
        if 6 not in cols:
            continue
        addr = cols.get(4)
        address = ip_from(tuple(addr)) if cols.get(3, 1) == 1 and isinstance(addr, bytes) and len(addr) == 4 else None
        iface = interfaces.get(if_index)
        out.append(Neighbor("cdp", if_index, iface.name if iface else "", text(cols[6]),
                            short_port(text(cols.get(7))), address, text(cols.get(8))))
    return out


def _lldp_id(value: Any, is_mac: bool) -> str:
    if is_mac and isinstance(value, bytes) and len(value) == 6:
        return mac_text(value) or ""
    return text(value)


def parse_lldp(rem_walk, man_walk, loc_walk, interfaces: dict[int, Interface]) -> list[Neighbor]:
    """lldpRemTable: index timeMark.localPortNum.remIndex. The management address is in the
    index of lldpRemManAddrTable: ...remIndex.subtype.length.address."""
    rows: dict[tuple[int, int], dict[int, Any]] = {}
    for idx, v in _by_index(rem_walk, LLDP_REM).items():
        if len(idx) == 4:
            rows.setdefault((idx[2], idx[3]), {})[idx[0]] = v
    addresses: dict[tuple[int, int], str] = {}
    for idx, _v in _by_index(man_walk, LLDP_REM_MAN_ADDR).items():
        if len(idx) == 9 and idx[3] == 1 and idx[4] == 4:
            addresses.setdefault((idx[1], idx[2]), ip_from(idx[5:9]))
    local = {idx[0]: text(v) for idx, v in _by_index(loc_walk, LLDP_LOC_PORT_ID).items() if len(idx) == 1}
    by_name = {short_port(i.name): i.index for i in interfaces.values() if i.name}
    out = []
    for (port_num, rem), cols in sorted(rows.items()):
        local_name = short_port(local.get(port_num, ""))
        if_index = by_name.get(local_name) if local_name else None
        if if_index is None and port_num in interfaces:   # most devices number LLDP ports by ifIndex
            if_index = port_num
            local_name = local_name or interfaces[port_num].name
        # port ID subtype 3 and chassis ID subtype 4 are MAC addresses
        port = _lldp_id(cols.get(7), cols.get(6) == 3) or text(cols.get(8))
        out.append(Neighbor("lldp", if_index, local_name, text(cols.get(9)), short_port(port),
                            addresses.get((port_num, rem)), "", _lldp_id(cols.get(5), cols.get(4) == 4)))
    return out


def parse_vtp_vlans(walk) -> list[int]:
    """vtpVlanState: index domain.vlan; 1 = operational."""
    return sorted({idx[1] for idx, v in _by_index(walk, VTP_VLAN_STATE).items() if len(idx) == 2 and v == 1})


def parse_trunks(walk) -> dict[int, bool]:
    return {idx[0]: v == 1 for idx, v in _by_index(walk, TRUNK_STATUS).items() if len(idx) == 1}


def parse_access_vlans(walk) -> dict[int, int]:
    return {idx[0]: v for idx, v in _by_index(walk, VM_VLAN).items() if len(idx) == 1 and isinstance(v, int)}


def parse_routed_vlans(walk) -> dict[int, int]:
    """cviRoutedVlanIfIndex: index vlan.physicalIfIndex -> the subinterface's ifIndex."""
    return {v: idx[0] for idx, v in _by_index(walk, ROUTED_VLAN).items() if len(idx) == 2 and isinstance(v, int)}


_SVI = re.compile(r"^(?:Vl|Vlan)\s*(\d+)$", re.I)


# ── polling ──
def poll_device(session: Any, address: str) -> Device:
    """Everything one device can tell. Raises SnmpError if it does not answer at all; a table
    it cannot give is noted in Device.errors and skipped."""
    started = time.monotonic()
    dev = Device(address)
    system = session.get([SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_NAME])
    if all(v is None for v in system.values()):
        raise SnmpError(f"{address} answered, but gave none of its system values")
    dev.descr, dev.name = text(system.get(SYS_DESCR)), text(system.get(SYS_NAME))
    oid = system.get(SYS_OBJECT_ID)
    if isinstance(oid, tuple):
        dev.object_id = ".".join(map(str, oid))
        if oid[:6] == (1, 3, 6, 1, 4, 1) and len(oid) > 6:
            dev.vendor = ENTERPRISES.get(oid[6], f"enterprise {oid[6]}")
    if isinstance(system.get(SYS_UPTIME), int):
        dev.uptime_seconds = system[SYS_UPTIME] // 100
    dev.os, dev.version = describe(dev.descr)

    def walk(base: Oid, what: str, vlan: Optional[int] = None) -> list:
        try:
            return session.walk(base, vlan)
        except SnmpAuthError:
            raise
        except SnmpError as exc:
            dev.errors.append(f"{what}: {exc}")
            return []

    names = walk(IF_NAME, "interface names")
    dev.interfaces = parse_interfaces(names, walk(IF_ALIAS, "port descriptions"), walk(IF_PHYS, "interface MACs"),
                                      walk(IF_OPER, "interface states"), [] if names else walk(IF_DESCR, "interfaces"))
    dev.addresses = parse_addresses(walk(IP_AD_IFINDEX, "addresses"), walk(IP_AD_MASK, "address masks"))

    dev.arp = parse_arp(walk(NET_TO_MEDIA, "ARP table")) or parse_arp_phys(walk(NET_TO_PHYS, "ARP table (IP-MIB)"))
    dev.routes = parse_cidr_routes(walk(CIDR_ROUTE_IFINDEX, "routes"), walk(CIDR_ROUTE_TYPE, "route types"))
    if not dev.routes:
        dev.routes = parse_rfc1213_routes(walk(IP_ROUTE_IFINDEX, "routes (RFC 1213)"),
                                          walk(IP_ROUTE_NEXTHOP, "route next hops"), walk(IP_ROUTE_MASK, "route masks"))

    for if_index, vlan in parse_routed_vlans(walk(ROUTED_VLAN, "routed VLANs")).items():
        if if_index in dev.interfaces:
            dev.interfaces[if_index].vlan = vlan
    for iface in dev.interfaces.values():
        m = _SVI.match(iface.name)
        if m and iface.vlan is None:
            iface.vlan = int(m.group(1))

    dev.neighbors = parse_cdp(walk(CDP_CACHE, "CDP neighbours"), dev.interfaces)
    dev.neighbors += parse_lldp(walk(LLDP_REM, "LLDP neighbours"), walk(LLDP_REM_MAN_ADDR, "LLDP addresses"),
                                walk(LLDP_LOC_PORT_ID, "LLDP local ports"), dev.interfaces)

    port_ifindex = parse_base_ports(walk(BASE_PORT_IFINDEX, "bridge ports"))
    if port_ifindex:
        _poll_bridge(session, dev, port_ifindex, walk)

    dev.requests = getattr(session, "requests", 0)
    dev.bytes_received = getattr(session, "bytes_received", 0)
    dev.seconds = round(time.monotonic() - started, 2)
    return dev


def _poll_bridge(session: Any, dev: Device, port_ifindex: dict[int, int], walk: Any) -> None:
    try:
        dev.bridge_mac = mac_text(session.get([BRIDGE_ADDRESS]).get(BRIDGE_ADDRESS))
    except SnmpAuthError:
        raise
    except SnmpError as exc:
        dev.errors.append(f"bridge address: {exc}")
    for if_index, trunk in parse_trunks(walk(TRUNK_STATUS, "trunk states")).items():
        if if_index in dev.interfaces:
            dev.interfaces[if_index].trunk = trunk
    for if_index, vlan in parse_access_vlans(walk(VM_VLAN, "access VLANs")).items():
        if if_index in dev.interfaces and not dev.interfaces[if_index].trunk:
            dev.interfaces[if_index].vlan = vlan
    dev.vlans = parse_vtp_vlans(walk(VTP_VLAN_STATE, "VLANs"))

    q = parse_qbridge_fdb(walk(Q_FDB_PORT, "MAC table (Q-BRIDGE)"), port_ifindex)
    if q:
        dev.fdb = q
        return
    # Cisco: the plain table is VLAN 1's; every other VLAN has its own context
    dev.fdb = parse_fdb(walk(TP_FDB_PORT, "MAC table"), port_ifindex, 1 if dev.vlans else None)
    for vlan in dev.vlans:
        if vlan == 1 or vlan in RESERVED_VLANS:
            continue
        try:
            ports = parse_base_ports(session.walk(BASE_PORT_IFINDEX, vlan)) or port_ifindex
            dev.fdb += parse_fdb(session.walk(TP_FDB_PORT, vlan), ports, vlan)
        except SnmpError as exc:
            dev.notes.append(f"no MAC table per VLAN (VLAN {vlan}: {exc}); device locations come from VLAN 1 only")
            break
