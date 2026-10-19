"""Passive pipeline stages: collect what the sniffers heard, then enrich it."""

from __future__ import annotations

from ..passive import PassiveSuite
from ..pipeline.record import HostRecord
from ..pipeline.runner import PipelineContext, Stage, StageError


def enrich_passive_hosts(hosts: list[HostRecord], suite: PassiveSuite) -> list[HostRecord]:
    """Enrich ARP-discovered hosts with mDNS/NetBIOS names and services, DHCP
    fingerprints and SSDP/UPnP details, matched by IP and, failing that, by MAC (phones
    announce over IPv6 from the same MAC that ARP saw for their IPv4 address).

    Can only add or improve, never downgrade:
      hostname: mDNS/NetBIOS (by IP, then by MAC) > DHCP option 12 > existing reverse DNS
      os:       DHCP fingerprint fields, mdns_services, mdns_offered, mdns_name,
                netbios_name, ssdp_server and ssdp_types merged additively; existing keys win
    """
    for host in hosts:
        mac = (host.mac or "").lower() or None
        mdns_name = suite.mdns.get_hostname(host.ip) if suite.mdns else None
        mac_info_of = getattr(suite.mdns, "get_mac_info", None) if suite.mdns else None
        mac_info = mac_info_of(mac) if mac_info_of and mac else {}
        dhcp_info = suite.dhcp.get_info(host.ip) if suite.dhcp else {}
        if not dhcp_info and suite.dhcp and mac and hasattr(suite.dhcp, "get_info_by_mac"):
            dhcp_info = suite.dhcp.get_info_by_mac(mac)

        host.hostname = mdns_name or mac_info.get("hostname") or dhcp_info.get("dhcp_hostname") or host.hostname

        ssdp = getattr(suite, "ssdp", None)
        ssdp_info: dict = {}
        if ssdp:
            ssdp_info = (ssdp.get_mac_info(mac) if mac else {}) or ssdp.get_info(host.ip)

        extra = {k: v for k, v in dhcp_info.items() if k != "dhcp_hostname"}
        for key in ("mdns_services", "mdns_offered", "mdns_name", "netbios_name"):
            if mac_info.get(key):
                extra[key] = mac_info[key]
        for key in ("ssdp_server", "ssdp_types"):
            if ssdp_info.get(key):
                extra[key] = ssdp_info[key]
        if extra:
            merged = dict(host.os) if isinstance(host.os, dict) else {}
            for key, value in extra.items():
                if key not in merged:
                    merged[key] = value
            host.os = merged or None
    return hosts


class PassiveCollectStage(Stage):
    name = "collect"
    label = "Collect passive observations"

    def __init__(self, suite: PassiveSuite) -> None:
        self.suite = suite

    def run(self, ctx: PipelineContext) -> None:
        if self.suite.arp is None:
            raise StageError(
                "passive sniffing is not running. Start the agent with passive mode enabled, "
                "as Administrator/root, with scapy and Npcap/libpcap installed"
            )
        ctx.hosts = self.suite.arp.drain()
        ctx.progress(f"{len(ctx.hosts)} host(s) seen since the last flush", len(ctx.hosts), None)


class PassiveEnrichStage(Stage):
    name = "enrich"
    label = "Add hostnames and device fingerprints"
    optional = True

    def __init__(self, suite: PassiveSuite) -> None:
        self.suite = suite

    def should_run(self, ctx: PipelineContext) -> bool:
        return bool(ctx.hosts)

    def run(self, ctx: PipelineContext) -> None:
        enrich_passive_hosts(ctx.hosts, self.suite)
