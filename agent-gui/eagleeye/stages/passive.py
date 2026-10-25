"""Passive pipeline stages: collect what the sniffers heard, then enrich it."""

from __future__ import annotations

from collections import Counter
from typing import Any, Optional

from ..passive import PassiveSuite
from ..pipeline.record import HostRecord
from ..pipeline.runner import PipelineContext, Stage, StageError

# How name sources are shown in the log, in the order they are tried.
NAME_SOURCES = (("mdns", "mDNS"), ("netbios", "NetBIOS"), ("dhcp", "DHCP"),
                ("rdns", "reverse DNS"), ("none", "none"))


def enrich_passive_hosts(hosts: list[HostRecord], suite: PassiveSuite,
                         sources: Optional[Counter[str]] = None) -> list[HostRecord]:
    """Enrich ARP-discovered hosts with mDNS/NetBIOS names and services, DHCP
    fingerprints and SSDP/UPnP details, matched by MAC first (what a device said about
    itself stays true when DHCP gives its address to another device) and then by IP
    (phones announce over IPv6, so only their MAC links them to the IPv4 ARP saw).

    Can only add or improve, never downgrade:
      hostname: mDNS/NetBIOS (by MAC, then by IP) > DHCP option 12 > reverse DNS,
                which is asked only for the hosts still without a name
      os:       DHCP fingerprint fields, mdns_services, mdns_offered, mdns_name,
                netbios_name, ssdp_server and ssdp_types merged additively; existing keys win
    `sources` counts where each host's name came from (mdns, netbios, dhcp, rdns, none).
    """
    unnamed: list[HostRecord] = []
    for host in hosts:
        mac = (host.mac or "").lower() or None
        mdns = suite.mdns
        mac_info_of = getattr(mdns, "get_mac_info", None) if mdns else None
        mac_info = mac_info_of(mac) if mac_info_of and mac else {}
        dhcp_info: dict[str, Any] = {}
        if suite.dhcp:
            if mac and hasattr(suite.dhcp, "get_info_by_mac"):
                dhcp_info = suite.dhcp.get_info_by_mac(mac)
            dhcp_info = dhcp_info or suite.dhcp.get_info(host.ip)

        name, source = None, None
        if mac_info.get("hostname"):
            name, source = mac_info["hostname"], "mdns" if mac_info.get("mdns_name") else "netbios"
        elif mdns and mdns.get_hostname(host.ip):
            name = mdns.get_hostname(host.ip)
            source = mdns.name_source(host.ip) if hasattr(mdns, "name_source") else "mdns"
        elif dhcp_info.get("dhcp_hostname"):
            name, source = dhcp_info["dhcp_hostname"], "dhcp"
        if name:
            host.hostname = name
            if sources is not None:
                sources[source or "mdns"] += 1
        elif not host.hostname:
            unnamed.append(host)

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

    rdns = getattr(suite, "rdns", None)
    names = rdns.resolve([h.ip for h in unnamed]) if rdns is not None and unnamed else {}
    for host in unnamed:
        host.hostname = names.get(host.ip)
        if sources is not None:
            sources["rdns" if host.hostname else "none"] += 1
    return hosts


def describe_sources(sources: Counter[str]) -> str:
    """'names: mDNS 12, NetBIOS 3, DHCP 4, reverse DNS 9, none 17' (empty sources left out)."""
    parts = [f"{label} {sources[key]}" for key, label in NAME_SOURCES if sources.get(key)]
    return "names: " + (", ".join(parts) if parts else "none")


class PassiveCollectStage(Stage):
    """Takes what the ARP sniffer heard. The service hands over one batch (the hosts
    heard on one network); without one, everything heard is drained."""

    name = "collect"
    label = "Collect passive observations"

    def __init__(self, suite: PassiveSuite, batch: Optional[tuple[Optional[dict[str, Any]], list[HostRecord]]] = None) -> None:
        self.suite = suite
        self.batch = batch

    def run(self, ctx: PipelineContext) -> None:
        if self.suite.arp is None:
            raise StageError(
                "passive sniffing is not running. Start the agent with passive mode enabled, "
                "as Administrator/root, with scapy and Npcap/libpcap installed"
            )
        if self.batch is not None:
            # The network they were heard on goes with them (see UploadStage).
            ctx.network, ctx.hosts = self.batch[0], list(self.batch[1])
        else:
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
        sources: Counter[str] = Counter()
        enrich_passive_hosts(ctx.hosts, self.suite, sources)
        ctx.progress(describe_sources(sources))
