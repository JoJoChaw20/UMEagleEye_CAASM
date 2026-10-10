"""Passive pipeline stages: collect what the sniffers heard, then enrich it."""

from __future__ import annotations

from ..passive import PassiveSuite
from ..pipeline.record import HostRecord
from ..pipeline.runner import PipelineContext, Stage, StageError


def enrich_passive_hosts(hosts: list[HostRecord], suite: PassiveSuite) -> list[HostRecord]:
    """Enrich ARP-discovered hosts with mDNS/NetBIOS hostnames and DHCP fingerprints.

    Can only add or improve, never downgrade:
      hostname: mDNS/NetBIOS > DHCP option 12 > existing reverse DNS
      os:       DHCP fingerprint fields merged additively; existing keys win
    """
    for host in hosts:
        mdns_name = suite.mdns.get_hostname(host.ip) if suite.mdns else None
        dhcp_info = suite.dhcp.get_info(host.ip) if suite.dhcp else {}

        host.hostname = mdns_name or dhcp_info.get("dhcp_hostname") or host.hostname

        if dhcp_info:
            merged = dict(host.os) if isinstance(host.os, dict) else {}
            for key, value in dhcp_info.items():
                if key not in merged and key != "dhcp_hostname":
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
