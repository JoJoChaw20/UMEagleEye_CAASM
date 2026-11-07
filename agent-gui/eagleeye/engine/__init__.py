"""The agent's own active scan engine (no Nmap, no Npcap). The Nmap stage stays as it was;
Settings.scan_engine chooses between them (see stages/scan_own.py)."""

from .ports import BASE_PORTS, CONSUMER_PORTS, TIERS, WIDE_PORTS, ports_for
from .scan import EngineStats, Probes, run_own_scan

__all__ = ["BASE_PORTS", "CONSUMER_PORTS", "WIDE_PORTS", "TIERS", "ports_for",
           "EngineStats", "Probes", "run_own_scan"]
