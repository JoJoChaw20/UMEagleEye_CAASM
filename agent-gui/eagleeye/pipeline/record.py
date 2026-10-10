"""The data every stage reads and adds to: one HostRecord per discovered host."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

# SNMP facts travel at the top level of the host in the ingest payload.
SNMP_KEYS = ("snmp_sysdescr", "snmp_sysobjectid", "snmp_interfaces")


@dataclass
class HostRecord:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    ports: list[dict[str, Any]] = field(default_factory=list)
    os: Optional[dict[str, Any]] = None
    snmp: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """The host exactly as POST /scans/ingest expects it."""
        payload: dict[str, Any] = {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "ports": self.ports,
            "os": self.os,
        }
        payload.update(self.snmp)
        return payload

    @classmethod
    def from_payload(cls, data: dict[str, Any]) -> "HostRecord":
        return cls(
            ip=data["ip"],
            hostname=data.get("hostname"),
            mac=data.get("mac"),
            ports=list(data.get("ports") or []),
            os=data.get("os"),
            snmp={k: data[k] for k in SNMP_KEYS if k in data},
        )
