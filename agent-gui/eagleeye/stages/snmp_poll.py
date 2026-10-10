"""SNMPv3 (authPriv) polling of discovered hosts, for network-device classification.

Nmap sees port 161 as TCP-closed, so SNMP is invisible without a dedicated UDP poll.
This is best-effort enrichment: a failure on one host never aborts the scan.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..config import Settings
from ..pipeline.runner import PipelineContext, Stage

log = logging.getLogger("eagleeye.snmp")

_AUTH_PROTOCOLS = {
    "SHA":    "usmHMACSHAAuthProtocol",
    "SHA1":   "usmHMACSHAAuthProtocol",
    "MD5":    "usmHMACMD5AuthProtocol",
    "SHA224": "usmHMAC128SHA224AuthProtocol",
    "SHA256": "usmHMAC192SHA256AuthProtocol",
    "SHA384": "usmHMAC256SHA384AuthProtocol",
    "SHA512": "usmHMAC384SHA512AuthProtocol",
}
_PRIV_PROTOCOLS = {
    "AES":    "usmAesCfb128Protocol",
    "AES128": "usmAesCfb128Protocol",
    "AES192": "usmAesCfb192Protocol",
    "AES256": "usmAesCfb256Protocol",
    "DES":    "usmDESPrivProtocol",
    "3DES":   "usm3DESEDEPrivProtocol",
}


def query_snmp_v3(
    ip: str,
    user: str,
    auth_key: str,
    priv_key: str,
    auth_protocol: str = "SHA",
    priv_protocol: str = "AES",
) -> dict[str, Any]:
    """Poll one host and return {"snmp_sysdescr", "snmp_sysobjectid", "snmp_interfaces"},
    or {} on any failure (timeout, credential mismatch, pysnmp missing).

    Targets the pysnmp 6/7 asyncio HLAPI: one GET for sysDescr and sysObjectID, one
    WALK of ifDescr for interface names.
    """
    import asyncio
    import importlib

    hlapi = None
    for module in ("pysnmp.hlapi.v3arch.asyncio", "pysnmp.hlapi.asyncio"):
        try:
            hlapi = importlib.import_module(module)
            break
        except ImportError:
            continue
    if hlapi is None:
        log.warning("pysnmp (asyncio HLAPI) not installed - SNMPv3 poll of %s skipped. Run: pip install pysnmp", ip)
        return {}

    auth_proto = getattr(hlapi, _AUTH_PROTOCOLS.get(auth_protocol.upper(), ""), None)
    priv_proto = getattr(hlapi, _PRIV_PROTOCOLS.get(priv_protocol.upper(), ""), None)
    if auth_proto is None or priv_proto is None:
        log.warning("SNMPv3 poll of %s skipped - unsupported protocol (auth=%s, priv=%s)", ip, auth_protocol, priv_protocol)
        return {}

    async def _poll() -> dict[str, Any]:
        engine = hlapi.SnmpEngine()
        try:
            user_data = hlapi.UsmUserData(
                user, authKey=auth_key, privKey=priv_key,
                authProtocol=auth_proto, privProtocol=priv_proto,
            )
            transport = await hlapi.UdpTransportTarget.create((ip, 161), timeout=3, retries=1)
            context = hlapi.ContextData()
            result: dict[str, Any] = {}

            error_indication, error_status, _idx, var_binds = await hlapi.get_cmd(
                engine, user_data, transport, context,
                hlapi.ObjectType(hlapi.ObjectIdentity("1.3.6.1.2.1.1.1.0")),  # sysDescr
                hlapi.ObjectType(hlapi.ObjectIdentity("1.3.6.1.2.1.1.2.0")),  # sysObjectID
            )
            if error_indication:
                log.warning("SNMPv3 GET failed for %s: %s", ip, error_indication)
                return {}
            if error_status:
                log.warning("SNMPv3 GET error for %s: %s", ip, error_status.prettyPrint())
                return {}
            if len(var_binds) >= 2:
                result["snmp_sysdescr"] = str(var_binds[0][1])
                result["snmp_sysobjectid"] = str(var_binds[1][1])

            interfaces: list[str] = []
            async for walk_error, walk_status, _widx, walk_binds in hlapi.walk_cmd(
                engine, user_data, transport, context,
                hlapi.ObjectType(hlapi.ObjectIdentity("1.3.6.1.2.1.2.2.1.2")),  # ifDescr
                lexicographicMode=False,
            ):
                if walk_error:
                    log.warning("SNMPv3 ifDescr walk failed for %s: %s", ip, walk_error)
                    break
                if walk_status:
                    log.warning("SNMPv3 ifDescr walk error for %s: %s", ip, walk_status.prettyPrint())
                    break
                for _oid, value in walk_binds:
                    name = str(value).strip()
                    if name:
                        interfaces.append(name)
            if interfaces:
                result["snmp_interfaces"] = interfaces
            return result
        finally:
            closer = getattr(engine, "close_dispatcher", None) or getattr(engine, "closeDispatcher", None)
            if closer:
                try:
                    closer()
                except Exception:  # noqa: BLE001 - cleanup must never raise
                    pass

    try:
        result = asyncio.run(_poll())
        if result:
            log.info(
                "SNMPv3 poll of %s - sysDescr='%s', %d interface(s)",
                ip, result.get("snmp_sysdescr", "?")[:60], len(result.get("snmp_interfaces", [])),
            )
        return result
    except Exception as exc:  # noqa: BLE001
        log.warning("SNMPv3 poll of %s failed: %s", ip, exc)
        return {}


class SnmpPollStage(Stage):
    name = "snmp"
    label = "Poll network devices over SNMPv3"
    optional = True

    def __init__(self, settings: Settings, workers: int = 8) -> None:
        self.settings = settings
        self.workers = workers

    def should_run(self, ctx: PipelineContext) -> bool:
        return self.settings.snmp_enabled and bool(ctx.hosts)

    def run(self, ctx: PipelineContext) -> None:
        s = self.settings

        def poll(host_ip: str) -> dict[str, Any]:
            try:
                return query_snmp_v3(host_ip, s.snmp_user, s.snmp_auth_key, s.snmp_priv_key,
                                     s.snmp_auth_protocol, s.snmp_priv_protocol)
            except Exception as exc:  # noqa: BLE001
                log.warning("SNMPv3 enrichment failed for %s: %s", host_ip, exc)
                return {}

        answered = 0
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            for host, data in zip(ctx.hosts, pool.map(poll, [h.ip for h in ctx.hosts])):
                if data:
                    host.snmp.update(data)
                    answered += 1
        ctx.progress(f"{answered} of {len(ctx.hosts)} host(s) answered SNMP", answered, len(ctx.hosts))
