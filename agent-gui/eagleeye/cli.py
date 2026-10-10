"""Command-line interface.

    python -m eagleeye run                     poll the dashboard and run scans (the agent)
    python -m eagleeye scan 192.168.1.0/24     scan once, locally, and print the results
    python -m eagleeye listen --seconds 60     passively listen on the network, then print
    python -m eagleeye inventory               collect this machine's inventory, then print
    python -m eagleeye check-deps              report missing tools
    python -m eagleeye config init|show        write / print the config file
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import sys
from pathlib import Path
from typing import Any, Optional

from . import VERSION, deps
from .config import ConfigError, Settings, default_config_path, load_settings, save_settings
from .passive import PassiveSuite
from .pipeline import Pipeline, PipelineContext
from .service import AgentService, log_event
from .stages import (
    InventoryDryRunStage, LocalInventoryStage,
    DryRunUploadStage, NmapScanStage, PassiveCollectStage, PassiveEnrichStage, SnmpPollStage,
)

log = logging.getLogger("eagleeye")


def _add_settings_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("settings (override the config file and EAGLEEYE_* variables)")
    g.add_argument("--config", type=Path, help="config file (default: per-user EagleEye config dir)")
    g.add_argument("--api-url", dest="api_url")
    g.add_argument("--api-key", dest="api_key")
    g.add_argument("--agent-id", dest="agent_id")
    g.add_argument("--interval", dest="poll_interval", type=int, help="scan poll interval in seconds")
    g.add_argument("--heartbeat-interval", dest="heartbeat_interval", type=int)
    g.add_argument("--passive", dest="passive", action="store_true", default=None,
                   help="enable passive sniffing (ARP, mDNS/NetBIOS, DHCP)")
    g.add_argument("--passive-interface", dest="passive_interface")
    g.add_argument("--passive-interval", dest="passive_interval", type=int)
    g.add_argument("--fingerbank-key", dest="fingerbank_key")
    g.add_argument("--snmp-user", dest="snmp_user")
    g.add_argument("--snmp-auth-key", dest="snmp_auth_key")
    g.add_argument("--snmp-priv-key", dest="snmp_priv_key")
    g.add_argument("--snmp-auth-protocol", dest="snmp_auth_protocol")
    g.add_argument("--snmp-priv-protocol", dest="snmp_priv_protocol")
    g.add_argument("--no-inventory", dest="inventory", action="store_false", default=None,
                   help="do not collect the endpoint inventory of this machine")
    g.add_argument("--inventory-interval", dest="inventory_interval", type=int,
                   help="seconds between endpoint inventories (default 21600 = 6 h)")
    g.add_argument("--include-user-software", dest="inventory_user_software", action="store_true", default=None,
                   help="also report software installed per user (personal data; off by default)")
    g.add_argument("--include-admin-names", dest="inventory_admin_names", action="store_true", default=None,
                   help="report local administrator account names instead of only their count (off by default)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eagleeye", description=f"EagleEye agent v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run the agent: heartbeat, poll for scans, upload results")
    _add_settings_flags(run)

    scan = sub.add_parser("scan", help="scan a subnet once, locally; nothing is uploaded")
    scan.add_argument("target", help="IPv4 address or CIDR range, e.g. 192.168.1.0/24")
    scan.add_argument("--json", type=Path, dest="json_out", help="write the ingest payload to this file")
    _add_settings_flags(scan)

    listen = sub.add_parser("listen", help="passively listen for a while, then print what was seen")
    listen.add_argument("--seconds", type=int, default=60)
    listen.add_argument("--json", type=Path, dest="json_out")
    _add_settings_flags(listen)

    inv = sub.add_parser("inventory", help="collect this machine's endpoint inventory and print a summary; nothing is uploaded")
    inv.add_argument("--json", type=Path, dest="json_out", help="write the full inventory document to this file")
    _add_settings_flags(inv)

    chk = sub.add_parser("check-deps", help="check Nmap, Npcap/libpcap, Python modules and privileges")
    chk.add_argument("--json", action="store_true", dest="as_json")

    cfg = sub.add_parser("config", help="manage the config file")
    cfg_sub = cfg.add_subparsers(dest="config_command", required=True)
    init = cfg_sub.add_parser("init", help="write the config file from the flags / environment")
    _add_settings_flags(init)
    show = cfg_sub.add_parser("show", help="print the effective settings (secrets masked)")
    _add_settings_flags(show)

    sub.add_parser("version", help="print the version")
    return parser


def _settings_from(args: argparse.Namespace) -> Settings:
    overrides = {k: v for k, v in vars(args).items() if k in Settings.__dataclass_fields__ and v is not None}
    return load_settings(getattr(args, "config", None), overrides=overrides)


def _print_hosts(hosts: list[Any]) -> None:
    if not hosts:
        print("No hosts found.")
        return
    print(f"{'IP':<16} {'MAC':<18} {'HOSTNAME':<26} {'OS / HINT':<28} PORTS")
    for h in hosts:
        os_text = ""
        if h.os:
            os_text = h.os.get("name") or h.os.get("fingerbank_device") or h.os.get("dhcp_device_hint") or ""
        ports = ",".join(str(p["port"]) for p in h.ports)
        print(f"{h.ip:<16} {(h.mac or '-'):<18} {(h.hostname or '-')[:25]:<26} {os_text[:27]:<28} {ports or '-'}")
    print(f"\n{len(hosts)} host(s)")


def _write_json(path: Optional[Path], payload: dict[str, Any]) -> None:
    if path:
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Payload written to {path}")


# ── commands ──

def cmd_run(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    problems = settings.problems()
    if problems:
        print("Cannot start:", *[f"  - {p}" for p in problems], sep="\n", file=sys.stderr)
        print(f"\nSet them with flags, EAGLEEYE_* variables, or `eagleeye config init`. "
              f"Config file: {default_config_path()}", file=sys.stderr)
        return 2

    log.info("EagleEye Agent v%s starting", VERSION)
    log.info("API URL      : %s", settings.api_url)
    log.info("Agent ID     : %s", settings.agent_id)
    log.info("Hostname     : %s", socket.gethostname())
    log.info("Active poll  : %ss   Heartbeat: %ss", settings.poll_interval, settings.heartbeat_interval)
    log.info("Passive mode : %s", "enabled" if settings.passive else "disabled")
    log.info("SNMPv3 poll  : %s", "enabled" if settings.snmp_enabled else "disabled")
    log.info("Inventory    : %s", f"every {settings.inventory_interval}s" if settings.inventory else "disabled")
    missing = [d for d in deps.check_all() if not d.ok and d.name in ("Nmap",)]
    for d in missing:
        log.warning("%s: %s. %s", d.name, d.detail, d.hint)

    service = AgentService(settings)
    try:
        service.run_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    stages: list[Any] = [NmapScanStage(args.target)]
    if settings.snmp_enabled:
        stages.append(SnmpPollStage(settings))
    holder: dict[str, Any] = {}
    stages.append(DryRunUploadStage("active", holder.update))
    ctx = PipelineContext("active", subnet=args.target, scan_type="active")
    result = Pipeline("active", stages, log_event).run(ctx)
    if not result.ok:
        print(f"Scan {result.status}: {result.error}", file=sys.stderr)
        return 1
    _print_hosts(ctx.hosts)
    print(f"Scanner: {ctx.summary.get('scanner')}   Took {result.seconds:.1f}s")
    _write_json(args.json_out, holder)
    return 0


def cmd_listen(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    suite = PassiveSuite(settings.passive_interface or None, settings.fingerbank_key or None)
    if not suite.start():
        print("Passive sniffing could not start (needs scapy, Npcap/libpcap and Administrator/root).", file=sys.stderr)
        print("Run `eagleeye check-deps` for details.", file=sys.stderr)
        return 1
    print(f"Listening for {args.seconds}s ...")
    import time
    time.sleep(args.seconds)
    holder: dict[str, Any] = {}
    ctx = PipelineContext("passive", scan_type="passive")
    result = Pipeline("passive", [
        PassiveCollectStage(suite), PassiveEnrichStage(suite), DryRunUploadStage("passive", holder.update),
    ], log_event).run(ctx)
    suite.stop()
    for problem in suite.problems():
        print(f"warning: {problem}", file=sys.stderr)
    if not result.ok:
        print(f"Listen {result.status}: {result.error}", file=sys.stderr)
        return 1
    _print_hosts(ctx.hosts)
    _write_json(args.json_out, holder)
    return 0


def cmd_inventory(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    holder: dict[str, Any] = {}
    ctx = PipelineContext("inventory", scan_type="inventory")
    stages = [LocalInventoryStage(options=settings.inventory_options), InventoryDryRunStage(holder.update)]
    result = Pipeline("inventory", stages, log_event).run(ctx)
    if not result.ok:
        print(f"Inventory {result.status}: {result.error}", file=sys.stderr)
        return 1
    inv = holder
    ident, hw, os_, sec, patches = inv["identity"], inv["hardware"], inv["os"], inv["security"], inv["patches"]
    nics = [n for n in inv["network"]["interfaces"] if n["physical"]]
    joined = f"domain {ident['domain']}" if ident["part_of_domain"] else "workgroup"
    ram_gb = round((hw["memory_bytes"] or 0) / 2**30, 1)
    days = patches["days_since_last_patch"]
    antivirus = ", ".join(f"{a['name']} ({'on' if a['enabled'] else 'off'})" for a in sec["antivirus"]) or "-"
    print(f"Host       : {ident['hostname']}  ({joined})")
    print(f"Hardware   : {hw['manufacturer']} {hw['model']}  [{hw['form_factor']}]  RAM {ram_gb} GB")
    print(f"OS         : {os_['name']} {os_['display_version'] or ''} build {os_['build']}  ({os_['role']})")
    print(f"Patches    : {patches['hotfix_count']} hotfix(es), last {patches['last_patch_id'] or '-'} "
          f"{days if days is not None else '?'} day(s) ago, pending reboot: {patches['pending_reboot']}")
    print(f"Security   : firewall all on: {sec['firewall_all_enabled']}, secure boot: {sec['secure_boot']}, "
          f"UAC: {sec['uac_enabled']}, RDP: {sec['rdp_enabled']}, antivirus: {antivirus}")
    print(f"Network    : {len(nics)} physical NIC(s): " + ", ".join(f"{n['name']} {n['mac']}" for n in nics))
    print(f"Listening  : {len(inv['network']['listening'])} port(s)")
    print(f"Software   : {len(inv['software'])} application(s)"
          + ("" if inv["privacy"]["user_software"] else "  (per-user installs not included)"))
    admins = sec["local_admin_count"]
    print(f"Local admins: {admins if admins is not None else '?'}"
          + ("" if inv["privacy"]["admin_names"] else "  (names not included)"))
    if inv["unavailable"]:
        print(f"Needs admin: {', '.join(inv['unavailable'])}")
    for err in inv["errors"]:
        print(f"warning    : {err}")
    _write_json(args.json_out, inv)
    return 0


def cmd_check_deps(args: argparse.Namespace) -> int:
    results = deps.check_all()
    if args.as_json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            mark = "OK     " if r.ok else ("MISSING" if r.required else "absent ")
            version = f" {r.version}" if r.version else ""
            print(f"[{mark}] {r.name}{version}: {r.detail}")
            if not r.ok and r.hint:
                print(f"          -> {r.hint}")
    return 1 if any(r.required and not r.ok for r in results) else 0


def cmd_config(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    if args.config_command == "show":
        print(json.dumps(settings.redacted(), indent=2))
        problems = settings.problems()
        if problems:
            print("\nNot ready:", *[f"  - {p}" for p in problems], sep="\n")
        return 0
    path = save_settings(settings, args.config)
    print(f"Config written to {path}")
    problems = settings.problems()
    if problems:
        print("Still missing:", *[f"  - {p}" for p in problems], sep="\n")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    commands = {
        "run": cmd_run, "scan": cmd_scan, "listen": cmd_listen,
        "check-deps": cmd_check_deps, "config": cmd_config, "inventory": cmd_inventory,
    }
    if args.command == "version":
        print(VERSION)
        return 0
    if args.command is None:
        parser.print_help()
        return 0
    try:
        return commands[args.command](args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
