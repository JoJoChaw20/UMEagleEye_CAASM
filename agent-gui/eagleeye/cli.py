"""Command-line interface.

    python -m eagleeye run                     poll the dashboard and run scans (the agent)
    python -m eagleeye scan 192.168.1.0/24     scan once, locally, and print the results
    python -m eagleeye listen --seconds 60     passively listen on the network, then print
    python -m eagleeye inventory               collect this machine's inventory, then print
    python -m eagleeye sbom                    list this machine's packages and their CVEs, then print
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
from .config import ConfigError, Settings, default_config_path, load_settings, save_settings, sbom_cache_path, state_path
from .enrol import ConnectionCodeError, parse_connection_code
from .keychain import Keychain
from .passive import PassiveSuite
from .pipeline import Pipeline, PipelineContext
from .schedule import Schedule
from .service import SCHEDULES_ENABLED, AgentService, log_event
from .stages import (
    CveCheckStage, InventoryDryRunStage, LocalInventoryStage, SbomBuildStage, SbomDryRunStage,
    DryRunUploadStage, PassiveCollectStage, PassiveEnrichStage, SnmpPollStage,
)
from .stages.scan_own import active_scan_stage

log = logging.getLogger("eagleeye")


def _add_settings_flags(p: argparse.ArgumentParser) -> None:
    g = p.add_argument_group("settings (override the config file and EAGLEEYE_* variables)")
    g.add_argument("--config", type=Path, help="config file (default: per-user EagleEye config dir)")
    g.add_argument("--connection-code", dest="connection_code",
                   help="the code from the dashboard's Agents page; sets the API URL, agent ID and API key")
    g.add_argument("--api-url", dest="api_url")
    g.add_argument("--api-key", dest="api_key")
    g.add_argument("--agent-id", dest="agent_id")
    g.add_argument("--interval", dest="poll_interval", type=int, help="scan poll interval in seconds")
    g.add_argument("--heartbeat-interval", dest="heartbeat_interval", type=int)
    g.add_argument("--passive", dest="passive", action="store_true", default=None,
                   help="enable passive sniffing (ARP, mDNS/NetBIOS, DHCP)")
    g.add_argument("--passive-interface", dest="passive_interface")
    g.add_argument("--passive-interval", dest="passive_interval", type=int)
    g.add_argument("--capture", dest="passive_backend", choices=("auto", "npcap", "native"),
                   help="what captures packets for passive listening: npcap (Npcap/libpcap), "
                        "native (built in: Microsoft's NDIS capture on Windows, a packet socket on Linux)")
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
    g.add_argument("--no-sbom", dest="sbom", action="store_false", default=None,
                   help="do not build this machine's SBOM (package list checked for CVEs)")
    g.add_argument("--sbom-interval", dest="sbom_interval", type=int,
                   help="seconds between SBOMs (default 86400 = 24 h)")
    g.add_argument("--sbom-extra-paths", dest="sbom_extra_paths",
                   help="extra folders for the SBOM, separated by ';'")
    g.add_argument("--sbom-include-binaries", dest="sbom_include_binaries", action="store_true", default=None,
                   help="also read compiled programs (Go binaries, .exe/.dll, Linux kernel); many more, noisier findings")
    g.add_argument("--engine", dest="scan_engine", choices=("auto", "nmap", "own", "compare"),
                   help="active scan engine: auto/nmap = the Nmap stage, own = the agent's own engine, "
                        "compare = both, with a local comparison report")
    g.add_argument("--ports", dest="scan_ports", choices=("base", "consumer", "wide"),
                   help="port tier for the own engine (default base)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="eagleeye", description=f"EagleEye agent v{VERSION}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("run", help="run the agent: heartbeat, poll for scans, upload results")
    _add_settings_flags(run)

    scan = sub.add_parser("scan", help="scan a subnet once, locally; nothing is uploaded")
    scan.add_argument("target", help="IPv4 address or CIDR range, e.g. 192.168.1.0/24")
    scan.add_argument("--json", type=Path, dest="json_out", help="write the ingest payload to this file")
    scan.add_argument("--truth", type=Path, help="with --engine compare: score both engines against this CSV "
                                               "(columns ip, mac, name, device, os, services)")
    _add_settings_flags(scan)

    listen = sub.add_parser("listen", help="passively listen for a while, then print what was seen")
    listen.add_argument("--seconds", type=int, default=60)
    listen.add_argument("--json", type=Path, dest="json_out")
    listen.add_argument("--compare", action="store_true",
                        help="listen with Npcap and the built-in capture at the same time and compare them")
    _add_settings_flags(listen)

    inv = sub.add_parser("inventory", help="collect this machine's endpoint inventory and print a summary; nothing is uploaded")
    inv.add_argument("--json", type=Path, dest="json_out", help="write the full inventory document to this file")
    _add_settings_flags(inv)

    sb = sub.add_parser("sbom", help="build this machine's SBOM and check it with Grype; nothing is uploaded")
    sb.add_argument("--json", type=Path, dest="json_out", help="write the SBOM, folders and findings to this file")
    _add_settings_flags(sb)

    chk = sub.add_parser("check-deps", help="check Nmap, Npcap/libpcap, Python modules and privileges")
    chk.add_argument("--json", action="store_true", dest="as_json")

    cfg = sub.add_parser("config", help="manage the config file")
    cfg_sub = cfg.add_subparsers(dest="config_command", required=True)
    init = cfg_sub.add_parser("init", help="write the config file from the flags / environment")
    _add_settings_flags(init)
    show = cfg_sub.add_parser("show", help="print the effective settings (secrets masked)")
    _add_settings_flags(show)

    gui = sub.add_parser("gui", help="open the desktop app (needs PySide6)")
    gui.add_argument("--minimized", action="store_true", help="start in the system tray")

    svc = sub.add_parser("service", help="the agent as a system service: install, uninstall, start, stop, status, run")
    svc.add_argument("action", choices=("install", "uninstall", "start", "stop", "status", "run", "scm", "apply"))
    svc.add_argument("--instance", default="", help="a second agent on this computer, e.g. production")
    svc.add_argument("--from-config", type=Path, dest="from_config",
                     help="install: the settings to move into the service (default: this user's); "
                          "apply: the settings the agent app saved")
    svc.add_argument("--no-start", action="store_true", help="install: do not start it yet")
    svc.add_argument("--purge", action="store_true", help="uninstall: also delete its settings, state and logs")

    sub.add_parser("version", help="print the version")
    return parser


def cmd_service(args: argparse.Namespace) -> int:
    """The agent as a Windows service / systemd unit (serviceinstall.py, servicehost.py)."""
    from . import ipc, serviceinstall
    from .machine import service_name
    instance = "".join(ch for ch in args.instance if ch.isalnum() or ch in "-_")[:40]
    if args.action == "scm":                       # started by Windows' Service Control Manager
        from . import servicehost, winservice

        def make_host() -> "servicehost.ServiceHost":
            servicehost.setup_logging(instance)         # only once Windows really started the service
            return servicehost.ServiceHost(instance)
        return winservice.run(service_name(instance), make_host)
    if args.action == "run":                       # foreground: systemd, or a test in a console
        from . import servicehost
        if not sys.stdout.isatty():
            servicehost.setup_logging(instance)
        return servicehost.run_foreground(instance)
    if args.action == "status":
        try:
            st = ipc.call({"cmd": "status"}, ipc.address(instance))
        except ipc.ServiceUnavailable as exc:
            print(f"{service_name(instance)}: {exc}")
            return 1
        print(f"{service_name(instance)} {st.get('version')}: {st.get('state')}"
              + (f" ({'; '.join(st['problems'])})" if st.get("problems") else ""))
        if st.get("last_heartbeat_at"):
            print(f"  last heartbeat {st['last_heartbeat_at']} ({'ok' if st.get('last_heartbeat_ok') else 'failed'})")
        if st.get("passive"):
            print(f"  passive listening on {st['passive']['listening_on']} with {st['passive']['capture']}")
        if st.get("managed"):
            print(f"  set by the administrator: {', '.join(sorted(st['managed']))}")
        print(f"  settings {st.get('config_path')}\n  log {st.get('log_path')}")
        return 0
    if not serviceinstall.is_admin():
        print("Run this as an administrator (Windows: an elevated PowerShell; Linux: sudo).", file=sys.stderr)
        return 1
    if args.action == "install":
        for line in serviceinstall.install(instance, args.from_config, start=not args.no_start):
            print(line)
    elif args.action == "uninstall":
        for line in serviceinstall.uninstall(instance, purge=args.purge):
            print(line)
    elif args.action == "apply":                   # run elevated by the agent app (gui/remote.py)
        if not args.from_config:
            print("apply needs --from-config", file=sys.stderr)
            return 2
        print(serviceinstall.apply_settings_file(args.from_config, instance))
    else:
        print(serviceinstall.control(args.action, instance))
    return 0


def _settings_from(args: argparse.Namespace) -> Settings:
    overrides = {k: v for k, v in vars(args).items() if k in Settings.__dataclass_fields__ and v is not None}
    code = getattr(args, "connection_code", None)
    if code:
        try:
            url, agent_id, key = parse_connection_code(code)
        except ConnectionCodeError as exc:
            raise ConfigError(str(exc)) from None
        # A value given with its own flag still wins over the code.
        for name, value in (("api_url", url), ("agent_id", agent_id), ("api_key", key)):
            overrides.setdefault(name, value)
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
    log.info("SBOM         : %s", f"every {settings.sbom_interval}s" if settings.sbom else "disabled")
    missing = [d for d in deps.check_all() if not d.ok and d.name in ("Nmap",)]
    for d in missing:
        log.warning("%s: %s. %s", d.name, d.detail, d.hint)

    from .policy import policy_path
    service = AgentService(settings, state_path=state_path(), sbom_cache_path=sbom_cache_path(),
                           policy_path=policy_path())
    if SCHEDULES_ENABLED:
        for sched in settings.schedules:
            log.info("Schedule     : %s %s", sched.get("subnet"), Schedule.from_dict(sched).describe())
    try:
        service.run_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    stages: list[Any] = [active_scan_stage(args.target, settings, getattr(args, "truth", None))]
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
    engine = ctx.summary.get("engine")
    if engine:
        print(f"Own engine: {engine['up']} up of {engine['addresses']} (ARP {engine['by_arp']}, ping {engine['by_ping']}, "
              f"ports {engine['by_port']}), {engine['connections']} connections, {engine['open_ports']} open, "
              f"{engine['seconds']}s, CPU {engine['cpu_seconds']}s, phases {engine['phases']}")
    cmp_ = ctx.summary.get("compare")
    if cmp_:
        h, p = cmp_["hosts"], cmp_["ports"]
        print(f"Compared with {cmp_['ref_scanner']} ({cmp_['ref_seconds']}s): hosts own {h['own']} / ref {h['ref']} / both {h['both']}"
              f"; only own {h['only_own']}; only ref {h['only_ref']}; open-port agreement {p['agreement']:.0%}")
        for engine_name, t in (cmp_.get("truth") or {}).items():
            print(f"Truth ({engine_name}): devices {t['found']}/{t['devices']}, MACs {t['mac_right']}/{t['mac_checked']}, "
                  f"names {t['name_right']}/{t['name_checked']}, ports {t['ports_found']}/{t['ports']}, "
                  f"products {t['product_right']}/{t['product_checked']}, versions {t['version_right']}/{t['version_checked']}")
        print(f"Report: {cmp_['report']}")
    _write_json(args.json_out, holder)
    return 0


def cmd_listen(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    if args.compare:
        return _compare_capture(args, settings)
    suite = PassiveSuite(settings.passive_interface or None, settings.fingerbank_key or None,
                         backend=settings.passive_backend)
    if not suite.start():
        print("Passive sniffing could not start (needs scapy, Administrator/root and, for --capture npcap, "
              "Npcap/libpcap).", file=sys.stderr)
        for problem in suite.problems():
            print(f"  {problem}", file=sys.stderr)
        print("Run `eagleeye check-deps` for details.", file=sys.stderr)
        return 1
    print(f"Listening for {args.seconds}s with {suite.capture} ...")
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


def _compare_capture(args: argparse.Namespace, settings: Settings) -> int:
    from datetime import datetime

    from .passive import compare
    from .stages.scan_own import report_dir
    report = compare.run(settings.passive_interface or None, args.seconds, settings.fingerbank_key or None)
    if report["capture"] is None:
        print("Could not start both captures:", file=sys.stderr)
        for problem in report["problems"]:
            print(f"  {problem}", file=sys.stderr)
        return 1
    cpu, fr = report["cpu_seconds"], report["frames"]
    print(f"\nListening on {report['listening_on']} (adapter index {report['adapter_index']})")
    print(f"Built-in capture: {fr['built_in_from_adapter']} frames ({fr['per_second']}/s), "
          f"{fr['built_in_to_sniffers']} passed to the sniffers")
    if report["ndis_indexes"]:
        print("Packets per driver adapter index (miniport/lower): "
              + ", ".join(f"{k}: {v}" for k, v in report["ndis_indexes"].items()))
    print(f"CPU in {args.seconds}s: Npcap sniffers {cpu['npcap']} s, built-in capture {cpu['built_in']} s")
    print(f"\n{'':8} {'Npcap':>6} {'built-in':>9} {'both':>6}")
    for kind, row in report["compare"].items():
        print(f"{kind:8} {row['npcap']:>6} {row['built_in']:>9} {row['both']:>6}")
        for side in ("only_npcap", "only_built_in"):
            for item in row[side][:10]:
                print(f"           {side.replace('_', ' ')}: {item}")
    for problem in report["problems"]:
        print(f"warning: {problem}", file=sys.stderr)
    out = report_dir()
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"listen-compare-{datetime.now():%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport: {path}")
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
    joined = f"domain {ident['domain']}" if ident["part_of_domain"] else (
        f"workgroup {ident['workgroup']}" if ident.get("workgroup") else "not in a domain")
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


def cmd_sbom(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    holder: dict[str, Any] = {}
    ctx = PipelineContext("sbom", scan_type="sbom")
    stages = [SbomBuildStage(settings.sbom_extra_paths, include_binaries=settings.sbom_include_binaries),
              CveCheckStage(), SbomDryRunStage(holder.update)]
    result = Pipeline("sbom", stages, log_event).run(ctx)
    if not result.ok:
        print(f"SBOM {result.status}: {result.error}", file=sys.stderr)
        return 1
    findings = holder["findings"]
    print(f"Folders    : {', '.join(holder['scope'])}")
    print(f"Packages   : {len(holder['sbom']['components'])}")
    print(f"Findings   : {len(findings)} ({len({f['cve_id'] for f in findings})} distinct CVE/advisory IDs)")
    for f in sorted(findings, key=lambda f: -f["cvss_base_score"])[:15]:
        print(f"  {f['cve_id']:<20} {f['cvss_base_score']:>4}  {f['package_name']} {f['package_version']}")
    print(f"Took {result.seconds:.0f}s")
    _write_json(args.json_out, holder)
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
    keychain = Keychain()
    path = save_settings(settings, args.config, keychain=keychain)
    print(f"Config written to {path}")
    if keychain.available():
        print("Secrets (API key, SNMP and Fingerbank keys) are stored in the OS credential store, not in the file.")
    else:
        print("The OS credential store is not available, so secrets are stored in the file. Keep it private.")
    problems = settings.problems()
    if problems:
        print("Still missing:", *[f"  - {p}" for p in problems], sep="\n")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        # Piped output on Windows uses a legacy code page; never crash on a product name.
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    commands = {
        "run": cmd_run, "scan": cmd_scan, "listen": cmd_listen,
        "check-deps": cmd_check_deps, "config": cmd_config, "inventory": cmd_inventory, "sbom": cmd_sbom,
        "service": cmd_service,
    }
    if args.command == "version":
        print(VERSION)
        return 0
    if args.command == "gui":
        try:
            from .gui import main as gui_main
        except ImportError as exc:
            print(f"The desktop app needs PySide6 (pip install PySide6): {exc}", file=sys.stderr)
            return 1
        return gui_main(["--minimized"] if args.minimized else [])
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
