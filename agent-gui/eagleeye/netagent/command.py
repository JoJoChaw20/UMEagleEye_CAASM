"""`eagleeye netpoll`: crawl the network from seed devices over SNMP, once, and print what was
found. Nothing is uploaded.

    eagleeye netpoll --seed 10.99.0.1 --allow 10.10.0.0/16 --allow 10.99.0.0/24
    eagleeye netpoll --seed 10.99.0.1 --allow 10.0.0.0/8 --record lab/   # keep the answers
    eagleeye netpoll --seed 10.99.0.1 --allow 10.0.0.0/8 --replay lab/   # use them, no network
    eagleeye netpoll ... --upload --config netagent.json                 # and send it, as the agent would

Passwords and communities never go on the command line (shell history): they come from
--credentials FILE (JSON), EAGLEEYE_SNMP_* variables, or a prompt.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from .. import VERSION
from .crawl import CrawlResult, crawl, parse_ranges
from .recorded import RecordedSession, Recorder
from .snmp import Credentials, Session

_ENV = {"version": "EAGLEEYE_SNMP_VERSION", "community": "EAGLEEYE_SNMP_COMMUNITY", "user": "EAGLEEYE_SNMP_USER",
        "auth_protocol": "EAGLEEYE_SNMP_AUTH_PROTOCOL", "auth_key": "EAGLEEYE_SNMP_AUTH_KEY",
        "priv_protocol": "EAGLEEYE_SNMP_PRIV_PROTOCOL", "priv_key": "EAGLEEYE_SNMP_PRIV_KEY"}


def add_parser(sub: Any) -> None:
    p = sub.add_parser("netpoll", help="crawl routers and switches over SNMP from seed devices; nothing is uploaded")
    p.add_argument("--seed", action="append", required=True, help="a router or switch to start from (repeatable)")
    p.add_argument("--allow", action="append", default=[],
                   help="a range the crawl may poll, e.g. 10.0.0.0/8 (repeatable); without it only the seeds are polled")
    p.add_argument("--depth", type=int, default=3, help="CDP/LLDP hops from a seed (default 3)")
    p.add_argument("--credentials", type=Path, help="JSON file: version, user, auth_protocol, auth_key, "
                                                    "priv_protocol, priv_key (or community for v2c)")
    p.add_argument("--snmp-version", choices=("3", "2c"), help="default 3")
    p.add_argument("--snmp-user")
    p.add_argument("--auth-protocol", help="MD5, SHA (default), SHA224, SHA256, SHA384, SHA512")
    p.add_argument("--priv-protocol", help="AES (default) or none")
    p.add_argument("--timeout", type=float, default=2.0, help="seconds per try (default 2)")
    p.add_argument("--retries", type=int, default=1)
    p.add_argument("--record", type=Path, help="write every answer to this folder (net-snmp text, one file per device)")
    p.add_argument("--replay", type=Path, help="answer from a recorded folder instead of the network")
    p.add_argument("--truth", type=Path, help="score against a ground-truth devices CSV")
    p.add_argument("--links", type=Path, help="with --truth: score the links against this CSV")
    p.add_argument("--json", type=Path, dest="json_out", help="write the full result to this file")
    p.add_argument("--upload", action="store_true",
                   help="also send the result to the server, exactly as the network agent does (needs --config)")
    p.add_argument("--config", type=Path, help="with --upload: the network agent's settings (API URL, agent ID, API key)")


def credentials(args: argparse.Namespace, env: Optional[dict[str, str]] = None,
                ask: Any = getpass.getpass) -> Credentials:
    env = os.environ if env is None else env
    values: dict[str, Any] = {}
    if args.credentials:
        values.update(json.loads(args.credentials.read_text(encoding="utf-8-sig")))
    for key, name in _ENV.items():
        if env.get(name) and key not in values:
            values[key] = env[name]
    for key, flag in (("version", args.snmp_version), ("user", args.snmp_user),
                      ("auth_protocol", args.auth_protocol), ("priv_protocol", args.priv_protocol)):
        if flag is not None:
            values[key] = flag
    creds = Credentials.from_dict(values)
    if creds.priv_protocol.lower() == "none":
        creds.priv_protocol = ""
    interactive = sys.stdin is not None and sys.stdin.isatty()
    if creds.version == "2c" and not creds.community and interactive:
        creds.community = ask("SNMP community: ")
    if creds.version == "3":
        if not creds.user and interactive:
            creds.user = input("SNMPv3 user: ").strip()
        if not creds.auth_key and interactive:
            creds.auth_key = ask(f"Authentication password for {creds.user}: ")
        if creds.priv_protocol and not creds.priv_key and interactive:
            creds.priv_key = ask(f"Privacy password for {creds.user}: ")
    creds.check()
    return creds


def run(args: argparse.Namespace) -> int:
    recorders: list[Recorder] = []
    if args.replay:
        if not args.replay.is_dir():
            print(f"No recording folder {args.replay}", file=sys.stderr)
            return 2

        def open_session(address: str) -> Any:
            return RecordedSession.from_dir(args.replay, address)
    else:
        try:
            creds = credentials(args)
        except (ValueError, OSError) as exc:
            print(f"SNMP credentials: {exc}", file=sys.stderr)
            return 2

        def open_session(address: str) -> Any:
            session = Session(address, creds, timeout=args.timeout, retries=args.retries)
            if args.record is None:
                return session
            rec = Recorder(session)
            recorders.append(rec)
            return rec
    try:
        allowed = parse_ranges(args.allow)
    except ValueError as exc:
        print(f"--allow: {exc}", file=sys.stderr)
        return 2
    if args.upload:
        result = _crawl_and_upload(args, open_session)
        if result is None:
            return 1
    else:
        result = crawl(args.seed, open_session, allowed, depth=args.depth, progress=lambda m: print(f"  {m}"))
    print_result(result, allowed)
    if args.record is not None:
        header = f"recorded by eagleeye netpoll {VERSION} on {datetime.now():%Y-%m-%d %H:%M}"
        written = [p for rec in recorders for p in rec.write(args.record, header)]
        print(f"\nRecorded {len(written)} file(s) in {args.record}")
    if args.truth:
        from .truth import load_csv, score
        print_score(score(result, load_csv(args.truth), load_csv(args.links) if args.links else None))
    if args.json_out:
        args.json_out.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
        print(f"Result written to {args.json_out}")
    return 0 if result.devices else 1


def _crawl_and_upload(args: argparse.Namespace, open_session: Any) -> Optional[CrawlResult]:
    """One crawl through NetworkAgentService, the code the service runs: a heartbeat as a
    network agent, the crawl, the addresses' ingest and the topology."""
    import dataclasses
    from ..config import ConfigError, load_settings
    from ..vendor import mac_vendor
    from .service import NetworkAgentService
    if not args.config:
        print("--upload needs --config: the network agent's settings file", file=sys.stderr)
        return None
    try:
        settings = load_settings(args.config)
    except ConfigError as exc:
        print(f"Config: {exc}", file=sys.stderr)
        return None
    missing = [p for p in settings.problems() if p.split()[0] in ("api_url", "api_key", "agent_id")]
    if missing:
        print("Cannot upload: " + "; ".join(missing), file=sys.stderr)
        return None
    settings = dataclasses.replace(settings, kind="network", network_seeds=list(args.seed),
                                   network_ranges=list(args.allow), network_depth=args.depth)
    svc = NetworkAgentService(settings, open_session=open_session, vendor=mac_vendor)
    svc._heartbeat()
    if not svc.last_heartbeat_ok:
        print("The server did not answer the heartbeat (API URL, agent ID or key?)", file=sys.stderr)
        return None
    result = svc.crawl_once(trigger="manual")
    record = svc.history[-1] if svc.history else None
    if record is not None:
        print(f"\nUpload: {record.status}" + (f" ({record.error})" if record.error else "")
              + (f"; {svc.last_crawl['topology']}" if svc.last_crawl else ""))
    return result


def print_result(r: CrawlResult, allowed: list) -> None:
    print(f"\nDevices ({len(r.devices)})")
    print(f"  {'NAME':<14} {'ADDRESS':<15} {'OS':<16} {'VERSION':<24} {'PORTS':>5} {'ARP':>5} {'MACS':>5} "
          f"{'NEIGH':>5}  {'FOUND VIA':<22} TIME")
    for d in r.devices:
        print(f"  {d.label[:14]:<14} {d.address:<15} {d.os[:16]:<16} {d.version[:24]:<24} {len(d.interfaces):>5} "
              f"{len(d.arp):>5} {len(d.fdb):>5} {len(d.neighbors):>5}  {d.found_via[:22]:<22} {d.seconds}s")
    if r.links:
        print(f"\nLinks ({len(r.links)})")
        for l in r.links:
            seen = " and ".join(l["seen_from"])
            print(f"  {l['a']['device']} {l['a']['port']}  <->  {l['b']['device']} {l['b']['port']}"
                  f"    {'+'.join(l['protocols'])}, seen from {seen}")
    print(f"\nAddresses ({len(r.hosts)})")
    print(f"  {'IP':<15} {'MAC':<18} {'DEVICE':<8} {'VLAN':>4}  {'SEEN BY':<10} {'INTERFACE':<12} LOCATION")
    for h in r.hosts:
        loc = h.get("location")
        where = f"{loc['switch']} {loc['port']}" + (" (ambiguous)" if loc["ambiguous"] else "") if loc else "-"
        print(f"  {(h['ip'] or '-'):<15} {h['mac']:<18} {(h['device'] or '-')[:8]:<8} {str(h['vlan'] or '-'):>4}  "
              f"{','.join(h['seen_by'])[:10]:<10} {h['interface'][:12]:<12} {where}")
    if r.networks:
        print(f"\nNetworks ({len(r.networks)})")
        for n in r.networks:
            on = ", ".join(f"{a['device']} {a['interface']} {a['ip']}" for a in n["addresses"])
            print(f"  {n['network']:<18} VLAN {str(n['vlan'] or '-'):<4} {on}")
    notes = [f"{d.label}: {n}" for d in r.devices for n in d.notes] + \
            [f"{d.label}: could not read {e}" for d in r.devices for e in d.errors]
    if notes:
        print("\nNotes")
        for n in notes:
            print(f"  {n}")
    if r.skipped:
        print("\nNeighbours not polled")
        for s in r.skipped:
            print(f"  {s['name'] or '?'} {s['address'] or ''}: {s['reason']} ({s['via']})")
        if not allowed:
            print("  (give --allow RANGE to let the crawl go past the seeds)")
    if r.unreachable:
        print("\nNo answer")
        for u in r.unreachable:
            print(f"  {u['address']}: {u['error']} ({u['via']})")
    print(f"\nTook {r.seconds}s, {r.requests} SNMP requests, {r.bytes_received / 1024:.1f} KB received")


def print_score(s: dict[str, Any]) -> None:
    print(f"\nAgainst the ground truth: addresses {s['found']}/{s['addresses']}, MACs {s['mac_right']}/{s['mac_checked']}, "
          f"device names {s['names_right']}/{s['names_checked']}, locations right {s['located_right']}, "
          f"wrong {s['located_wrong']}, not located {s['not_located']}")
    for row in s["rows"]:
        bits = [f"{k} {v}" for k, v in row.items() if k in ("mac", "location")]
        print(f"  {row['ip']:<15} {row['name'][:10]:<10} {'found' if row['found'] else 'MISSING':<8} {'; '.join(bits)}")
    links = s.get("links")
    if links:
        print(f"Links: {links['found']}/{links['expected']} found")
        for m in links["missed"]:
            print(f"  missed {m}")
        for x in links["extra"]:
            print(f"  not in the truth: {x}")
        for v in links["not_visible"]:
            print(f"  not visible to CDP/LLDP (expected): {v['link']}{' - found anyway' if v['found'] else ''}")
