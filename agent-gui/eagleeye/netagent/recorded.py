"""Recorded SNMP answers: net-snmp's text output (snmpget/snmpwalk, numeric OIDs) read back as
a session, and our own sessions written out in the same format.

A recording directory holds one file per device and VLAN context:

    10.99.0.1.txt           what 10.99.0.1 answered
    10.10.99.2@vlan-10.txt  what it answered for VLAN 10 (no file: that context never answers)

Lines starting with # are comments. `netpoll --record DIR` writes these; `--replay DIR` reads them.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Optional

from .snmp import Oid, OidLike, SnmpTimeout, oid_text, to_oid

_LINE = re.compile(r"^(?:iso|\.?1)((?:\.\d+)+)\s*=\s*(.*)$")
_SKIP = ("No Such Object", "No Such Instance", "No more variables")


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text.replace('\\"', '"').replace("\\\\", "\\")


def parse_value(raw: str) -> Any:
    raw = raw.strip()
    if raw == '""':
        return b""
    kind, _, rest = raw.partition(":")
    rest = rest.strip()
    kind = kind.strip()
    if kind == "STRING":
        return _unquote(rest).encode("utf-8")
    if kind == "Hex-STRING":
        return bytes.fromhex(rest.replace("\n", " "))
    if kind in ("INTEGER", "Counter32", "Gauge32", "Counter64", "Unsigned32", "Timeticks"):
        m = re.search(r"\((\d+)\)", rest) if kind == "Timeticks" or "(" in rest else None
        return int(m.group(1)) if m else int(rest.split()[0])
    if kind == "IpAddress":
        return rest
    if kind == "OID":
        return (1,) + to_oid(rest[3:]) if rest.startswith("iso") else to_oid(rest)
    raise ValueError(f"unknown value type: {raw[:40]}")


def parse_text(text: str) -> list[tuple[Oid, Any]]:
    """(oid, value) of every value in net-snmp output; errors and missing values are skipped."""
    entries: list[list[Any]] = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = _LINE.match(line)
        if m:
            entries.append([(1,) + to_oid(m.group(1)), m.group(2)])
        elif entries and line.strip() and not line.startswith(("Timeout", "snmpwalk", "snmpget")):
            entries[-1][1] += "\n" + line         # a value that runs over several lines
    out = []
    for oid, raw in entries:
        if raw.startswith(_SKIP):
            continue
        out.append((oid, parse_value(raw)))
    return sorted(out)


def format_value(value: Any) -> str:
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, int):
        return f"INTEGER: {value}"
    if isinstance(value, str):
        return f"IpAddress: {value}"
    if isinstance(value, tuple):
        return f"OID: {oid_text(value)}"
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
            if text.isprintable() or all(c.isprintable() or c in "\r\n\t" for c in text):
                return 'STRING: "' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        except UnicodeDecodeError:
            pass
        return "Hex-STRING: " + " ".join(f"{b:02X}" for b in value)
    return 'STRING: ""'


def format_text(values: Iterable[tuple[Oid, Any]]) -> str:
    return "".join(f"{oid_text(oid)} = {format_value(v)}\n" for oid, v in sorted(values))


def _file_name(host: str, vlan: Optional[int]) -> str:
    return f"{host}.txt" if vlan is None else f"{host}@vlan-{vlan}.txt"


class RecordedSession:
    """Answers GET and walk from a recording. A context with no recording times out, like a
    device that does not answer it."""

    def __init__(self, host: str, contexts: dict[Optional[int], list[tuple[Oid, Any]]]) -> None:
        self.host = host
        self.contexts = {k: sorted(v) for k, v in contexts.items()}
        self.requests = 0
        self.bytes_received = 0

    @classmethod
    def from_dir(cls, directory: Path, host: str) -> "RecordedSession":
        contexts: dict[Optional[int], list[tuple[Oid, Any]]] = {}
        main = directory / _file_name(host, None)
        if main.exists():
            contexts[None] = parse_text(main.read_text(encoding="utf-8"))
        for path in directory.glob(f"{host}@vlan-*.txt"):
            contexts[int(path.stem.rsplit("-", 1)[1])] = parse_text(path.read_text(encoding="utf-8"))
        return cls(host, contexts)

    def __enter__(self) -> "RecordedSession":
        return self

    def __exit__(self, *_exc: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def _context(self, vlan: Optional[int]) -> list[tuple[Oid, Any]]:
        self.requests += 1
        if vlan not in self.contexts:
            raise SnmpTimeout(f"no answer from {self.host}")
        return self.contexts[vlan]

    def get(self, oids: Iterable[OidLike], vlan: Optional[int] = None) -> dict[Oid, Any]:
        values = dict(self._context(vlan))
        return {o: values.get(o) for o in map(to_oid, oids)}

    def walk(self, base: OidLike, vlan: Optional[int] = None, limit: int = 100_000) -> list[tuple[Oid, Any]]:
        root = to_oid(base)
        return [(o, v) for o, v in self._context(vlan) if o[:len(root)] == root][:limit]


class Recorder:
    """Wraps a session and keeps everything it answered, to write as a recording."""

    def __init__(self, session: Any) -> None:
        self.session = session
        self.host = session.host
        self.seen: dict[Optional[int], dict[Oid, Any]] = {}

    def __getattr__(self, name: str) -> Any:
        return getattr(self.session, name)

    def __enter__(self) -> "Recorder":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.session.close()

    def get(self, oids: Iterable[OidLike], vlan: Optional[int] = None) -> dict[Oid, Any]:
        out = self.session.get(oids, vlan)
        self.seen.setdefault(vlan, {}).update({o: v for o, v in out.items() if v is not None})
        return out

    def walk(self, base: OidLike, vlan: Optional[int] = None, limit: int = 100_000) -> list[tuple[Oid, Any]]:
        out = self.session.walk(base, vlan, limit)
        self.seen.setdefault(vlan, {}).update(out)
        return out

    def write(self, directory: Path, header: str = "") -> list[Path]:
        directory.mkdir(parents=True, exist_ok=True)
        paths = []
        for vlan, values in self.seen.items():
            path = directory / _file_name(self.host, vlan)
            path.write_text((f"# {header}\n" if header else "") + format_text(values.items()), encoding="utf-8")
            paths.append(path)
        return paths
