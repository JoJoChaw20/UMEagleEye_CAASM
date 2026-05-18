#!/usr/bin/env python3
"""
UMEagleEye Bridge — HTTP relay server.

Receives requests from local agents and forwards them to the Cloudflare Worker.
Optionally buffers POST /api/v1/scans/ingest in SQLite when the Worker is
unreachable (BUFFER_MODE=true).

Usage:
    python bridge.py

Config (bridge.env in the same directory, overridden by environment variables):
    WORKER_URL          Cloudflare Worker base URL (required)
    BRIDGE_ID           UUID from dashboard registration
    BRIDGE_API_KEY      API key from dashboard registration
    LISTEN_PORT         Port to listen on (default: 8080)
    BUFFER_MODE         'true' / 'false' (default: false)
    FLUSH_INTERVAL      Seconds between buffer flushes (default: 60)
    HEARTBEAT_INTERVAL  Seconds between bridge heartbeats (default: 30)
"""

import json
import logging
import os
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, urljoin

import requests
from requests.exceptions import RequestException

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BRIDGE_VERSION: str = "1.0.0"

# Hop-by-hop headers that must not be forwarded (RFC 2616 §13.5.1)
HOP_BY_HOP: frozenset = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "host",
    # Also strip content-encoding to avoid double-decompression
    "content-encoding",
})

# Maximum relay attempts before dropping a buffered entry
MAX_FLUSH_ATTEMPTS: int = 5

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BRIDGE] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def _load_env_file(path: Path) -> Dict[str, str]:
    """Parse a simple KEY=VALUE env file (ignores comments and blank lines)."""
    result: Dict[str, str] = {}
    if not path.exists():
        return result
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            result[key.strip()] = value.strip()
    return result


def _load_config() -> Dict[str, str]:
    """Load config from bridge.env then override with environment variables."""
    env_file = Path(__file__).parent / "bridge.env"
    cfg = _load_env_file(env_file)
    # Environment variables win
    for key in (
        "WORKER_URL",
        "BRIDGE_ID",
        "BRIDGE_API_KEY",
        "LISTEN_PORT",
        "BUFFER_MODE",
        "FLUSH_INTERVAL",
        "HEARTBEAT_INTERVAL",
    ):
        if key in os.environ:
            cfg[key] = os.environ[key]
    return cfg


CONFIG: Dict[str, str] = _load_config()

WORKER_URL: str = CONFIG.get("WORKER_URL", "").rstrip("/")
BRIDGE_ID: Optional[str] = CONFIG.get("BRIDGE_ID") or None
BRIDGE_API_KEY: Optional[str] = CONFIG.get("BRIDGE_API_KEY") or None
LISTEN_PORT: int = int(CONFIG.get("LISTEN_PORT", "8080"))
BUFFER_MODE: bool = CONFIG.get("BUFFER_MODE", "false").lower() == "true"
FLUSH_INTERVAL: int = int(CONFIG.get("FLUSH_INTERVAL", "60"))
HEARTBEAT_INTERVAL: int = int(CONFIG.get("HEARTBEAT_INTERVAL", "30"))

# ---------------------------------------------------------------------------
# SQLite buffer
# ---------------------------------------------------------------------------

DB_PATH: Path = Path(__file__).parent / "bridge-buffer.db"
_db_lock: threading.Lock = threading.Lock()


def _init_db() -> None:
    """Create the buffer table if it doesn't exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS buffer (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                method      TEXT NOT NULL,
                path        TEXT NOT NULL,
                query       TEXT NOT NULL DEFAULT '',
                headers     TEXT NOT NULL DEFAULT '{}',
                body        BLOB,
                attempts    INTEGER NOT NULL DEFAULT 0,
                created_at  REAL NOT NULL
            )
            """
        )
        conn.commit()


def _queue_request(
    method: str,
    path: str,
    query: str,
    headers: Dict[str, str],
    body: Optional[bytes],
) -> None:
    """Insert a request into the SQLite buffer."""
    with _db_lock, sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO buffer (method, path, query, headers, body, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (method, path, query, json.dumps(headers), body, time.time()),
        )
        conn.commit()


def _get_queue_depth() -> int:
    """Return the number of entries in the buffer."""
    if not BUFFER_MODE:
        return 0
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT COUNT(*) FROM buffer").fetchone()
            return row[0] if row else 0
    except Exception:
        return 0


def _flush_buffer() -> None:
    """Try to forward all buffered requests to the Worker."""
    try:
        with _db_lock, sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT id, method, path, query, headers, body, attempts FROM buffer ORDER BY id"
            ).fetchall()
    except Exception as exc:
        logger.error("Buffer read failed: %s", exc)
        return

    if not rows:
        return

    logger.info("Flushing %d buffered request(s)...", len(rows))

    for row in rows:
        row_id, method, path, query, headers_json, body, attempts = row
        try:
            headers: Dict[str, str] = json.loads(headers_json)
        except Exception:
            headers = {}

        target_url = _build_url(path, query)
        success = False
        try:
            resp = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                timeout=10,
                allow_redirects=False,
            )
            if resp.status_code < 500:
                logger.info("Flushed buffered entry id=%d → %d", row_id, resp.status_code)
                success = True
            else:
                logger.warning(
                    "Worker returned %d for buffered entry id=%d", resp.status_code, row_id
                )
        except RequestException as exc:
            logger.warning("Failed to flush entry id=%d: %s", row_id, exc)

        new_attempts = attempts + 1
        if success or new_attempts >= MAX_FLUSH_ATTEMPTS:
            if not success:
                logger.error(
                    "Dropping buffered entry id=%d after %d failed attempt(s)", row_id, new_attempts
                )
            with _db_lock, sqlite3.connect(DB_PATH) as conn:
                conn.execute("DELETE FROM buffer WHERE id = ?", (row_id,))
                conn.commit()
        else:
            with _db_lock, sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE buffer SET attempts = ? WHERE id = ?", (new_attempts, row_id)
                )
                conn.commit()


def _worker_reachable() -> bool:
    """Return True if the Worker health endpoint responds within 5 s."""
    health_url = WORKER_URL.rstrip("/api/v1").rstrip("/") + "/health"
    try:
        resp = requests.get(health_url, timeout=5)
        return resp.status_code < 500
    except RequestException:
        # Fallback: try the root
        try:
            root_url = WORKER_URL.split("/api/")[0]
            resp = requests.get(root_url, timeout=5)
            return resp.status_code < 500
        except RequestException:
            return False

# ---------------------------------------------------------------------------
# Background threads
# ---------------------------------------------------------------------------

def _flush_thread() -> None:
    """Background thread: periodically flush the buffer when Worker is reachable."""
    logger.info("Buffer flush thread started (interval=%ds)", FLUSH_INTERVAL)
    while True:
        time.sleep(FLUSH_INTERVAL)
        if _get_queue_depth() > 0 and _worker_reachable():
            _flush_buffer()


def _local_ip() -> str:
    """Best-effort local IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _heartbeat_thread() -> None:
    """Background thread: POST bridge heartbeat to Worker every HEARTBEAT_INTERVAL s."""
    if not BRIDGE_ID or not BRIDGE_API_KEY:
        logger.warning(
            "BRIDGE_ID or BRIDGE_API_KEY not set — heartbeat disabled. "
            "Bridge will still relay requests."
        )
        return

    heartbeat_url = f"{WORKER_URL}/bridges/{BRIDGE_ID}/heartbeat"
    logger.info("Heartbeat thread started (interval=%ds, url=%s)", HEARTBEAT_INTERVAL, heartbeat_url)

    while True:
        time.sleep(HEARTBEAT_INTERVAL)
        payload = {
            "version": BRIDGE_VERSION,
            "bridge_ip": _local_ip(),
            "queue_depth": _get_queue_depth(),
        }
        try:
            resp = requests.post(
                heartbeat_url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {BRIDGE_API_KEY}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            logger.debug("Heartbeat → %d", resp.status_code)
        except RequestException as exc:
            logger.warning("Heartbeat failed: %s", exc)

# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _build_url(path: str, query: str) -> str:
    """Concatenate WORKER_URL + path + optional query string."""
    url = WORKER_URL.rstrip("/") + path
    if query:
        url = f"{url}?{query}"
    return url

# ---------------------------------------------------------------------------
# Allowed routes
# ---------------------------------------------------------------------------

# (method, path_prefix_or_exact)
_ALLOWED_ROUTES: List[Tuple[str, str]] = [
    ("GET",  "/api/v1/scans/pending"),
    ("POST", "/api/v1/scans/ingest"),
    ("POST", "/api/v1/agents/"),        # /api/v1/agents/{agentId}/heartbeat
]

_BUFFERABLE_PATH: str = "/api/v1/scans/ingest"


def _match_route(method: str, path: str) -> bool:
    """Return True if the method + path is in the allowed relay list."""
    method = method.upper()
    for allowed_method, allowed_prefix in _ALLOWED_ROUTES:
        if method != allowed_method:
            continue
        if path == allowed_prefix or path.startswith(allowed_prefix):
            return True
    return False

# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class BridgeHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that relays whitelisted paths to the Worker."""

    server_version = f"UMEagleEye-Bridge/{BRIDGE_VERSION}"

    # Silence default request logging — we do our own
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        parsed = urlparse(self.path)
        path: str = parsed.path
        query: str = parsed.query

        # Local health endpoint
        if method == "GET" and path == "/health":
            self._handle_health()
            return

        # Security: only whitelisted routes
        if not _match_route(method, path):
            self._send_json(404, {"error": "not_found", "path": path})
            logger.info("%s %s → 404 (not allowed)", method, path)
            return

        # Buffer mode: queue ingest when Worker is unreachable
        if (
            BUFFER_MODE
            and method == "POST"
            and path == _BUFFERABLE_PATH
            and not _worker_reachable()
        ):
            self._handle_buffer(method, path, query)
            return

        self._forward(method, path, query)

    # ------------------------------------------------------------------
    # Local /health
    # ------------------------------------------------------------------

    def _handle_health(self) -> None:
        body = {
            "status": "ok",
            "bridge_version": BRIDGE_VERSION,
            "mode": "buffer" if BUFFER_MODE else "relay",
            "worker_url": WORKER_URL,
            "queue_depth": _get_queue_depth(),
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        self._send_json(200, body)

    # ------------------------------------------------------------------
    # Buffer
    # ------------------------------------------------------------------

    def _handle_buffer(self, method: str, path: str, query: str) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body: Optional[bytes] = self.rfile.read(length) if length else None
        fwd_headers = self._collect_forward_headers()
        _queue_request(method, path, query, fwd_headers, body)
        logger.info("%s %s → 202 queued (queue depth=%d)", method, path, _get_queue_depth())
        self._send_json(202, {"status": "queued"})

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    def _collect_forward_headers(self) -> Dict[str, str]:
        """Return filtered headers suitable for forwarding to the Worker."""
        result: Dict[str, str] = {}
        for name, value in self.headers.items():
            if name.lower() in HOP_BY_HOP:
                continue
            result[name] = value
        return result

    def _forward(self, method: str, path: str, query: str) -> None:
        target_url = _build_url(path, query)
        fwd_headers = self._collect_forward_headers()

        length = int(self.headers.get("Content-Length", 0))
        body: Optional[bytes] = self.rfile.read(length) if length else None

        logger.info("%s %s → %s", method, self.path, target_url)

        try:
            resp = requests.request(
                method=method,
                url=target_url,
                headers=fwd_headers,
                data=body,
                timeout=30,
                allow_redirects=False,
                stream=True,
            )
        except RequestException as exc:
            logger.error("Worker request failed: %s", exc)
            self._send_json(502, {"error": "bad_gateway", "detail": str(exc)})
            return

        # Send status line
        self.send_response(resp.status_code)

        # Forward response headers (strip hop-by-hop)
        for name, value in resp.headers.items():
            if name.lower() in HOP_BY_HOP:
                continue
            self.send_header(name, value)
        self.end_headers()

        # Stream response body
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    self.wfile.write(chunk)
        except Exception as exc:
            logger.warning("Error streaming response body: %s", exc)

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def _send_json(self, status: int, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if not WORKER_URL:
        logger.error("WORKER_URL is not set. Create agent/bridge.env or set the environment variable.")
        sys.exit(1)

    logger.info("UMEagleEye Bridge v%s starting", BRIDGE_VERSION)
    logger.info("  Worker URL   : %s", WORKER_URL)
    logger.info("  Listen port  : %d", LISTEN_PORT)
    logger.info("  Mode         : %s", "buffer" if BUFFER_MODE else "relay")

    if BUFFER_MODE:
        _init_db()
        logger.info("  Buffer DB    : %s", DB_PATH)
        t_flush = threading.Thread(target=_flush_thread, daemon=True, name="flush")
        t_flush.start()

    t_hb = threading.Thread(target=_heartbeat_thread, daemon=True, name="heartbeat")
    t_hb.start()

    server = HTTPServer(("0.0.0.0", LISTEN_PORT), BridgeHandler)
    logger.info("Bridge listening on 0.0.0.0:%d — press Ctrl+C to stop", LISTEN_PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down bridge...")
        server.server_close()


if __name__ == "__main__":
    main()
