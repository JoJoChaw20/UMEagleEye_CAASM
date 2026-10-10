"""HTTP client for the EagleEye API (or a bridge in front of it).

Same endpoints and payloads as the original agent, so the backend needs no change.
Network errors and 5xx responses are retried a few times; other 4xx responses are not.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

import requests

from . import VERSION
from .netinfo import default_gateway, local_ip

log = logging.getLogger("eagleeye.api")

RETRY_DELAYS = (2.0, 5.0)   # seconds before the 2nd and 3rd attempt


@dataclass
class IngestResult:
    ok: bool
    hosts_discovered: int = 0
    assets_upserted: int = 0
    error: Optional[str] = None


class AgentClient:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        agent_id: str,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.agent_id = agent_id
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "X-Agent-ID": agent_id,
            "Content-Type": "application/json",
            "User-Agent": f"EagleEye-Agent/{VERSION}",
        })

    # ── internals ──
    def _request(self, method: str, path: str, timeout: float, **kwargs: Any) -> requests.Response:
        """One request with retry on connection errors, timeouts and 5xx."""
        url = f"{self.api_url}{path}"
        last_exc: Optional[Exception] = None
        for attempt in range(len(RETRY_DELAYS) + 1):
            if attempt:
                self._sleep(RETRY_DELAYS[attempt - 1])
            try:
                resp = self.session.request(method, url, timeout=timeout, **kwargs)
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                continue
            if resp.status_code >= 500:
                last_exc = requests.HTTPError(f"{resp.status_code} from {path}", response=resp)
                continue
            return resp
        assert last_exc is not None
        raise last_exc

    @staticmethod
    def _detail(resp: requests.Response) -> str:
        try:
            body = resp.json()
            if isinstance(body, dict) and body.get("detail"):
                return str(body["detail"])
        except ValueError:
            pass
        return f"HTTP {resp.status_code}"

    # ── endpoints ──
    def send_heartbeat(self) -> bool:
        payload: dict[str, Any] = {"version": VERSION, "gateway_ip": local_ip()}
        gateway = default_gateway()
        if gateway:
            payload["default_gateway"] = gateway
        try:
            resp = self._request("POST", f"/agents/{self.agent_id}/heartbeat", 15, data=json.dumps(payload))
            resp.raise_for_status()
            return True
        except requests.RequestException as exc:
            log.warning("Heartbeat failed: %s", exc)
            return False

    def get_pending_scans(self) -> list[dict[str, Any]]:
        try:
            resp = self._request("GET", "/scans/pending", 30)
            resp.raise_for_status()
            return resp.json().get("scans", [])
        except requests.RequestException as exc:
            log.error("Failed to fetch pending scans: %s", exc)
            return []

    def mark_scan_running(self, scan_id: str) -> None:
        try:
            self.session.post(f"{self.api_url}/scans/{scan_id}/start", timeout=10)
        except requests.RequestException as exc:
            log.warning("Could not mark scan %s as running: %s", scan_id[:8], exc)

    def get_scan_status(self, scan_id: str) -> Optional[str]:
        """Scan status, so a running local process can honour a cancellation."""
        try:
            resp = self.session.get(f"{self.api_url}/scans/agent-status/{scan_id}", timeout=10)
            resp.raise_for_status()
            return resp.json().get("status")
        except requests.RequestException as exc:
            log.warning("Could not check scan %s status: %s", scan_id[:8], exc)
            return None

    def mark_scan_failed(self, scan_id: str, reason: str) -> None:
        """Mark a scan failed and keep a concise, user-visible reason."""
        body = {"agent_id": self.agent_id, "scan_id": scan_id, "reason": reason[:1000]}
        try:
            self._request("POST", "/scans/fail", 15, data=json.dumps(body)).raise_for_status()
        except requests.RequestException as exc:
            log.warning("Could not mark scan %s as failed: %s", scan_id[:8], exc)

    def ingest(
        self,
        scan_type: str,
        hosts: list[dict[str, Any]],
        scan_id: Optional[str] = None,
        network: Optional[dict[str, Any]] = None,
    ) -> IngestResult:
        """POST /scans/ingest. scan_id is optional only for passive auto-flushes
        (the backend then creates the scan record itself)."""
        payload: dict[str, Any] = {"agent_id": self.agent_id, "scan_type": scan_type, "hosts": hosts}
        if scan_id:
            payload["scan_id"] = scan_id
        if network:
            payload["network"] = network
        try:
            resp = self._request("POST", "/scans/ingest", 120, data=json.dumps(payload))
        except requests.RequestException as exc:
            return IngestResult(False, error=f"could not reach the server: {exc}")
        if not resp.ok:
            return IngestResult(False, error=f"server rejected the results ({self._detail(resp)})")
        data = resp.json()
        return IngestResult(True, data.get("hosts_discovered", 0), data.get("assets_upserted", 0))
