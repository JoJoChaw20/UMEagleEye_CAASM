"""Final stage: build the ingest payload and send it (or just print it for a dry run)."""

from __future__ import annotations

import json
from typing import Any, Callable, Optional

from ..api import AgentClient
from ..netinfo import build_network_info
from ..pipeline.runner import PipelineContext, Stage, StageError


class UploadStage(Stage):
    name = "upload"
    label = "Upload results"

    def __init__(self, client: AgentClient, scan_type: str) -> None:
        self.client = client
        self.scan_type = scan_type

    def should_run(self, ctx: PipelineContext) -> bool:
        # An autonomous passive flush with nothing new has nothing to send. A passive
        # scan the dashboard asked for still posts, so its record closes as Completed (0).
        return not (self.scan_type == "passive" and not ctx.hosts and not ctx.scan_id)

    def run(self, ctx: PipelineContext) -> None:
        ctx.network = build_network_info(ctx.subnet if self.scan_type == "active" else None, ctx.hosts)
        ctx.progress(f"Uploading {len(ctx.hosts)} host(s)")
        result = self.client.ingest(
            self.scan_type,
            [h.to_payload() for h in ctx.hosts],
            scan_id=ctx.scan_id,
            network=ctx.network,
        )
        if not result.ok:
            raise StageError(result.error or "upload failed")
        ctx.summary["assets_upserted"] = result.assets_upserted
        ctx.progress(f"Server recorded {result.hosts_discovered} host(s), {result.assets_upserted} asset(s) upserted")


class DryRunUploadStage(Stage):
    """Builds the exact payload but sends nothing. Used by `eagleeye scan`."""

    name = "upload"
    label = "Prepare payload (dry run)"

    def __init__(self, scan_type: str, sink: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        self.scan_type = scan_type
        self.sink = sink

    def run(self, ctx: PipelineContext) -> None:
        ctx.network = build_network_info(ctx.subnet if self.scan_type == "active" else None, ctx.hosts)
        payload = {
            "scan_type": self.scan_type,
            "hosts": [h.to_payload() for h in ctx.hosts],
            "network": ctx.network,
        }
        ctx.summary["payload"] = payload
        if self.sink:
            self.sink(payload)
        try:
            json.dumps(payload)
        except TypeError as exc:
            raise StageError(f"payload is not JSON serialisable: {exc}") from None
