"""Endpoint inventory pipeline: collect facts about this machine, then upload them."""

from __future__ import annotations

from typing import Any, Callable, Optional

from ..api import AgentClient
from ..collectors import collect_inventory
from ..pipeline.runner import PipelineContext, Stage, StageError


class LocalInventoryStage(Stage):
    name = "inventory"
    label = "Collect inventory of this machine"

    def __init__(
        self,
        collector: Callable[..., dict[str, Any]] = collect_inventory,
        options: Optional[dict[str, bool]] = None,
    ) -> None:
        self.collector = collector
        self.options = options or {}

    def run(self, ctx: PipelineContext) -> None:
        ctx.progress("Reading hardware, OS, patches, security settings, network and installed software")
        inventory = self.collector(**self.options)
        ctx.summary["inventory"] = inventory
        ctx.progress(
            f"{len(inventory.get('software') or [])} application(s), "
            f"{len((inventory.get('network') or {}).get('listening') or [])} listening port(s), "
            f"{len(inventory.get('errors') or [])} section error(s)"
        )
        if inventory.get("unavailable"):
            ctx.progress("Run as Administrator to also read: " + ", ".join(inventory["unavailable"]))


class OpenScapStage(Stage):
    """Linux, when the dashboard's OpenSCAP setting is on: the last CIS Level 1 result goes with the
    inventory, after running OpenSCAP again when a week has passed (openscap.py)."""
    name = "openscap"
    label = "OpenSCAP CIS Level 1"

    def __init__(self, scanner: Any = None) -> None:
        self.scanner = scanner

    def run(self, ctx: PipelineContext) -> None:
        inventory = ctx.summary.get("inventory") or {}
        if inventory.get("platform") != "linux":
            return
        from ..collectors.linux import parse_os_release
        from ..openscap import OpenScap
        try:
            with open("/etc/os-release", encoding="utf-8") as fh:
                os_release = parse_os_release(fh.read())
        except OSError:
            os_release = {}
        result = (self.scanner or OpenScap()).result(os_release, (inventory.get("os") or {}).get("role"))
        inventory["openscap"] = {k: v for k, v in result.items() if k not in ("content_path", "content_mtime")}
        if result.get("status") == "ok":
            c = result["counts"]
            ctx.progress(f"OpenSCAP: {c['pass']} pass, {c['fail']} fail, {c['notapplicable']} not applicable")
        else:
            ctx.progress(f"OpenSCAP: {result.get('reason')}")


class InventoryUploadStage(Stage):
    name = "upload"
    label = "Upload inventory"

    def __init__(self, client: AgentClient) -> None:
        self.client = client

    def run(self, ctx: PipelineContext) -> None:
        result = self.client.send_inventory(ctx.summary["inventory"])
        if not result.ok:
            raise StageError(result.error or "upload failed")
        ctx.summary["inventory_result"] = result
        how = "created a new asset" if result.created else f"matched asset by {result.matched_by}"
        sw = result.software or {}
        ctx.progress(
            f"Server {how}; software +{sw.get('added', 0)} -{sw.get('removed', 0)} ={sw.get('unchanged', 0)}"
        )


class InventoryDryRunStage(Stage):
    name = "upload"
    label = "Prepare inventory (dry run)"

    def __init__(self, sink: Optional[Callable[[dict[str, Any]], None]] = None) -> None:
        self.sink = sink

    def run(self, ctx: PipelineContext) -> None:
        if self.sink:
            self.sink(ctx.summary["inventory"])
