"""Progress events. The runner emits them; the CLI logs them and the GUI will render them."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class EventKind(str, Enum):
    PIPELINE_STARTED = "pipeline_started"
    STAGE_STARTED = "stage_started"
    STAGE_PROGRESS = "stage_progress"
    STAGE_FINISHED = "stage_finished"
    STAGE_SKIPPED = "stage_skipped"
    STAGE_FAILED = "stage_failed"
    PIPELINE_FINISHED = "pipeline_finished"


@dataclass(frozen=True)
class PipelineEvent:
    kind: EventKind
    pipeline: str
    stage: Optional[str] = None
    message: str = ""
    current: Optional[int] = None
    total: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
