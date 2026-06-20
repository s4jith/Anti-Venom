from __future__ import annotations
import json
import uuid
from pathlib import Path
from typing import TextIO

from antivenom.audit.events import AuditEvent
from antivenom.core.chunk import Chunk
from antivenom.core.result import ScanResult


class AuditLogger:
    """Writes structured JSONL audit events. Sync writes (v0.1)."""

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path) if path else None
        self._fh: TextIO | None = None
        if self._path:
            self._fh = self._path.open("a", encoding="utf-8")

    def log(self, chunk: Chunk, result: ScanResult) -> AuditEvent:
        event = AuditEvent.now(
            event_id=str(uuid.uuid4()),
            chunk_id=result.chunk_id,
            source_id=chunk.source_id,
            verdict=result.severity.value,
            confidence=result.confidence,
            layers_triggered=[r.layer_name for r in result.layer_results if r.triggered],
            evidence_summary=[e for r in result.layer_results for e in r.evidence][:10],
            metadata=chunk.metadata,
        )
        if self._fh:
            self._fh.write(json.dumps(event.__dict__) + "\n")
            self._fh.flush()
        return event

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def __del__(self) -> None:
        self.close()
