from __future__ import annotations

import json
import threading
import uuid
from pathlib import Path
from typing import TextIO

from antivenom.audit.events import AuditEvent
from antivenom.core.chunk import Chunk
from antivenom.core.result import ScanResult


class AuditLogger:
    """Writes structured JSONL audit events.

    Thread-safe: a lock serializes the write+flush so concurrent scans from
    multiple threads can never interleave partial lines in the JSONL file.
    """

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path) if path else None
        self._fh: TextIO | None = None
        self._lock = threading.Lock()
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
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
            line = json.dumps(event.__dict__, ensure_ascii=False, default=str) + "\n"
            with self._lock:
                if self._fh:  # re-check under lock in case of concurrent close()
                    self._fh.write(line)
                    self._fh.flush()
        return event

    def close(self) -> None:
        with self._lock:
            if self._fh:
                try:
                    self._fh.close()
                finally:
                    self._fh = None

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
