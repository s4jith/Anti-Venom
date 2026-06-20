from __future__ import annotations
import asyncio
import hashlib
import time
import uuid
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.pipeline import DetectionPipeline
from antivenom.core.result import ScanResult, Severity
from antivenom.layers.pattern import PatternLayer
from antivenom.layers.structural import StructuralLayer
from antivenom.layers.canary import CanaryLayer


def _make_chunk_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class AntiVenomScanner:
    """Main scanner orchestrator. Thread-safe; async-native."""

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._pipeline = self._build_pipeline()
        self._audit_logger: Any = None
        self._quarantine: Any = None
        self._initialized = False

    def _build_pipeline(self) -> DetectionPipeline:
        enabled = self.config.enabled_layers
        fast: list[Any] = []
        if enabled is None or "pattern" in enabled:
            fast.append(PatternLayer(self.config.layer_configs.get("pattern", {})))
        if enabled is None or "structural" in enabled:
            fast.append(StructuralLayer(self.config.layer_configs.get("structural", {})))
        if enabled is None or "canary" in enabled:
            fast.append(CanaryLayer(self.config.layer_configs.get("canary", {})))
        return DetectionPipeline(fast_layers=fast, config=self.config)

    def _ensure_audit(self) -> None:
        if self._initialized:
            return
        from antivenom.audit.audit_log import AuditLogger
        from antivenom.audit.quarantine import QuarantineStore
        self._audit_logger = AuditLogger(path=self.config.audit_log_path)
        self._quarantine = QuarantineStore(db_path=self.config.db_path)
        self._initialized = True

    async def ascan(self, chunk: Chunk) -> ScanResult:
        self._ensure_audit()
        start = time.perf_counter()
        is_poisoned, confidence, layer_results = await self._pipeline.run(chunk)
        duration_ms = (time.perf_counter() - start) * 1000

        chunk_id = _make_chunk_id(chunk.text)
        if is_poisoned:
            result = ScanResult.poisoned(chunk_id, confidence, layer_results, duration_ms)
        else:
            result = ScanResult.clean(chunk_id, layer_results, duration_ms)

        if self._audit_logger:
            self._audit_logger.log(chunk, result)
        if is_poisoned and self.config.quarantine_on_detection and self._quarantine:
            self._quarantine.quarantine(chunk, result)

        return result

    def scan(self, chunk: Chunk) -> ScanResult:
        return asyncio.run(self.ascan(chunk))

    def scan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "") -> ScanResult:
        return self.scan(Chunk(text=text, metadata=metadata or {}, source_id=source_id))

    async def ascan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "") -> ScanResult:
        return await self.ascan(Chunk(text=text, metadata=metadata or {}, source_id=source_id))

    async def ascan_batch(self, chunks: list[Chunk]) -> list[ScanResult]:
        self._ensure_audit()
        sem = asyncio.Semaphore(self.config.async_concurrency)
        async def _bounded(c: Chunk) -> ScanResult:
            async with sem:
                return await self.ascan(c)
        return list(await asyncio.gather(*[_bounded(c) for c in chunks]))

    def scan_batch(self, chunks: list[Chunk]) -> list[ScanResult]:
        return asyncio.run(self.ascan_batch(chunks))
