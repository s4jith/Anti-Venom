from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import importlib.util
import threading
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.pipeline import DetectionPipeline
from antivenom.core.result import ScanResult
from antivenom.layers.canary import CanaryLayer
from antivenom.layers.pattern import PatternLayer
from antivenom.layers.structural import StructuralLayer


def _make_chunk_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


def _run_coro_blocking(coro: Any) -> Any:
    """Run a coroutine to completion from sync code, safely.

    If no event loop is running in the current thread, use asyncio.run().
    If a loop IS already running (FastAPI handler, Jupyter, another async
    framework), asyncio.run() would raise — so we execute the coroutine on a
    dedicated worker thread with its own event loop and block for the result.
    This makes the sync API safe to call from anywhere.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # No running loop in this thread — safe to drive one directly.
        return asyncio.run(coro)

    # A loop is already running; offload to a separate thread.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class AntiVenomScanner:
    """Main scanner orchestrator. Thread-safe and async-native.

    A single scanner instance is safe to share across threads and across
    concurrent async tasks: lazy initialization is guarded by a lock, and the
    audit log, quarantine store, and cache are each internally thread-safe.
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._pipeline = self._build_pipeline()
        self._cache: Any = None
        self._audit_logger: Any = None
        self._quarantine: Any = None
        self._initialized = False
        self._init_lock = threading.Lock()

    def _build_pipeline(self) -> DetectionPipeline:
        enabled = self.config.enabled_layers
        fast: list[Any] = []
        medium: list[Any] = []

        # FAST layers (v0.1)
        if enabled is None or "pattern" in enabled:
            fast.append(PatternLayer(self.config.layer_configs.get("pattern", {})))
        if enabled is None or "structural" in enabled:
            fast.append(StructuralLayer(self.config.layer_configs.get("structural", {})))
        if enabled is None or "canary" in enabled:
            fast.append(CanaryLayer(self.config.layer_configs.get("canary", {})))

        # MEDIUM layers (v0.2 — only if dependencies installed)
        semantic_requested = enabled is None or "semantic" in (enabled or [])
        if semantic_requested and importlib.util.find_spec("sentence_transformers") is not None:
            from antivenom.layers.semantic import SemanticLayer
            medium.append(SemanticLayer(self.config.layer_configs.get("semantic", {})))

        if enabled is None or "cross_chunk" in (enabled or []):
            from antivenom.layers.cross_chunk import CrossChunkLayer
            medium.append(CrossChunkLayer(self.config.layer_configs.get("cross_chunk", {})))

        # SLOW layers (v0.3 — sequential).
        # Classifier auto-loads but gracefully skips when transformers/torch are
        # absent, so it is safe to include by default.
        slow: list[Any] = []
        if enabled is None or "classifier" in (enabled or []):
            from antivenom.layers.classifier import ClassifierLayer
            slow.append(ClassifierLayer(self.config.layer_configs.get("classifier", {})))
        # LLM Judge calls an external Ollama service and adds real latency, so it
        # is OPT-IN: only enabled when explicitly named in enabled_layers. It is
        # never activated by the "all layers" (enabled is None) default.
        if enabled is not None and "llm_judge" in enabled:
            from antivenom.layers.llm_judge import LLMJudgeLayer
            slow.append(LLMJudgeLayer(**self.config.layer_configs.get("llm_judge", {})))

        return DetectionPipeline(fast_layers=fast, medium_layers=medium, slow_layers=slow, config=self.config)

    def _ensure_audit(self) -> None:
        # Double-checked locking: fast path avoids the lock once initialized.
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            from antivenom.audit.audit_log import AuditLogger
            from antivenom.audit.quarantine import QuarantineStore
            self._audit_logger = AuditLogger(path=self.config.audit_log_path)
            self._quarantine = QuarantineStore(db_path=self.config.db_path)
            if getattr(self.config, "cache_enabled", False):
                from antivenom.cache.hash_cache import HashCache
                self._cache = HashCache(ttl=getattr(self.config, "cache_ttl_seconds", 3600))
            self._initialized = True

    async def ascan(self, chunk: Chunk) -> ScanResult:
        self._ensure_audit()

        # Cache check — never let a cache error break a scan.
        if self._cache is not None:
            try:
                cached = self._cache.get(chunk.text)
            except Exception:
                cached = None
            if cached is not None:
                return cached

        start = time.perf_counter()
        is_poisoned, confidence, layer_results = await self._pipeline.run(chunk)
        duration_ms = (time.perf_counter() - start) * 1000

        chunk_id = _make_chunk_id(chunk.text)
        if is_poisoned:
            result = ScanResult.poisoned(chunk_id, confidence, layer_results, duration_ms)
        else:
            result = ScanResult.clean(chunk_id, layer_results, duration_ms)

        # Side effects (cache/audit/quarantine) must never break the scan result.
        if self._cache is not None:
            try:
                self._cache.set(chunk.text, result)
            except Exception:
                pass
        if self._audit_logger:
            try:
                self._audit_logger.log(chunk, result)
            except Exception:
                pass
        if is_poisoned and self.config.quarantine_on_detection and self._quarantine:
            try:
                self._quarantine.quarantine(chunk, result)
            except Exception:
                pass

        return result

    def scan(self, chunk: Chunk) -> ScanResult:
        return _run_coro_blocking(self.ascan(chunk))

    def scan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "") -> ScanResult:
        return self.scan(Chunk(text=text, metadata=metadata or {}, source_id=source_id))

    async def ascan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "") -> ScanResult:
        return await self.ascan(Chunk(text=text, metadata=metadata or {}, source_id=source_id))

    async def ascan_batch(self, chunks: list[Chunk]) -> list[ScanResult]:
        self._ensure_audit()
        concurrency = max(1, int(self.config.async_concurrency))
        sem = asyncio.Semaphore(concurrency)

        async def _bounded(c: Chunk) -> ScanResult:
            async with sem:
                return await self.ascan(c)

        return list(await asyncio.gather(*[_bounded(c) for c in chunks]))

    def scan_batch(self, chunks: list[Chunk]) -> list[ScanResult]:
        return _run_coro_blocking(self.ascan_batch(chunks))

    def close(self) -> None:
        """Release the audit log file handle and quarantine DB connection."""
        with self._init_lock:
            if self._audit_logger is not None:
                try:
                    self._audit_logger.close()
                except Exception:
                    pass
            if self._quarantine is not None and hasattr(self._quarantine, "close"):
                try:
                    self._quarantine.close()
                except Exception:
                    pass

    def __enter__(self) -> AntiVenomScanner:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
