from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import importlib.util
import threading
import time
from dataclasses import replace
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.finding import Finding, Technique
from antivenom.core.normalize import normalize
from antivenom.core.pipeline import DetectionPipeline
from antivenom.core.report import RiskReport
from antivenom.core.result import LayerResult, ScanResult, Severity
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
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


class AntiVenomScanner:
    """Main scanner orchestrator. Thread-safe and async-native.

    The detection pipeline (regex + classifier) is the hot path and never makes
    network calls. The LLM Judge is NOT a pipeline layer: it is summoned only via
    explain()/scan(explain=True) for natural-language rationale and arbitration of
    borderline (SUSPICIOUS) cases. Input is normalized (NFKC, zero-width strip,
    homoglyph fold, base64/hex decode) and scanned in both raw and normalized form
    so evasion attempts are themselves a signal.
    """

    def __init__(self, config: ScannerConfig | None = None) -> None:
        self.config = config or ScannerConfig()
        self._pipeline = self._build_pipeline()
        self._cache: Any = None
        self._audit_logger: Any = None
        self._quarantine: Any = None
        self._judge: Any = None
        self._initialized = False
        self._init_lock = threading.Lock()

    def _build_pipeline(self) -> DetectionPipeline:
        enabled = self.config.enabled_layers
        fast: list[Any] = []
        medium: list[Any] = []

        if enabled is None or "pattern" in enabled:
            fast.append(PatternLayer(self.config.layer_configs.get("pattern", {})))
        if enabled is None or "structural" in enabled:
            fast.append(StructuralLayer(self.config.layer_configs.get("structural", {})))
        if enabled is None or "canary" in enabled:
            fast.append(CanaryLayer(self.config.layer_configs.get("canary", {})))

        semantic_requested = enabled is None or "semantic" in (enabled or [])
        if semantic_requested and importlib.util.find_spec("sentence_transformers") is not None:
            from antivenom.layers.semantic import SemanticLayer
            medium.append(SemanticLayer(self.config.layer_configs.get("semantic", {})))

        if enabled is None or "cross_chunk" in (enabled or []):
            from antivenom.layers.cross_chunk import CrossChunkLayer
            medium.append(CrossChunkLayer(self.config.layer_configs.get("cross_chunk", {})))

        # Classifier auto-loads but gracefully skips without a fine-tuned checkpoint.
        slow: list[Any] = []
        if enabled is None or "classifier" in (enabled or []):
            from antivenom.layers.classifier import ClassifierLayer
            slow.append(ClassifierLayer(self.config.layer_configs.get("classifier", {})))

        # NOTE: the LLM Judge is intentionally NOT added here. It is an explainer/
        # arbiter, summoned on demand by explain(), never on the scan hot path.
        return DetectionPipeline(fast_layers=fast, medium_layers=medium, slow_layers=slow, config=self.config)

    def _ensure_audit(self) -> None:
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

    def _get_judge(self) -> Any:
        if self._judge is None:
            from antivenom.layers.llm_judge import LLMJudgeLayer
            self._judge = LLMJudgeLayer(**self.config.layer_configs.get("llm_judge", {}))
        return self._judge

    @staticmethod
    def _retag(layer_results: list[LayerResult], form: str) -> None:
        for lr in layer_results:
            if lr.findings:
                lr.findings = [replace(f, form=form) for f in lr.findings]

    async def _scan_all_forms(self, chunk: Chunk) -> tuple[list[LayerResult], float]:
        """Scan raw text, then (if normalization changed it) the normalized form
        and any decoded base64/hex blobs. Returns merged results + max confidence."""
        _, max_conf, raw_results = await self._pipeline.run(chunk)
        all_results: list[LayerResult] = list(raw_results)

        if not getattr(self.config, "normalize_enabled", True):
            return all_results, max_conf

        nr = normalize(chunk.text, decode_blobs=getattr(self.config, "normalize_decode_blobs", True))
        if not nr.changed:
            return all_results, max_conf

        # Evasion is itself a (sub-threshold) signal recorded as a finding.
        evasion = [
            Finding(
                technique=Technique.ENCODING_EVASION,
                reason=f"obfuscation detected: {t}",
                confidence=0.5,
                layer="normalize",
                form="normalized" if t != "decoded_blob" else "decoded",
            )
            for t in nr.transforms
        ]
        if evasion:
            all_results.append(LayerResult(
                layer_name="normalize", triggered=True, confidence=0.5, findings=evasion,
            ))
            max_conf = max(max_conf, 0.5)

        short = self.config.short_circuit_threshold
        if max_conf >= short:
            return all_results, max_conf

        # Re-scan the de-obfuscated text — this is where hidden attacks surface.
        if nr.normalized_text != chunk.text:
            norm_chunk = Chunk(text=nr.normalized_text, source_id=chunk.source_id, metadata=chunk.metadata)
            _, norm_conf, norm_results = await self._pipeline.run(norm_chunk)
            self._retag(norm_results, "normalized")
            all_results.extend(norm_results)
            max_conf = max(max_conf, norm_conf)

        for blob in nr.decoded_blobs:
            if max_conf >= short:
                break
            _, blob_conf, blob_results = await self._pipeline.run(Chunk(text=blob, source_id=chunk.source_id))
            self._retag(blob_results, "decoded:base64")
            all_results.extend(blob_results)
            max_conf = max(max_conf, blob_conf)

        return all_results, max_conf

    async def ascan(self, chunk: Chunk) -> ScanResult:
        self._ensure_audit()

        if self._cache is not None:
            try:
                cached = self._cache.get(chunk.text)
            except Exception:
                cached = None
            if cached is not None:
                return cached

        start = time.perf_counter()
        layer_results, max_conf = await self._scan_all_forms(chunk)
        duration_ms = (time.perf_counter() - start) * 1000

        chunk_id = _make_chunk_id(chunk.text)
        is_poisoned = max_conf >= self.config.confidence_threshold
        if is_poisoned:
            result = ScanResult.poisoned(chunk_id, max_conf, layer_results, duration_ms)
        else:
            result = ScanResult.clean(chunk_id, layer_results, duration_ms)
        result.report = RiskReport.from_scan(result)

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

    async def _arbitrate(self, result: ScanResult, chunk: Chunk) -> ScanResult:
        """Use the LLM judge to add a natural-language rationale and arbitrate
        borderline (SUSPICIOUS) cases. Never on the default hot path."""
        judge = self._get_judge()
        try:
            jr = await judge.scan(chunk)
        except Exception as exc:  # noqa: BLE001
            jr = None
            rationale = f"LLM judge error: {exc}"
        if jr is not None:
            rationale = jr.findings[0].reason if jr.findings else (
                jr.evidence[0] if jr.evidence else "no rationale")
            # Arbitrate: a borderline SUSPICIOUS case the judge confidently flags
            # is promoted to MALICIOUS. We never auto-demote a detection.
            if result.severity == Severity.SUSPICIOUS and jr.triggered:
                result.is_poisoned = True
                result.severity = Severity.MALICIOUS
                result.confidence = max(result.confidence, jr.confidence)
                result.layer_results.append(jr)
        if result.report is None:
            result.report = RiskReport.from_scan(result)
        result.report.llm_rationale = rationale
        return result

    def scan(self, chunk: Chunk) -> ScanResult:
        return _run_coro_blocking(self.ascan(chunk))

    def scan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "",
                  *, explain: bool = False, source_type: str = "document") -> ScanResult:
        return _run_coro_blocking(
            self.ascan_text(text, metadata=metadata, source_id=source_id,
                            explain=explain, source_type=source_type))

    async def ascan_text(self, text: str, metadata: dict[str, Any] | None = None, source_id: str = "",
                         *, explain: bool = False, source_type: str = "document") -> ScanResult:
        meta = dict(metadata or {})
        meta.setdefault("source_type", source_type)
        chunk = Chunk(text=text, metadata=meta, source_id=source_id)
        result = await self.ascan(chunk)
        if explain:
            result = await self._arbitrate(result, chunk)
        return result

    async def aexplain(self, text: str, metadata: dict[str, Any] | None = None,
                       source_id: str = "", source_type: str = "document") -> RiskReport:
        result = await self.ascan_text(text, metadata=metadata, source_id=source_id,
                                       explain=True, source_type=source_type)
        return result.report or RiskReport.from_scan(result)

    def explain(self, text: str, metadata: dict[str, Any] | None = None,
                source_id: str = "", source_type: str = "document") -> RiskReport:
        return _run_coro_blocking(self.aexplain(text, metadata=metadata,
                                                source_id=source_id, source_type=source_type))

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
