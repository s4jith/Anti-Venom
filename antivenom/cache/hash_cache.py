from __future__ import annotations

import hashlib
import threading
from typing import Any

from antivenom.core.finding import Finding
from antivenom.core.report import RiskReport
from antivenom.core.result import LayerResult, ScanResult, Severity


def _serialize_result(result: ScanResult) -> dict:
    return {
        "chunk_id": result.chunk_id,
        "is_poisoned": result.is_poisoned,
        "confidence": result.confidence,
        "severity": result.severity.value,
        "scan_duration_ms": result.scan_duration_ms,
        "from_cache": True,
        "layer_results": [
            {
                "layer_name": lr.layer_name,
                "triggered": lr.triggered,
                "confidence": lr.confidence,
                "evidence": lr.evidence,  # kept for backward compatibility
                "findings": [f.to_dict() for f in lr.findings],
                "duration_ms": lr.duration_ms,
            }
            for lr in result.layer_results
        ],
    }


def _deserialize_result(data: dict) -> ScanResult:
    layer_results = []
    for lr in data.get("layer_results", []):
        if "findings" in lr:
            findings = [Finding.from_dict(f) for f in lr["findings"]]
            layer_results.append(LayerResult(
                layer_name=lr["layer_name"],
                triggered=lr["triggered"],
                confidence=lr["confidence"],
                findings=findings,
                duration_ms=lr["duration_ms"],
            ))
        else:
            # Legacy cache entry (pre-v0.4): fall back to evidence strings.
            layer_results.append(LayerResult(
                layer_name=lr["layer_name"],
                triggered=lr["triggered"],
                confidence=lr["confidence"],
                evidence=lr.get("evidence", []),
                duration_ms=lr["duration_ms"],
            ))
    result = ScanResult(
        chunk_id=data["chunk_id"],
        is_poisoned=data["is_poisoned"],
        confidence=data["confidence"],
        severity=Severity(data["severity"]),
        layer_results=layer_results,
        scan_duration_ms=data.get("scan_duration_ms", 0.0),
        from_cache=True,
    )
    result.report = RiskReport.from_scan(result)
    return result


class HashCache:
    """SHA-256 keyed scan result cache. Skip re-scanning identical chunks."""

    def __init__(self, backend: Any | None = None, ttl: int = 3600) -> None:
        if backend is None:
            from antivenom.cache.backends.memory import InMemoryBackend
            backend = InMemoryBackend()
        self._backend = backend
        self._ttl = ttl
        self._hits = 0
        self._misses = 0
        self._stats_lock = threading.Lock()

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def get(self, text: str) -> ScanResult | None:
        data = self._backend.get(self._key(text))
        with self._stats_lock:
            if data is None:
                self._misses += 1
            else:
                self._hits += 1
        if data is None:
            return None
        return _deserialize_result(data)

    def set(self, text: str, result: ScanResult) -> None:
        self._backend.set(self._key(text), _serialize_result(result), ttl=self._ttl)

    @property
    def hit_rate(self) -> float:
        with self._stats_lock:
            total = self._hits + self._misses
            return self._hits / total if total > 0 else 0.0

    def clear(self) -> None:
        self._backend.clear()
        with self._stats_lock:
            self._hits = 0
            self._misses = 0
