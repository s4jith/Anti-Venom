from __future__ import annotations
import hashlib
import json
from typing import Any

from antivenom.core.result import ScanResult, LayerResult, Severity


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
                "evidence": lr.evidence,
                "duration_ms": lr.duration_ms,
            }
            for lr in result.layer_results
        ],
    }


def _deserialize_result(data: dict) -> ScanResult:
    layer_results = [
        LayerResult(
            layer_name=lr["layer_name"],
            triggered=lr["triggered"],
            confidence=lr["confidence"],
            evidence=lr["evidence"],
            duration_ms=lr["duration_ms"],
        )
        for lr in data.get("layer_results", [])
    ]
    return ScanResult(
        chunk_id=data["chunk_id"],
        is_poisoned=data["is_poisoned"],
        confidence=data["confidence"],
        severity=Severity(data["severity"]),
        layer_results=layer_results,
        scan_duration_ms=data.get("scan_duration_ms", 0.0),
        from_cache=True,
    )


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

    @staticmethod
    def _key(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def get(self, text: str) -> ScanResult | None:
        data = self._backend.get(self._key(text))
        if data is None:
            self._misses += 1
            return None
        self._hits += 1
        return _deserialize_result(data)

    def set(self, text: str, result: ScanResult) -> None:
        self._backend.set(self._key(text), _serialize_result(result), ttl=self._ttl)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    def clear(self) -> None:
        self._backend.clear()
        self._hits = 0
        self._misses = 0
