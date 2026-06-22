from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScannerConfig:
    # Confidence threshold above which a chunk is considered poisoned
    confidence_threshold: float = 0.7
    # Short-circuit threshold — any layer hitting this skips remaining layers
    short_circuit_threshold: float = 0.95
    # Enabled layer names; None means all available layers
    enabled_layers: list[str] | None = None
    # Per-layer configuration overrides
    layer_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Quarantine detected chunks automatically
    quarantine_on_detection: bool = True
    # Path for SQLite audit/quarantine DB; None = in-memory
    db_path: str | None = "antivenom_audit.db"
    # Path for JSONL audit log; None = disable file log
    audit_log_path: str | None = "antivenom_audit.jsonl"
    # Max concurrent async tasks for batch scanning
    async_concurrency: int = 10
    # Hash cache (v0.2)
    cache_enabled: bool = False
    cache_ttl_seconds: int = 3600
    # Input normalization / evasion resistance (v0.4)
    normalize_enabled: bool = True
    normalize_decode_blobs: bool = True
    # Trust Plane (v0.5) — opt-in signed provenance + retrieval-time flow control.
    # The detector is unaffected when this is off (default).
    trust_enabled: bool = False
    # HMAC key for sealing trust labels; falls back to ANTIVENOM_TRUST_KEY env var.
    trust_key: str | None = None
