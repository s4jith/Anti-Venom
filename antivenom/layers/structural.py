from __future__ import annotations

import re
import time
from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult
from antivenom.layers.base import AbstractDetectionLayer

# Imperative verbs that appear in adversarial injections but rarely in benign docs
_IMPERATIVE_VERBS = frozenset({
    "ignore", "disregard", "forget", "pretend", "reveal", "output",
    "print", "send", "bypass", "override", "act", "assume", "respond",
    "repeat", "echo", "return", "expose", "leak", "exfiltrate",
    "simulate", "roleplay", "impersonate", "become", "transform",
    "execute", "run", "perform", "comply", "obey", "follow",
    "abandon", "drop", "delete", "remove", "clear", "reset",
})

_WORD_RE = re.compile(r"\b([a-z]+)\b", re.IGNORECASE)

# Cap scan length to bound worst-case time on pathological/huge inputs.
_MAX_SCAN_CHARS = 100_000


def _imperative_density(text: str) -> tuple[float, list[str]]:
    words = _WORD_RE.findall(text.lower())
    if len(words) < 5:
        return 0.0, []
    hits = [w for w in words if w in _IMPERATIVE_VERBS]
    density = len(hits) / len(words)
    return density, list(dict.fromkeys(hits))  # deduplicated, order-preserving


class StructuralLayer(AbstractDetectionLayer):
    """Layer 2 (FAST): detects abnormal imperative verb density without spaCy.

    When spacy is installed ([structural-nlp] extra), upgrades to POS-aware detection.
    """

    name = "structural"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._config = config or {}
        self._threshold: float = self._config.get("threshold", 0.08)
        self._spacy_nlp = self._try_load_spacy()

    @staticmethod
    def _try_load_spacy() -> Any:
        import importlib.util
        if importlib.util.find_spec("spacy") is None:
            return None
        try:
            import spacy  # type: ignore[import]
            return spacy.load("en_core_web_sm", disable=["ner", "parser"])
        except Exception:
            return None

    async def scan(self, chunk: Chunk) -> LayerResult:
        start = time.perf_counter()
        if self._spacy_nlp is not None:
            return self._scan_spacy(chunk, start)
        return self._scan_regex(chunk, start)

    def _scan_regex(self, chunk: Chunk, start: float) -> LayerResult:
        density, hits = _imperative_density(chunk.text[:_MAX_SCAN_CHARS])
        triggered = density >= self._threshold
        confidence = min(density / self._threshold * 0.7, 0.85) if triggered else 0.0
        evidence = [f"imperative density={density:.3f} (threshold={self._threshold}), verbs: {', '.join(hits[:8])}"] if triggered else []
        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    def _scan_spacy(self, chunk: Chunk, start: float) -> LayerResult:
        doc = self._spacy_nlp(chunk.text[:5000])
        imperative_count = sum(
            1 for token in doc
            if token.pos_ == "VERB" and token.dep_ in ("ROOT", "relcl")
            and token.lemma_.lower() in _IMPERATIVE_VERBS
        )
        total_tokens = max(len(doc), 1)
        density = imperative_count / total_tokens
        triggered = density >= (self._threshold * 0.6)  # spaCy is more precise
        confidence = min(density / self._threshold * 0.8, 0.88) if triggered else 0.0
        evidence = [f"spaCy imperative density={density:.3f}, count={imperative_count}/{total_tokens}"] if triggered else []
        return LayerResult(
            layer_name=self.name,
            triggered=triggered,
            confidence=confidence,
            evidence=evidence,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
