from __future__ import annotations
import asyncio
import warnings
from typing import Any, Literal, Sequence

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.exceptions import DetectionError
from antivenom.core.result import ScanResult
from antivenom.core.scanner import AntiVenomScanner

try:
    from langchain_core.documents import Document
    from langchain_core.documents.transformers import BaseDocumentTransformer
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False
    Document = Any  # type: ignore[assignment,misc]
    BaseDocumentTransformer = object  # type: ignore[assignment,misc]


class AntiVenomDocumentTransformer(BaseDocumentTransformer):  # type: ignore[misc]
    """LangChain document transformer that scans chunks before vector DB insertion.

    on_detection modes:
      "filter"  — PROTECTION: remove poisoned chunks (default)
      "raise"   — STRICT: raise DetectionError with evidence
      "tag"     — ⚠ MONITORING ONLY: chunks enter the store with antivenom_flagged=True.
                  Do NOT use "tag" as protection — poisoned chunks will reach the vector DB.
    """

    def __init__(
        self,
        config: ScannerConfig | None = None,
        on_detection: Literal["filter", "raise", "tag"] = "filter",
        monitoring_mode: bool = False,
    ) -> None:
        if not _LANGCHAIN_AVAILABLE:
            raise ImportError(
                "langchain-core is required. Install with: pip install antivenom[langchain]"
            )
        if on_detection == "tag" and not monitoring_mode:
            warnings.warn(
                "on_detection='tag' is MONITORING MODE ONLY. Poisoned chunks WILL enter the "
                "vector store. Use only for auditing existing pipelines, not for protection. "
                "Pass monitoring_mode=True to suppress this warning.",
                UserWarning,
                stacklevel=2,
            )
        self._scanner = AntiVenomScanner(config=config)
        self._on_detection = on_detection

    def _to_chunk(self, doc: Any) -> Chunk:
        return Chunk(
            text=doc.page_content,
            metadata=doc.metadata or {},
            source_id=doc.metadata.get("source", ""),
        )

    def _process(self, doc: Any, result: ScanResult) -> Any | None:
        if not result.is_poisoned:
            return doc
        if self._on_detection == "filter":
            return None
        if self._on_detection == "raise":
            evidence = [e for r in result.layer_results for e in r.evidence]
            raise DetectionError(
                f"Poisoned chunk detected (confidence={result.confidence:.2f})",
                confidence=result.confidence,
                evidence=evidence,
            )
        # "tag" mode — pass through with metadata flags
        doc.metadata["antivenom_flagged"] = True
        doc.metadata["antivenom_confidence"] = result.confidence
        doc.metadata["antivenom_severity"] = result.severity.value
        return doc

    def transform_documents(self, documents: Sequence[Any], **kwargs: Any) -> list[Any]:
        results = self._scanner.scan_batch([self._to_chunk(d) for d in documents])
        out = []
        for doc, result in zip(documents, results):
            processed = self._process(doc, result)
            if processed is not None:
                out.append(processed)
        return out

    async def atransform_documents(self, documents: Sequence[Any], **kwargs: Any) -> list[Any]:
        results = await self._scanner.ascan_batch([self._to_chunk(d) for d in documents])
        out = []
        for doc, result in zip(documents, results):
            processed = self._process(doc, result)
            if processed is not None:
                out.append(processed)
        return out
