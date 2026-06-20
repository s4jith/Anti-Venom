from __future__ import annotations

from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.scanner import AntiVenomScanner

try:
    from llama_index.core.schema import BaseNode, TextNode  # type: ignore[import]
    _LLAMA_AVAILABLE = True
except ImportError:
    _LLAMA_AVAILABLE = False
    BaseNode = Any
    TextNode = Any


class AntiVenomIngestionNode:
    """LlamaIndex ingestion pipeline component: filters poisoned nodes pre-embedding.

    Usage:
        pipeline = IngestionPipeline(transformations=[
            SentenceSplitter(chunk_size=512),
            AntiVenomIngestionNode(),      # sits before embedding
            HuggingFaceEmbedding(model_name="BAAI/bge-small-en-v1.5"),
        ])
        nodes = await pipeline.arun(documents=documents)
    """

    def __init__(
        self,
        config: ScannerConfig | None = None,
        on_detection: str = "filter",
    ) -> None:
        self._scanner = AntiVenomScanner(config=config)
        self._on_detection = on_detection

    def __call__(self, nodes: list[Any], **kwargs: Any) -> list[Any]:
        return self._process(nodes)

    async def acall(self, nodes: list[Any], **kwargs: Any) -> list[Any]:
        chunks = [
            Chunk(
                text=n.get_content() if hasattr(n, "get_content") else str(n),
                source_id=getattr(n, "node_id", "") or "",
                metadata=getattr(n, "metadata", {}) or {},
            )
            for n in nodes
        ]
        results = await self._scanner.ascan_batch(chunks)

        safe: list[Any] = []
        for node, result in zip(nodes, results):
            if not result.is_poisoned:
                safe.append(node)
            elif self._on_detection == "tag":
                if hasattr(node, "metadata"):
                    node.metadata["antivenom_flagged"] = True
                    node.metadata["antivenom_confidence"] = result.confidence
                safe.append(node)
        return safe

    def _process(self, nodes: list[Any]) -> list[Any]:
        chunks = [
            Chunk(
                text=n.get_content() if hasattr(n, "get_content") else str(n),
                source_id=getattr(n, "node_id", "") or "",
                metadata=getattr(n, "metadata", {}) or {},
            )
            for n in nodes
        ]
        results = self._scanner.scan_batch(chunks)

        safe: list[Any] = []
        for node, result in zip(nodes, results):
            if not result.is_poisoned:
                safe.append(node)
            elif self._on_detection == "tag":
                if hasattr(node, "metadata"):
                    node.metadata["antivenom_flagged"] = True
                    node.metadata["antivenom_confidence"] = result.confidence
                safe.append(node)
        return safe
