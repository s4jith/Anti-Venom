from __future__ import annotations

from typing import Any

from antivenom.core.chunk import Chunk
from antivenom.core.config import ScannerConfig
from antivenom.core.scanner import AntiVenomScanner

try:
    from llama_index.core.postprocessor.types import BaseNodePostprocessor  # type: ignore[import]
    from llama_index.core.schema import NodeWithScore, QueryBundle  # type: ignore[import]
    _LLAMA_AVAILABLE = True
except ImportError:
    _LLAMA_AVAILABLE = False
    BaseNodePostprocessor = object  # type: ignore[assignment,misc]
    NodeWithScore = Any
    QueryBundle = Any


class AntiVenomNodePostProcessor(BaseNodePostprocessor):  # type: ignore[misc]
    """LlamaIndex post-processor: filters poisoned nodes at retrieval time.

    Use this to sanitize retrieved nodes before they reach the LLM.
    For pre-embedding protection, use AntiVenomIngestionNode instead.

    Usage:
        index = VectorStoreIndex.from_documents(documents)
        retriever = index.as_retriever(
            node_postprocessors=[AntiVenomNodePostProcessor()]
        )
    """

    def __init__(
        self,
        config: ScannerConfig | None = None,
        on_detection: str = "filter",
    ) -> None:
        if not _LLAMA_AVAILABLE:
            raise ImportError(
                "llama-index-core is required. Install with: pip install antivenom[llamaindex]"
            )
        super().__init__()
        self._scanner = AntiVenomScanner(config=config)
        self._on_detection = on_detection

    def _postprocess_nodes(
        self,
        nodes: list[NodeWithScore],
        query_bundle: QueryBundle | None = None,
    ) -> list[NodeWithScore]:
        if not nodes:
            return nodes

        chunks = [
            Chunk(
                text=n.node.get_content(),
                source_id=n.node.node_id or "",
                metadata=n.node.metadata or {},
            )
            for n in nodes
        ]
        results = self._scanner.scan_batch(chunks)

        safe: list[NodeWithScore] = []
        for node, result in zip(nodes, results):
            if not result.is_poisoned:
                safe.append(node)
            elif self._on_detection == "tag":
                node.node.metadata["antivenom_flagged"] = True
                node.node.metadata["antivenom_confidence"] = result.confidence
                safe.append(node)
            # "filter" mode: drop poisoned nodes silently
        return safe
