from __future__ import annotations

import asyncio
import concurrent.futures
import importlib.util
import warnings
from typing import Any

from antivenom.core.scanner import AntiVenomScanner

# Guard: require haystack at import time so the error is raised when the
# integration module is first imported (consistent with other integrations).
if importlib.util.find_spec("haystack") is None:
    raise ImportError(
        "haystack-ai is required for the Haystack integration. "
        "Install with: pip install antivenom[haystack]"
    )

from haystack import Document, component  # type: ignore[import]


@component
class AntiVenomComponent:
    """Haystack component that filters or flags poisoned documents.

    on_detection modes:
      "filter"  — PROTECTION: remove poisoned documents from the pipeline (default)
      "tag"     — MONITORING ONLY: pass documents through with antivenom metadata set.
                  Do NOT use "tag" as protection — poisoned documents will continue
                  through the pipeline. Pass monitoring_mode=True to suppress warning.

    Usage::

        from antivenom.integrations.haystack import AntiVenomComponent

        cleaner = AntiVenomComponent(on_detection="filter")
        result = cleaner.run(documents=my_docs)
        safe_docs = result["documents"]
    """

    def __init__(
        self,
        on_detection: str = "filter",
        scanner: AntiVenomScanner | None = None,
        monitoring_mode: bool = False,
    ) -> None:
        if on_detection not in ("filter", "tag"):
            raise ValueError(
                f"on_detection must be 'filter' or 'tag', got {on_detection!r}"
            )
        if on_detection == "tag" and not monitoring_mode:
            warnings.warn(
                "on_detection='tag' is MONITORING MODE ONLY. Poisoned documents WILL "
                "continue through the Haystack pipeline. Use only for auditing existing "
                "pipelines, not for protection. "
                "Pass monitoring_mode=True to suppress this warning.",
                UserWarning,
                stacklevel=2,
            )
        self._on_detection = on_detection
        self._scanner: AntiVenomScanner = scanner if scanner is not None else AntiVenomScanner()

    @component.output_types(documents=list[Document])
    def run(self, documents: list[Document]) -> dict[str, Any]:
        """Scan each document and either filter or tag poisoned ones.

        Args:
            documents: List of Haystack Document objects to inspect.

        Returns:
            dict with key "documents" containing the kept/tagged documents.
        """
        if not documents:
            return {"documents": []}

        kept: list[Document] = []

        for doc in documents:
            text = doc.content or ""
            result = self._scan_sync(text)

            if not result.is_poisoned:
                kept.append(doc)
            elif self._on_detection == "tag":
                if doc.meta is None:
                    doc.meta = {}
                doc.meta["antivenom_flagged"] = True
                doc.meta["antivenom_confidence"] = result.confidence
                kept.append(doc)
            # "filter" mode: drop poisoned document silently

        return {"documents": kept}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_sync(self, text: str):  # type: ignore[return]
        """Run scanner.scan_text synchronously, even if an event loop is running."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            # We are inside an already-running event loop (e.g. Jupyter / async test).
            # Offload the coroutine to a fresh thread that spins its own loop.
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    asyncio.run,
                    self._scanner.ascan_text(text),
                )
                return future.result()

        # No running loop — safe to use asyncio.run directly.
        return asyncio.run(self._scanner.ascan_text(text))
