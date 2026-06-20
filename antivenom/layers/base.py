from __future__ import annotations
from abc import ABC, abstractmethod
from antivenom.core.chunk import Chunk
from antivenom.core.result import LayerResult


class AbstractDetectionLayer(ABC):
    """All detection layers implement this async interface."""

    @abstractmethod
    async def scan(self, chunk: Chunk) -> LayerResult:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...
