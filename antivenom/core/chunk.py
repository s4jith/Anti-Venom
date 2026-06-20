from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Chunk:
    text: str
    source_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    chunk_index: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.text, str):
            raise TypeError("Chunk.text must be a string")
