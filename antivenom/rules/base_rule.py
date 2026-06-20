from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class BaseRule(ABC):
    rule_id: str
    name: str
    description: str
    layer: str
    severity_weight: float = 0.8

    @abstractmethod
    def matches(self, text: str) -> tuple[bool, list[str]]:
        """Returns (triggered, evidence_list)."""
        ...
