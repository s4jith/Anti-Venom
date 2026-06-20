from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from antivenom.rules.base_rule import BaseRule


class RuleRegistry:
    """Central registry for detection rules. Thread-safe reads; single-writer pattern."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseRule] = {}

    def register(self, rule: BaseRule) -> None:
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> BaseRule:
        return self._rules[rule_id]

    def list_rules(self) -> list[BaseRule]:
        return list(self._rules.values())

    def __iter__(self) -> Iterator[BaseRule]:
        return iter(self._rules.values())

    def load_json(self, path: str | Path) -> None:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        for entry in data:
            from antivenom.rules.loaders import dict_to_rule
            self.register(dict_to_rule(entry))

    @classmethod
    def get_default(cls) -> RuleRegistry:
        registry = cls()
        return registry
