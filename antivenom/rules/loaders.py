from __future__ import annotations
import json
import re
from pathlib import Path
from antivenom.rules.base_rule import BaseRule


class _RegexRule(BaseRule):
    def __init__(self, rule_id: str, name: str, description: str, layer: str, pattern: str, weight: float) -> None:
        super().__init__(rule_id=rule_id, name=name, description=description, layer=layer, severity_weight=weight)
        self._re = re.compile(pattern, re.IGNORECASE)

    def matches(self, text: str) -> tuple[bool, list[str]]:
        m = self._re.search(text)
        if m:
            return True, [m.group(0)[:100]]
        return False, []


def dict_to_rule(data: dict) -> BaseRule:
    return _RegexRule(
        rule_id=data["rule_id"],
        name=data["name"],
        description=data.get("description", ""),
        layer=data.get("layer", "pattern"),
        pattern=data["pattern"],
        weight=data.get("severity_weight", 0.8),
    )


def load_json_rules(path: str | Path) -> list[BaseRule]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [dict_to_rule(entry) for entry in data]


def load_yaml_rules(path: str | Path) -> list[BaseRule]:
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        raise ImportError("PyYAML is required to load YAML rules: pip install pyyaml")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return [dict_to_rule(entry) for entry in data]


def load_rules(path: str | Path) -> list[BaseRule]:
    """Auto-detect format from file extension and load rules."""
    p = Path(path)
    if p.suffix in (".yaml", ".yml"):
        return load_yaml_rules(p)
    return load_json_rules(p)
