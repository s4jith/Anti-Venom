"""Built-in adversarial phrase rules loaded into RuleRegistry."""
from __future__ import annotations

import re

from antivenom.rules.base_rule import BaseRule


class _PhraseRule(BaseRule):
    def __init__(self, rule_id: str, name: str, description: str, pattern: str, weight: float) -> None:
        super().__init__(
            rule_id=rule_id,
            name=name,
            description=description,
            layer="pattern",
            severity_weight=weight,
        )
        self._re = re.compile(pattern, re.IGNORECASE | re.DOTALL)

    def matches(self, text: str) -> tuple[bool, list[str]]:
        m = self._re.search(text)
        if m:
            return True, [m.group(0)[:100]]
        return False, []


BUILTIN_RULES: list[BaseRule] = [
    _PhraseRule("av_001", "Direct injection — ignore previous",
                "Detects 'ignore previous instructions' and variants",
                r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|directions?)", 0.97),
    _PhraseRule("av_002", "Direct injection — disregard",
                "Detects 'disregard previous instructions' variants",
                r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.97),
    _PhraseRule("av_003", "Role override — DAN mode",
                "Detects DAN (Do Anything Now) jailbreak pattern",
                r"you\s+are\s+now\s+(DAN|jailbreak|an?\s+AI\s+with\s+no\s+restrictions?)", 0.98),
    _PhraseRule("av_004", "System prompt extraction",
                "Detects attempts to extract the system prompt",
                r"(repeat|output|print|reveal|display|show|echo)\s+(your\s+)?(system\s+prompt|initial\s+instructions?)", 0.96),
    _PhraseRule("av_005", "Override directive",
                "Detects new directive / instruction override patterns",
                r"(from\s+now\s+on|new\s+(prime\s+)?directive|your\s+new\s+instructions?\s+(are|is))", 0.88),
]
