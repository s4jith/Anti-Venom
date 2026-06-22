from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from antivenom.trust.label import TrustTier


@dataclass(frozen=True)
class SourceRule:
    """A reputation rule. `match` is either an exact source_type name (e.g.
    "internal") or an fnmatch glob tested against source_id (e.g. "https://*")."""

    match: str
    base_trust: float
    tier: TrustTier


# Conservative defaults: internal/verified sources are trusted; anything from the
# open web or an unknown origin is untrusted until proven otherwise.
_DEFAULT_RULES: tuple[SourceRule, ...] = (
    SourceRule("verified", 0.95, TrustTier.VERIFIED),
    SourceRule("internal", 0.90, TrustTier.TRUSTED),
    SourceRule("curated", 0.80, TrustTier.TRUSTED),
    SourceRule("user_upload", 0.50, TrustTier.UNTRUSTED),
    SourceRule("web", 0.20, TrustTier.UNTRUSTED),
    SourceRule("https://*", 0.20, TrustTier.UNTRUSTED),
    SourceRule("http://*", 0.15, TrustTier.UNTRUSTED),
)

_DEFAULT_UNKNOWN: tuple[float, TrustTier] = (0.30, TrustTier.UNTRUSTED)

_GLOB_CHARS = "*?["


class SourceRegistry:
    """Maps a chunk's source to a base trust score and ceiling tier.

    Precedence: a source_id glob match wins over a source_type match, which wins
    over the default for unknown sources. Among glob rules, the most recently
    added wins — so an explicit user rule overrides a built-in default (e.g.
    "https://trusted.internal/*" beats the generic "https://*").
    """

    def __init__(
        self,
        rules: list[SourceRule] | None = None,
        *,
        use_defaults: bool = True,
        unknown: tuple[float, TrustTier] = _DEFAULT_UNKNOWN,
    ) -> None:
        self._glob_rules: list[SourceRule] = []
        self._type_rules: dict[str, SourceRule] = {}
        self._unknown = unknown
        if use_defaults:
            for rule in _DEFAULT_RULES:
                self.add_rule(rule)
        for rule in rules or []:
            self.add_rule(rule)

    def add_rule(self, rule: SourceRule) -> None:
        if any(ch in rule.match for ch in _GLOB_CHARS):
            self._glob_rules.append(rule)
        else:
            self._type_rules[rule.match] = rule

    def base_trust(self, source_id: str = "", source_type: str = "") -> tuple[float, TrustTier]:
        # Most-recently-added glob rule wins, so user rules override defaults.
        for rule in reversed(self._glob_rules):
            if source_id and fnmatch.fnmatch(source_id, rule.match):
                return rule.base_trust, rule.tier
        type_rule = self._type_rules.get(source_type) if source_type else None
        if type_rule is not None:
            return type_rule.base_trust, type_rule.tier
        return self._unknown

    @classmethod
    def from_yaml(cls, path: str | Path, *, use_defaults: bool = True) -> SourceRegistry:
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as err:
            raise ImportError("PyYAML is required to load a source registry: pip install pyyaml") from err
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or []
        rules = [
            SourceRule(
                match=entry["match"],
                base_trust=float(entry.get("base_trust", 0.3)),
                tier=TrustTier(entry.get("tier", "untrusted")),
            )
            for entry in data
        ]
        return cls(rules=rules, use_defaults=use_defaults)
