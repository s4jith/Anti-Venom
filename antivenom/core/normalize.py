from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Invisible / zero-width / bidi-control characters used to break up keywords.
_INVISIBLE_CHARS = (
    "​‌‍‎‏"  # zero-width space/joiners, LRM/RLM
    "‪‫‬‭‮"  # bidi embedding/override
    "⁠⁡⁢⁣⁤"  # word joiner / invisible operators
    "﻿"                          # BOM / zero-width no-break space
    "­"                          # soft hyphen
    "͏"                          # combining grapheme joiner
)
_INVISIBLE_RE = re.compile("[" + re.escape(_INVISIBLE_CHARS) + "]")

# Small, high-precision confusables map: only characters that appear in common
# injection keywords (ignore/system/prompt/instructions/reveal/...). Kept tight
# so legitimately non-Latin text is not corrupted.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "к": "k", "т": "t", "в": "b", "н": "h",
    "м": "m", "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C", "У": "Y",
    "Х": "X", "І": "I", "Ѕ": "S", "К": "K", "Т": "T", "В": "B", "Н": "H", "М": "M",
    # Greek -> Latin
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v", "ρ": "p", "τ": "t",
    "υ": "u", "Ο": "O", "Α": "A", "Ε": "E", "Ι": "I", "Ρ": "P", "Τ": "T",
}
_HOMOGLYPH_RE = re.compile("[" + re.escape("".join(_HOMOGLYPHS)) + "]")

# Candidate base64 / hex runs (long enough to plausibly hide a payload).
_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")


@dataclass(frozen=True)
class NormalizationResult:
    normalized_text: str
    transforms: list[str] = field(default_factory=list)
    decoded_blobs: list[str] = field(default_factory=list)
    changed: bool = False


def _strip_invisible(text: str) -> str:
    return _INVISIBLE_RE.sub("", text)


def _fold_homoglyphs(text: str) -> str:
    return _HOMOGLYPH_RE.sub(lambda m: _HOMOGLYPHS[m.group(0)], text)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t ")
    return printable / len(s)


def _try_decode_blobs(text: str) -> list[str]:
    """Find base64/hex runs, decode the ones that yield plausible UTF-8 text."""
    blobs: list[str] = []
    for m in _B64_RE.finditer(text):
        token = m.group(0)
        token_padded = token + "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token_padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if len(decoded) >= 6 and _printable_ratio(decoded) >= 0.85:
            blobs.append(decoded)
    for m in _HEX_RE.finditer(text):
        token = m.group(0)
        if len(token) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if len(decoded) >= 6 and _printable_ratio(decoded) >= 0.85:
            blobs.append(decoded)
    return blobs


def normalize(text: str, decode_blobs: bool = True) -> NormalizationResult:
    """Normalize text to defeat common evasion tricks.

    Records which transforms actually changed the text (so an evasion attempt is
    itself a signal) and returns any decoded base64/hex payloads for re-scanning.
    """
    transforms: list[str] = []

    nfkc = unicodedata.normalize("NFKC", text)
    if nfkc != text:
        transforms.append("nfkc")

    stripped = _strip_invisible(nfkc)
    if stripped != nfkc:
        transforms.append("zero_width_strip")

    folded = _fold_homoglyphs(stripped)
    if folded != stripped:
        transforms.append("homoglyph_fold")

    decoded_blobs: list[str] = []
    if decode_blobs:
        decoded_blobs = _try_decode_blobs(folded)
        if decoded_blobs:
            transforms.append("decoded_blob")

    changed = folded != text or bool(decoded_blobs)
    return NormalizationResult(
        normalized_text=folded,
        transforms=transforms,
        decoded_blobs=decoded_blobs,
        changed=changed,
    )
