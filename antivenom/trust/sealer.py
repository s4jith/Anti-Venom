from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import replace

from antivenom.trust.label import TrustLabel


def _coerce_key(key: bytes | str) -> bytes:
    return key.encode("utf-8") if isinstance(key, str) else key


class TrustSealer:
    """Signs and verifies TrustLabels with HMAC-SHA256.

    A single symmetric key defines one trust domain (one deployment). The signed
    payload includes the key_id, so a label sealed by one key cannot be replayed
    as another key's. For multi-party provenance (different signers you must
    distinguish cryptographically), a pluggable asymmetric signer (Ed25519) is the
    intended v0.6+ extension — `seal()`/`verify()` are the only call sites to swap.
    """

    def __init__(self, key: bytes | str | None = None) -> None:
        if key is None:
            key = os.environ.get("ANTIVENOM_TRUST_KEY")
        if not key:
            raise ValueError(
                "TrustSealer requires a key: pass one explicitly or set ANTIVENOM_TRUST_KEY."
            )
        self._key = _coerce_key(key)
        self.key_id = hashlib.sha256(self._key).hexdigest()[:8]

    def _mac(self, label: TrustLabel) -> str:
        # Bind our key_id into the signed payload so the signature commits to it.
        payload = replace(label, signature="", key_id=self.key_id).canonical_payload()
        return hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def seal(self, label: TrustLabel) -> TrustLabel:
        """Return a copy of `label` with signature and key_id filled in."""
        return replace(label, signature=self._mac(label), key_id=self.key_id)

    def verify(self, label: TrustLabel) -> bool:
        """True only if the label was sealed by this key and is untampered."""
        if not label.signature or not label.key_id:
            return False
        if not hmac.compare_digest(label.key_id, self.key_id):
            return False
        return hmac.compare_digest(self._mac(label), label.signature)
