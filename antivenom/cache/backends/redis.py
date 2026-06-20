from __future__ import annotations
import json
from typing import Any

try:
    import redis as _redis
except ImportError:
    _redis = None  # type: ignore[assignment]


class RedisBackend:
    """Redis-backed cache for scan results."""

    def __init__(self, url: str = "redis://localhost:6379/0") -> None:
        if _redis is None:
            raise ImportError(
                "redis is not installed. Run: pip install antivenom[redis]"
            )
        self._client = _redis.from_url(url, decode_responses=True)

    def get(self, key: str) -> Any | None:
        raw = self._client.get(key)
        if raw is None:
            return None
        return json.loads(raw)

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        serialized = json.dumps(value)
        if ttl > 0:
            self._client.set(key, serialized, ex=ttl)
        else:
            self._client.set(key, serialized)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def clear(self) -> None:
        self._client.flushdb()

    def ping(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:
            return False
