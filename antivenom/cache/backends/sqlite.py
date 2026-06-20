from __future__ import annotations
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

_CREATE = """
CREATE TABLE IF NOT EXISTS scan_cache (
    cache_key  TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    expires_at REAL NOT NULL DEFAULT 0
)
"""


class SQLiteBackend:
    """Persistent SQLite-backed cache for scan results."""

    def __init__(self, db_path: str = "antivenom_cache.db") -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_CREATE)
        self._conn.commit()

    def get(self, key: str) -> Any | None:
        row = self._conn.execute(
            "SELECT value, expires_at FROM scan_cache WHERE cache_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        value_json, expires_at = row
        if expires_at > 0 and time.time() > expires_at:
            self._conn.execute("DELETE FROM scan_cache WHERE cache_key = ?", (key,))
            self._conn.commit()
            return None
        return json.loads(value_json)

    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        expires_at = time.time() + ttl if ttl > 0 else 0
        self._conn.execute(
            "INSERT OR REPLACE INTO scan_cache (cache_key, value, expires_at) VALUES (?, ?, ?)",
            (key, json.dumps(value), expires_at),
        )
        self._conn.commit()

    def delete(self, key: str) -> None:
        self._conn.execute("DELETE FROM scan_cache WHERE cache_key = ?", (key,))
        self._conn.commit()

    def clear(self) -> None:
        self._conn.execute("DELETE FROM scan_cache")
        self._conn.commit()

    def purge_expired(self) -> int:
        cur = self._conn.execute(
            "DELETE FROM scan_cache WHERE expires_at > 0 AND expires_at < ?", (time.time(),)
        )
        self._conn.commit()
        return cur.rowcount
