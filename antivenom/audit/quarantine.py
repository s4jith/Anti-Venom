from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from antivenom.core.chunk import Chunk
from antivenom.core.result import ScanResult

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS quarantine (
    quarantine_id TEXT PRIMARY KEY,
    chunk_id      TEXT NOT NULL,
    source_id     TEXT NOT NULL,
    chunk_text    TEXT NOT NULL,
    metadata      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    quarantined_at TEXT NOT NULL
)
"""

_COLS = ["quarantine_id", "chunk_id", "source_id", "chunk_text",
         "metadata", "confidence", "severity", "evidence", "quarantined_at"]


class QuarantineEntry:
    __slots__ = ("quarantine_id", "chunk_id", "source_id", "chunk_text",
                 "metadata", "confidence", "severity", "evidence", "quarantined_at")

    def __init__(self, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class QuarantineStore:
    """Thread-safe SQLite-backed quarantine store.

    Safe for concurrent multi-threaded use: a single connection is shared with
    check_same_thread=False and every access is serialized through a lock.
    WAL journaling + a busy timeout let separate processes/connections coexist
    without "database is locked" errors.
    """

    def __init__(self, db_path: str | None = "antivenom_audit.db") -> None:
        self._lock = threading.RLock()
        target = db_path if db_path else ":memory:"
        self._conn = sqlite3.connect(target, check_same_thread=False, timeout=30.0)
        with self._lock:
            # WAL allows concurrent readers with a writer; only meaningful for
            # file-backed DBs (no-op / harmless for :memory:).
            if db_path:
                try:
                    self._conn.execute("PRAGMA journal_mode=WAL")
                    self._conn.execute("PRAGMA synchronous=NORMAL")
                except sqlite3.Error:
                    pass
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute(_CREATE_TABLE)
            self._conn.commit()

    def quarantine(self, chunk: Chunk, result: ScanResult) -> str:
        qid = str(uuid.uuid4())
        evidence = json.dumps([e for r in result.layer_results for e in r.evidence][:10])
        with self._lock:
            self._conn.execute(
                "INSERT INTO quarantine VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    qid,
                    result.chunk_id,
                    chunk.source_id,
                    chunk.text,
                    json.dumps(chunk.metadata),
                    result.confidence,
                    result.severity.value,
                    evidence,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            self._conn.commit()
        return qid

    def list_quarantined(self, limit: int = 100, offset: int = 0) -> list[QuarantineEntry]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [QuarantineEntry(**dict(zip(_COLS, r))) for r in rows]

    def get_quarantined(self, quarantine_id: str) -> QuarantineEntry | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
            ).fetchone()
        if not row:
            return None
        return QuarantineEntry(**dict(zip(_COLS, row)))

    def release(self, quarantine_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def __enter__(self) -> QuarantineStore:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
