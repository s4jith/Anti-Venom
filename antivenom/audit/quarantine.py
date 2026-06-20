from __future__ import annotations
import json
import sqlite3
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

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


class QuarantineEntry:
    __slots__ = ("quarantine_id", "chunk_id", "source_id", "chunk_text",
                 "metadata", "confidence", "severity", "evidence", "quarantined_at")

    def __init__(self, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


class QuarantineStore:
    """SQLite-backed quarantine store. Sync (v0.1)."""

    def __init__(self, db_path: str | None = "antivenom_audit.db") -> None:
        if db_path:
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        else:
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()

    def quarantine(self, chunk: Chunk, result: ScanResult) -> str:
        qid = str(uuid.uuid4())
        evidence = json.dumps([e for r in result.layer_results for e in r.evidence][:10])
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
        rows = self._conn.execute(
            "SELECT * FROM quarantine ORDER BY quarantined_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        cols = ["quarantine_id", "chunk_id", "source_id", "chunk_text",
                "metadata", "confidence", "severity", "evidence", "quarantined_at"]
        return [QuarantineEntry(**dict(zip(cols, r))) for r in rows]

    def get_quarantined(self, quarantine_id: str) -> QuarantineEntry | None:
        row = self._conn.execute(
            "SELECT * FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        ).fetchone()
        if not row:
            return None
        cols = ["quarantine_id", "chunk_id", "source_id", "chunk_text",
                "metadata", "confidence", "severity", "evidence", "quarantined_at"]
        return QuarantineEntry(**dict(zip(cols, row)))

    def release(self, quarantine_id: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM quarantine WHERE quarantine_id = ?", (quarantine_id,)
        )
        self._conn.commit()
        return cur.rowcount > 0

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]
