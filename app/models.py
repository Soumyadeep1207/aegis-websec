"""SQLite persistence helpers for Aegis WebSec scan history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    summary TEXT NOT NULL,
    findings TEXT NOT NULL,
    pdf_path TEXT
);
"""


def init_db(db_path: str | Path) -> None:
    """Create the scans table if it does not already exist."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        _migrate_legacy_scans_table(connection)
        connection.execute(SCHEMA)


def save_scan(
    db_path: str | Path,
    target: str,
    timestamp: str,
    summary: dict[str, Any],
    findings: list[dict[str, Any]],
    pdf_path: str | None = None,
) -> int:
    """Persist a scan and return its new database id."""
    init_db(db_path)
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans (target, timestamp, summary, findings, pdf_path)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                target,
                timestamp,
                json.dumps(summary),
                json.dumps(findings),
                pdf_path,
            ),
        )
        return int(cursor.lastrowid)


def update_scan_pdf(db_path: str | Path, scan_id: int, pdf_path: str) -> None:
    """Attach a generated PDF path to an existing scan row."""
    init_db(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE scans SET pdf_path = ? WHERE id = ?", (pdf_path, scan_id))


def get_scan(db_path: str | Path, scan_id: int) -> dict[str, Any] | None:
    """Load one scan by id, returning decoded JSON fields."""
    init_db(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _decode_row(row) if row else None


def get_all_scans(db_path: str | Path) -> list[dict[str, Any]]:
    """Return all scans, newest first."""
    init_db(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return [_decode_row(row) for row in rows]


def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
    """Convert one SQLite row into the dashboard data shape."""
    return {
        "id": row["id"],
        "target": row["target"],
        "timestamp": row["timestamp"],
        "summary": json.loads(row["summary"]),
        "findings": json.loads(row["findings"]),
        "pdf_path": row["pdf_path"],
    }


def _migrate_legacy_scans_table(connection: sqlite3.Connection) -> None:
    """Archive an older incompatible scans table before creating the new schema."""
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'scans'"
    ).fetchone()
    if table is None:
        return

    columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)").fetchall()}
    required = {"id", "target", "timestamp", "summary", "findings", "pdf_path"}
    if required.issubset(columns):
        return

    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    connection.execute(f"ALTER TABLE scans RENAME TO scans_legacy_{suffix}")
