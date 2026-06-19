from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .scanner.models import Finding, ScanResult


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss REAL NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    remediation TEXT NOT NULL,
    url TEXT NOT NULL
);
"""


class ScanStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def init_db(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def save_scan(self, result: ScanResult) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (target_url, started_at, finished_at, metadata_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    result.target_url,
                    result.started_at,
                    result.finished_at,
                    json.dumps(result.metadata, indent=2),
                ),
            )
            scan_id = int(cursor.lastrowid)
            connection.executemany(
                """
                INSERT INTO findings
                (scan_id, module, title, severity, cvss, description, evidence, remediation, url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        finding.module,
                        finding.title,
                        finding.severity,
                        finding.cvss,
                        finding.description,
                        finding.evidence,
                        finding.remediation,
                        finding.url,
                    )
                    for finding in result.findings
                ],
            )
            return scan_id

    def list_scans(self, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT scans.*, COUNT(findings.id) AS finding_count
                FROM scans
                LEFT JOIN findings ON findings.scan_id = scans.id
                GROUP BY scans.id
                ORDER BY scans.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_scan(self, scan_id: int) -> ScanResult | None:
        with self.connect() as connection:
            scan = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if scan is None:
                return None
            rows = connection.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY cvss DESC, id ASC",
                (scan_id,),
            ).fetchall()

        findings = [
            Finding(
                module=row["module"],
                title=row["title"],
                severity=row["severity"],
                cvss=row["cvss"],
                description=row["description"],
                evidence=row["evidence"],
                remediation=row["remediation"],
                url=row["url"],
            )
            for row in rows
        ]
        return ScanResult(
            target_url=scan["target_url"],
            started_at=scan["started_at"],
            finished_at=scan["finished_at"],
            findings=findings,
            metadata=json.loads(scan["metadata_json"]),
        )
