"""SQLite persistence for privacy-preserving scan history."""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal

ScanType = Literal["message", "url", "screenshot"]
_SCAN_TYPES = ("message", "url", "screenshot")
_RISK_LEVELS = ("elevated", "unconfirmed", "caution", "unverified")
_DATABASE_ENV_VAR = "SCAMSHIELD_HISTORY_DB_PATH"


def get_database_path() -> Path:
    """Return the configured database path or a per-user local app-data path."""
    configured_path = os.environ.get(_DATABASE_ENV_VAR)
    if configured_path:
        return Path(configured_path).expanduser()

    if os.name == "nt":
        app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        base_path = Path(app_data) if app_data else Path.home() / "AppData" / "Local"
    else:
        base_path = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base_path / "ScamShieldAI" / "scan_history.sqlite3"


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_history (
            scan_id TEXT PRIMARY KEY,
            scan_type TEXT NOT NULL CHECK (scan_type IN ('message', 'url', 'screenshot')),
            timestamp TEXT NOT NULL,
            risk_level TEXT NOT NULL CHECK (
                risk_level IN ('elevated', 'unconfirmed', 'caution', 'unverified')
            ),
            predicted_class TEXT,
            model_confidence REAL,
            warning_signs TEXT NOT NULL,
            risk_indicators TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            explanation TEXT NOT NULL,
            details TEXT NOT NULL
        )
        """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp "
        "ON scan_history(timestamp DESC)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_type_timestamp "
        "ON scan_history(scan_type, timestamp DESC)"
    )


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    path = get_database_path()
    if str(path) != ":memory:":
        path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        _initialize_schema(connection)
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    """Create the database and schema if they do not already exist."""
    with _connection():
        pass


def _decode_json(value: str) -> Any:
    return json.loads(value)


def _record_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scan_id": row["scan_id"],
        "scan_type": row["scan_type"],
        "timestamp": row["timestamp"],
        "risk_level": row["risk_level"],
        "predicted_class": row["predicted_class"],
        "model_confidence": row["model_confidence"],
        "warning_signs": _decode_json(row["warning_signs"]),
        "risk_indicators": _decode_json(row["risk_indicators"]),
        "recommendations": _decode_json(row["recommendations"]),
        "explanation": row["explanation"],
        "details": _decode_json(row["details"]),
    }


def insert_scan(
    *,
    scan_type: ScanType,
    risk_level: str,
    explanation: str,
    warning_signs: list[str],
    recommendations: list[str],
    risk_indicators: list[str] | None = None,
    predicted_class: str | None = None,
    model_confidence: float | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Persist only scan results and explicitly supplied non-content metadata."""
    if scan_type not in _SCAN_TYPES:
        raise ValueError(f"Unsupported scan type: {scan_type}")
    if risk_level not in _RISK_LEVELS:
        raise ValueError(f"Unsupported risk level: {risk_level}")
    scan_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    values = (
        scan_id,
        scan_type,
        timestamp,
        risk_level,
        predicted_class,
        model_confidence,
        json.dumps(warning_signs, ensure_ascii=False),
        json.dumps(risk_indicators or [], ensure_ascii=False),
        json.dumps(recommendations, ensure_ascii=False),
        explanation,
        json.dumps(details or {}, ensure_ascii=False),
    )
    with _connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history (
                scan_id, scan_type, timestamp, risk_level, predicted_class,
                model_confidence, warning_signs, risk_indicators,
                recommendations, explanation, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        row = connection.execute(
            "SELECT * FROM scan_history WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Inserted scan history record could not be retrieved.")
    return _record_from_row(row)


def _summary_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "scan_id": row["scan_id"],
        "scan_type": row["scan_type"],
        "timestamp": row["timestamp"],
        "risk_level": row["risk_level"],
        "predicted_class": row["predicted_class"],
        "model_confidence": row["model_confidence"],
        "warning_signs": _decode_json(row["warning_signs"]),
        "risk_indicators": _decode_json(row["risk_indicators"]),
    }


def list_scans(
    *,
    limit: int,
    offset: int,
    scan_type: ScanType | None = None,
) -> dict[str, Any]:
    """List scans newest-first with bounded pagination performed by the caller."""
    with _connection() as connection:
        if scan_type is None:
            total = connection.execute(
                "SELECT COUNT(*) FROM scan_history"
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT scan_id, scan_type, timestamp, risk_level, predicted_class,
                       model_confidence, warning_signs, risk_indicators
                FROM scan_history
                ORDER BY timestamp DESC, rowid DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        else:
            total = connection.execute(
                "SELECT COUNT(*) FROM scan_history WHERE scan_type = ?",
                (scan_type,),
            ).fetchone()[0]
            rows = connection.execute(
                """
                SELECT scan_id, scan_type, timestamp, risk_level, predicted_class,
                       model_confidence, warning_signs, risk_indicators
                FROM scan_history
                WHERE scan_type = ?
                ORDER BY timestamp DESC, rowid DESC
                LIMIT ? OFFSET ?
                """,
                (scan_type, limit, offset),
            ).fetchall()
    return {"total": total, "items": [_summary_from_row(row) for row in rows]}


def get_scan(scan_id: str) -> dict[str, Any] | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM scan_history WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    return _record_from_row(row) if row is not None else None


def delete_all_scans() -> int:
    with _connection() as connection:
        deleted_count = connection.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]
        connection.execute("DELETE FROM scan_history")
    return deleted_count


def dashboard_summary(*, recent_limit: int = 5) -> dict[str, Any]:
    with _connection() as connection:
        total_scans = connection.execute(
            "SELECT COUNT(*) FROM scan_history"
        ).fetchone()[0]
        scan_type_rows = connection.execute(
            "SELECT scan_type, COUNT(*) AS count FROM scan_history GROUP BY scan_type"
        ).fetchall()
        risk_rows = connection.execute(
            "SELECT risk_level, COUNT(*) AS count FROM scan_history GROUP BY risk_level"
        ).fetchall()
        latest_scan_at = connection.execute(
            "SELECT MAX(timestamp) FROM scan_history"
        ).fetchone()[0]
        recent_rows = connection.execute(
            """
            SELECT scan_id, scan_type, timestamp, risk_level, predicted_class,
                   model_confidence, warning_signs, risk_indicators
            FROM scan_history
            ORDER BY timestamp DESC, rowid DESC
            LIMIT ?
            """,
            (recent_limit,),
        ).fetchall()

    scan_type_counts = {scan_type: 0 for scan_type in _SCAN_TYPES}
    scan_type_counts.update({row["scan_type"]: row["count"] for row in scan_type_rows})
    risk_level_counts = {risk_level: 0 for risk_level in _RISK_LEVELS}
    risk_level_counts.update({row["risk_level"]: row["count"] for row in risk_rows})
    return {
        "total_scans": total_scans,
        "scan_type_counts": scan_type_counts,
        "risk_level_counts": risk_level_counts,
        "latest_scan_at": latest_scan_at,
        "recent_scans": [_summary_from_row(row) for row in recent_rows],
    }
