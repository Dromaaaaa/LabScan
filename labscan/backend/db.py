"""Stockage SQLite de l'historique des scans et des chaînes (pipelines)."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent.parent / "labscan.db"


@contextmanager
def connect():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS pipelines (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                target      TEXT NOT NULL,
                status      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                finished_at TEXT
            )
            """
        )
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pipeline_id INTEGER REFERENCES pipelines(id) ON DELETE CASCADE,
                tool        TEXT NOT NULL,
                target      TEXT NOT NULL,
                preset      TEXT,
                options     TEXT,
                status      TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                finished_at TEXT,
                result      TEXT
            )
            """
        )
        # Tout ce qui tournait au démarrage a été coupé par l'arrêt du serveur
        c.execute("UPDATE scans SET status = 'interrupted' WHERE status IN ('queued', 'running')")
        c.execute("UPDATE pipelines SET status = 'interrupted' WHERE status IN ('queued', 'running')")


# --- Scans -----------------------------------------------------------------

def create_scan(tool: str, target: str, preset: str, options: dict,
                pipeline_id: int | None = None) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO scans (pipeline_id, tool, target, preset, options, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'queued', ?)",
            (pipeline_id, tool, target, preset, json.dumps(options),
             datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def set_status(scan_id: int, status: str) -> None:
    with connect() as c:
        c.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))


def save_result(scan_id: int, result: dict) -> None:
    status = "error" if result.get("error") else "done"
    with connect() as c:
        c.execute(
            "UPDATE scans SET status = ?, finished_at = ?, result = ? WHERE id = ?",
            (status, result.get("finished_at"), json.dumps(result), scan_id),
        )


def _row(row: sqlite3.Row, with_result: bool) -> dict:
    d = dict(row)
    d["options"] = json.loads(d["options"] or "{}")
    result = json.loads(d.pop("result") or "null")
    if with_result:
        d["result"] = result
    elif result:
        d["summary"] = result.get("parsed", {}).get("summary")
        d["error"] = result.get("error")
    return d


def list_scans(limit: int = 100) -> list[dict]:
    """Scans autonomes uniquement (les scans d'une chaîne sont vus via la chaîne)."""
    with connect() as c:
        rows = c.execute(
            "SELECT * FROM scans WHERE pipeline_id IS NULL ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row(r, with_result=False) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with connect() as c:
        row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return _row(row, with_result=True) if row else None


def delete_scan(scan_id: int) -> bool:
    with connect() as c:
        cur = c.execute("DELETE FROM scans WHERE id = ? AND pipeline_id IS NULL", (scan_id,))
        return cur.rowcount > 0


# --- Pipelines (chaînes) ---------------------------------------------------

def create_pipeline(target: str) -> int:
    with connect() as c:
        cur = c.execute(
            "INSERT INTO pipelines (target, status, created_at) VALUES (?, 'queued', ?)",
            (target, datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def set_pipeline_status(pipeline_id: int, status: str, finished: bool = False) -> None:
    with connect() as c:
        if finished:
            c.execute(
                "UPDATE pipelines SET status = ?, finished_at = ? WHERE id = ?",
                (status, datetime.now(timezone.utc).isoformat(), pipeline_id),
            )
        else:
            c.execute("UPDATE pipelines SET status = ? WHERE id = ?", (status, pipeline_id))


def list_pipelines(limit: int = 100) -> list[dict]:
    with connect() as c:
        rows = c.execute("SELECT * FROM pipelines ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["steps"] = c.execute(
                "SELECT COUNT(*) n FROM scans WHERE pipeline_id = ?", (r["id"],)
            ).fetchone()["n"]
            out.append(d)
    return out


def get_pipeline(pipeline_id: int) -> dict | None:
    with connect() as c:
        row = c.execute("SELECT * FROM pipelines WHERE id = ?", (pipeline_id,)).fetchone()
        if row is None:
            return None
        children = c.execute(
            "SELECT * FROM scans WHERE pipeline_id = ? ORDER BY id", (pipeline_id,)
        ).fetchall()
    pipeline = dict(row)
    pipeline["scans"] = [_row(r, with_result=True) for r in children]
    return pipeline


def delete_pipeline(pipeline_id: int) -> bool:
    with connect() as c:
        cur = c.execute("DELETE FROM pipelines WHERE id = ?", (pipeline_id,))
        return cur.rowcount > 0
