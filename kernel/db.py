"""
Database layer for the kernel. SQLite is the single source of truth.

Only the orchestrator writes to these tables (the "single writer" invariant,
PROJECT.md §6.2). Everything else — broker, judge, brains — reads/writes
through the kernel's API, never the DB file directly.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open a connection with sane defaults (row factory, FK enforcement)."""
    conn = sqlite3.connect(db_path, isolation_level=None)  # autocommit; we manage txns explicitly
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Apply schema.sql. Idempotent (CREATE TABLE IF NOT EXISTS everywhere)."""
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    conn.executescript(schema)


def connect_and_init(db_path: str | Path) -> sqlite3.Connection:
    conn = connect(db_path)
    init_db(conn)
    return conn
