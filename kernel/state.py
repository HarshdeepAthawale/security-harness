"""
Research-state API (PROJECT.md §9): curated threads, separate from the
ledger. The ledger saves every exchange; a thread records what we believe,
what we ruled out, and what would make us look again. A fresh agent reads
threads, not raw scrollback.
"""
from __future__ import annotations

import json
import sqlite3

from kernel.models import new_id

THREAD_STATUSES = ("open", "holding", "rejected", "confirmed")


def create_thread(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    hypothesis: str,
    unit_id: str | None = None,
    next_step: str | None = None,
    assumptions: dict | None = None,
    env_conditions: dict | None = None,
) -> str:
    thread_id = new_id("thr")
    conn.execute(
        "INSERT INTO threads (id, run_id, unit_id, hypothesis, status, next_step, rejected_paths, "
        "reopen_condition, assumptions, env_conditions) VALUES (?, ?, ?, ?, 'open', ?, '[]', NULL, ?, ?)",
        (thread_id, run_id, unit_id, hypothesis, next_step,
         json.dumps(assumptions or {}), json.dumps(env_conditions or {})),
    )
    return thread_id


def update_thread(
    conn: sqlite3.Connection,
    thread_id: str,
    *,
    status: str | None = None,
    next_step: str | None = None,
    reopen_condition: str | None = None,
) -> None:
    if status is not None and status not in THREAD_STATUSES:
        raise ValueError(f"unknown thread status {status!r}")
    fields, values = [], []
    for column, value in (("status", status), ("next_step", next_step), ("reopen_condition", reopen_condition)):
        if value is not None:
            fields.append(f"{column} = ?")
            values.append(value)
    if fields:
        conn.execute(f"UPDATE threads SET {', '.join(fields)} WHERE id = ?", (*values, thread_id))


def add_rejected_path(conn: sqlite3.Connection, thread_id: str, path: str) -> None:
    """Record a dead end so no agent walks it again."""
    row = conn.execute("SELECT rejected_paths FROM threads WHERE id = ?", (thread_id,)).fetchone()
    if row is None:
        raise KeyError(thread_id)
    paths = json.loads(row["rejected_paths"] or "[]")
    if path not in paths:
        paths.append(path)
    conn.execute("UPDATE threads SET rejected_paths = ? WHERE id = ?", (json.dumps(paths), thread_id))


def link_evidence(conn: sqlite3.Connection, thread_id: str, ledger_id: str, note: str | None = None) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO thread_evidence (thread_id, ledger_id, note) VALUES (?, ?, ?)",
        (thread_id, ledger_id, note),
    )


def get_thread(conn: sqlite3.Connection, thread_id: str) -> dict:
    """A thread plus the ledger rows behind it (the retrieval path)."""
    row = conn.execute("SELECT * FROM threads WHERE id = ?", (thread_id,)).fetchone()
    if row is None:
        raise KeyError(thread_id)
    evidence = conn.execute(
        """
        SELECT l.id, l.method, l.url, l.status_code, l.resp_digest, te.note
        FROM thread_evidence te JOIN ledger l ON l.id = te.ledger_id
        WHERE te.thread_id = ? ORDER BY l.ts
        """,
        (thread_id,),
    ).fetchall()
    thread = dict(row)
    thread["rejected_paths"] = json.loads(thread["rejected_paths"] or "[]")
    thread["assumptions"] = json.loads(thread["assumptions"] or "{}")
    thread["env_conditions"] = json.loads(thread["env_conditions"] or "{}")
    thread["evidence"] = [dict(e) for e in evidence]
    return thread


def open_threads(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT id FROM threads WHERE run_id = ? AND status IN ('open', 'holding')", (run_id,)
    ).fetchall()
    return [get_thread(conn, r["id"]) for r in rows]
