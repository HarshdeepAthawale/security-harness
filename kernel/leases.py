"""
Lease-based work recovery (PROJECT.md §6.2 — "leases, not trust").

A coverage_unit claimed by a worker gets a lease with an expiry. If the
worker dies, the lease lapses and the unit is reclaimed by someone else —
the kernel never just assumes a long-silent worker finished.
"""
from __future__ import annotations

import sqlite3
import time


def claim(conn: sqlite3.Connection, unit_id: str, agent_id: str, ttl_seconds: int = 300) -> bool:
    """Try to claim a unit. Returns False if already validly leased by someone else."""
    now = time.time()
    row = conn.execute("SELECT agent_id, expires_at FROM leases WHERE unit_id = ?", (unit_id,)).fetchone()
    if row is not None:
        expires_at = float(row["expires_at"])
        if expires_at > now and row["agent_id"] != agent_id:
            return False  # still validly held by someone else
        conn.execute("DELETE FROM leases WHERE unit_id = ?", (unit_id,))

    expires_at = now + ttl_seconds
    conn.execute(
        "INSERT INTO leases (unit_id, agent_id, expires_at) VALUES (?, ?, ?)",
        (unit_id, agent_id, str(expires_at)),
    )
    conn.execute(
        "UPDATE coverage_units SET state = 'in_progress', owner_agent = ? WHERE id = ?",
        (agent_id, unit_id),
    )
    return True


def release(conn: sqlite3.Connection, unit_id: str, agent_id: str, new_state: str) -> None:
    """Worker finished (or gave up). Drop the lease, set the final state."""
    conn.execute("DELETE FROM leases WHERE unit_id = ? AND agent_id = ?", (unit_id, agent_id))
    conn.execute("UPDATE coverage_units SET state = ?, owner_agent = NULL WHERE id = ?", (new_state, unit_id))


def release_all(conn: sqlite3.Connection, run_id: str) -> int:
    """Drop every lease in a run and put its in-flight units back to
    'planned'. Used when a run stops or crashes: those workers are gone."""
    conn.execute(
        "DELETE FROM leases WHERE unit_id IN (SELECT id FROM coverage_units WHERE run_id = ?)", (run_id,)
    )
    cur = conn.execute(
        "UPDATE coverage_units SET state = 'planned', owner_agent = NULL WHERE run_id = ? AND state = 'in_progress'",
        (run_id,),
    )
    return cur.rowcount


def reap_expired(conn: sqlite3.Connection, run_id: str) -> list[str]:
    """Reclaim any lapsed leases for this run. Returns the unit_ids recovered."""
    now = time.time()
    rows = conn.execute(
        """
        SELECT l.unit_id FROM leases l
        JOIN coverage_units c ON c.id = l.unit_id
        WHERE c.run_id = ? AND l.expires_at <= ?
        """,
        (run_id, str(now)),
    ).fetchall()
    recovered = [r["unit_id"] for r in rows]
    for unit_id in recovered:
        conn.execute("DELETE FROM leases WHERE unit_id = ?", (unit_id,))
        conn.execute("UPDATE coverage_units SET state = 'planned', owner_agent = NULL WHERE id = ?", (unit_id,))
    return recovered
