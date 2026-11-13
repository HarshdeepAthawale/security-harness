"""
Candidates, findings, and fingerprint dedup (PROJECT.md §6.1 job 6).

One root cause = one fingerprint. Two hunters that hit /api/orders/1001 and
/api/orders/2002 with the same pack, method and identity role found the
same bug, so they share a fingerprint and only the first is kept.

Dedup is per run: the fingerprint is stable across runs, but each run keeps
its own candidate. A re-run that finds a known bug still reports it, with
`previously_confirmed_in` pointing at the run that confirmed it first.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3

from kernel.models import now_iso

VERDICTS = ("confirmed", "needs_validation", "rejected")

_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,})$"
)


def normalize_path(path: str) -> str:
    """/api/orders/1001/items/7 -> /api/orders/{id}/items/{id}"""
    path = path.split("?", 1)[0]
    return "/".join("{id}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/"))


def compute_fingerprint(pack: str, method: str, path: str, identity_role: str = "") -> str:
    key = f"{pack}|{method.upper()}|{normalize_path(path)}|{identity_role}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def record_candidate(
    conn: sqlite3.Connection,
    *,
    fingerprint: str,
    run_id: str,
    unit_id: str,
    title: str,
    trace: dict,
    proposed_verdict: str | None = None,
) -> bool:
    """Insert a candidate. Returns False if this run already has this
    fingerprint (a duplicate of a root cause we already have), True if new."""
    exists = conn.execute(
        "SELECT 1 FROM candidates WHERE run_id = ? AND fingerprint = ?", (run_id, fingerprint)
    ).fetchone()
    if exists:
        return False
    ts = now_iso()
    conn.execute(
        "INSERT INTO candidates (fingerprint, run_id, unit_id, title, trace_json, proposed_verdict, "
        "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
        (fingerprint, run_id, unit_id, title, json.dumps(trace), proposed_verdict, ts, ts),
    )
    return True


def set_candidate_status(conn: sqlite3.Connection, run_id: str, fingerprint: str, status: str) -> None:
    conn.execute(
        "UPDATE candidates SET status = ?, updated_at = ? WHERE run_id = ? AND fingerprint = ?",
        (status, now_iso(), run_id, fingerprint),
    )


def write_finding(
    conn: sqlite3.Connection,
    *,
    fingerprint: str,
    run_id: str,
    verdict: str,
    evidence_refs: list[str],
    severity: str | None = None,
    cleanup_done: bool = False,
) -> None:
    """Severity is only allowed on a confirmed finding (PROJECT.md §4.2)."""
    if verdict not in VERDICTS:
        raise ValueError(f"unknown verdict {verdict!r}")
    if verdict != "confirmed" and severity is not None:
        raise ValueError("severity may only be set on a confirmed finding")
    conn.execute(
        "INSERT OR REPLACE INTO findings (fingerprint, run_id, verdict, severity, evidence_refs, cleanup_done) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (fingerprint, run_id, verdict, severity, json.dumps(evidence_refs), int(cleanup_done)),
    )
    set_candidate_status(conn, run_id, fingerprint, verdict)


def reportable_findings(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    """Confirmed + needs_validation findings for this run, each flagged with
    the earliest other run that already confirmed the same root cause."""
    rows = conn.execute(
        """
        SELECT f.fingerprint, f.verdict, f.severity, f.evidence_refs, f.cleanup_done, c.title, c.trace_json,
               (SELECT f2.run_id FROM findings f2 JOIN runs r2 ON r2.run_id = f2.run_id
                WHERE f2.fingerprint = f.fingerprint AND f2.run_id != f.run_id AND f2.verdict = 'confirmed'
                ORDER BY r2.started_at, r2.rowid LIMIT 1) AS previously_confirmed_in
        FROM findings f JOIN candidates c ON c.run_id = f.run_id AND c.fingerprint = f.fingerprint
        WHERE f.run_id = ? AND f.verdict IN ('confirmed', 'needs_validation')
        ORDER BY f.verdict, c.title
        """,
        (run_id,),
    ).fetchall()
    return [
        {
            "fingerprint": r["fingerprint"],
            "verdict": r["verdict"],
            "severity": r["severity"],
            "title": r["title"],
            "evidence_refs": json.loads(r["evidence_refs"]),
            "cleanup_done": bool(r["cleanup_done"]),
            "previously_confirmed_in": r["previously_confirmed_in"],
            "trace": json.loads(r["trace_json"]),
        }
        for r in rows
    ]
