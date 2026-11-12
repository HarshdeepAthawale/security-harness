"""
Candidates, findings, and fingerprint dedup (PROJECT.md §6.1 job 6).

One root cause = one fingerprint. Two hunters that hit /api/orders/1001 and
/api/orders/2002 with the same pack, method and identity role found the
same bug, so they share a fingerprint and only the first is kept.
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
    """Insert a candidate. Returns False if this fingerprint already exists
    (a duplicate of a root cause we already have), True if it's new."""
    exists = conn.execute("SELECT 1 FROM candidates WHERE fingerprint = ?", (fingerprint,)).fetchone()
    if exists:
        return False
    ts = now_iso()
    conn.execute(
        "INSERT INTO candidates (fingerprint, run_id, unit_id, title, trace_json, proposed_verdict, "
        "status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'proposed', ?, ?)",
        (fingerprint, run_id, unit_id, title, json.dumps(trace), proposed_verdict, ts, ts),
    )
    return True


def set_candidate_status(conn: sqlite3.Connection, fingerprint: str, status: str) -> None:
    conn.execute(
        "UPDATE candidates SET status = ?, updated_at = ? WHERE fingerprint = ?",
        (status, now_iso(), fingerprint),
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
    set_candidate_status(conn, fingerprint, verdict)


def reportable_findings(conn: sqlite3.Connection, run_id: str) -> list[dict]:
    """Confirmed + needs_validation findings, joined with their candidate title."""
    rows = conn.execute(
        """
        SELECT f.fingerprint, f.verdict, f.severity, f.evidence_refs, f.cleanup_done, c.title, c.trace_json
        FROM findings f JOIN candidates c ON c.fingerprint = f.fingerprint
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
            "trace": json.loads(r["trace_json"]),
        }
        for r in rows
    ]
