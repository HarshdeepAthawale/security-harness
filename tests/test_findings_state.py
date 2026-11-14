import pytest

from kernel import findings, state
from kernel.db import connect_and_init


def _seed(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    conn.execute("INSERT INTO runs (run_id, target, contract_hash, budget_json, started_at) VALUES ('run1','t','h','{}','now')")
    conn.execute("INSERT INTO identities VALUES ('i1','run1','attacker','user_B','r')")
    conn.execute("INSERT INTO objects (id, run_id, resource_type, endpoint, method) VALUES ('o1','run1','order','/x','GET')")
    conn.execute("INSERT INTO coverage_units (id, run_id, object_id, action, identity_id) VALUES ('u1','run1','o1','read','i1')")
    conn.execute("INSERT INTO ledger (id, run_id, request_hash, method, url, ts) VALUES ('L1','run1','h1','GET','u','2026-01-01')")
    return conn


def test_normalize_path():
    assert findings.normalize_path("/api/orders/1001/items/7") == "/api/orders/{id}/items/{id}"
    assert findings.normalize_path("/api/u/3f2504e0-4f89-11d3-9a0c-0305e82c3301?x=1") == "/api/u/{id}"
    assert findings.normalize_path("/api/me") == "/api/me"


def test_same_root_cause_same_fingerprint():
    a = findings.compute_fingerprint("idor-bola", "get", "/api/orders/1", "attacker")
    b = findings.compute_fingerprint("idor-bola", "GET", "/api/orders/2", "attacker")
    c = findings.compute_fingerprint("idor-bola", "GET", "/api/orders/2", "victim")
    assert a == b != c


def test_record_candidate_dedups(tmp_path):
    conn = _seed(tmp_path)
    kw = dict(fingerprint="fp", run_id="run1", unit_id="u1", title="t", trace={})
    assert findings.record_candidate(conn, **kw) is True
    assert findings.record_candidate(conn, **kw) is False


def test_severity_only_on_confirmed(tmp_path):
    conn = _seed(tmp_path)
    findings.record_candidate(conn, fingerprint="fp", run_id="run1", unit_id="u1", title="t", trace={})
    with pytest.raises(ValueError, match="severity"):
        findings.write_finding(conn, fingerprint="fp", run_id="run1", verdict="needs_validation",
                               evidence_refs=[], severity="high")


def test_write_finding_updates_candidate_and_reports(tmp_path):
    conn = _seed(tmp_path)
    findings.record_candidate(conn, fingerprint="fp", run_id="run1", unit_id="u1", title="IDOR", trace={"a": 1})
    findings.write_finding(conn, fingerprint="fp", run_id="run1", verdict="confirmed",
                           evidence_refs=["L1"], severity="high", cleanup_done=True)
    status = conn.execute("SELECT status FROM candidates WHERE fingerprint='fp'").fetchone()["status"]
    assert status == "confirmed"
    report = findings.reportable_findings(conn, "run1")
    assert report[0]["title"] == "IDOR" and report[0]["evidence_refs"] == ["L1"]


def test_thread_lifecycle(tmp_path):
    conn = _seed(tmp_path)
    tid = state.create_thread(conn, run_id="run1", hypothesis="IDOR on orders", unit_id="u1")
    state.link_evidence(conn, tid, "L1", note="B read A's order")
    state.add_rejected_path(conn, tid, "numeric id swap")
    state.add_rejected_path(conn, tid, "numeric id swap")  # no duplicates
    state.update_thread(conn, tid, status="holding", reopen_condition="new endpoint found")

    thread = state.get_thread(conn, tid)
    assert thread["rejected_paths"] == ["numeric id swap"]
    assert thread["reopen_condition"] == "new endpoint found"
    assert thread["evidence"][0]["id"] == "L1"
    assert [t["id"] for t in state.open_threads(conn, "run1")] == [tid]


def test_bad_thread_status_rejected(tmp_path):
    conn = _seed(tmp_path)
    tid = state.create_thread(conn, run_id="run1", hypothesis="h")
    with pytest.raises(ValueError):
        state.update_thread(conn, tid, status="maybe")
