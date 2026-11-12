"""End-to-end tests of Orchestrator.run() with fake Broker / Judge / Brains."""
import json

from kernel.db import connect_and_init
from kernel.default_hooks import register_default_hooks
from kernel.hooks import HookRegistry
from kernel.models import Budget
from kernel.orchestrator import Orchestrator
from tests.fakes import IDENTITIES, FakeBrains, FakeBroker, FakeJudge, make_contract


def _run(tmp_path, broker=None, judge=None, brains=None, budget=None, contract=None):
    conn = connect_and_init(tmp_path / "t.db")
    orch = Orchestrator(conn, register_default_hooks(HookRegistry()))
    result = orch.run(
        contract or make_contract(),
        budget or Budget(max_hunter_calls=50, max_validator_calls=10),
        broker or FakeBroker(),
        judge or FakeJudge(),
        brains or FakeBrains(),
        identities=IDENTITIES,
    )
    return conn, result


def test_happy_path_confirms_idor(tmp_path):
    broker, judge = FakeBroker(), FakeJudge()
    conn, result = _run(tmp_path, broker=broker, judge=judge)

    assert result.status == "complete", result.reason
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f["verdict"] == "confirmed" and f["severity"] == "high"
    assert "user_B" in f["title"]
    assert result.report == "1 reportable finding(s)"
    # 2 units hunted (owner + attacker) + 1 replay
    assert len(broker.sent) == 3 and judge.replayed == 1
    ledger_ids = {r["id"] for r in conn.execute("SELECT id FROM ledger").fetchall()}
    assert set(f["evidence_refs"]) <= ledger_ids
    states = {r["state"] for r in conn.execute("SELECT state FROM coverage_units").fetchall()}
    assert states == {"covered", "candidate"}


def test_threads_record_rejections_and_confirmation(tmp_path):
    conn, _ = _run(tmp_path)
    rows = conn.execute("SELECT status, rejected_paths FROM threads ORDER BY status").fetchall()
    statuses = sorted(r["status"] for r in rows)
    assert statuses == ["confirmed", "rejected"]
    rejected = next(r for r in rows if r["status"] == "rejected")
    assert "no differential" in json.loads(rejected["rejected_paths"])[0]


def test_readiness_gate_halts_run(tmp_path):
    broker = FakeBroker(identity_ok=False)
    conn, result = _run(tmp_path, broker=broker)
    assert result.status == "incomplete" and "identity" in result.reason
    assert broker.sent == []
    assert conn.execute("SELECT status FROM runs").fetchone()["status"] == "incomplete"


def test_tampered_contract_halts_before_any_request(tmp_path):
    contract = make_contract()
    contract.allowed_paths.append("/*")
    broker = FakeBroker()
    _, result = _run(tmp_path, broker=broker, contract=contract)
    assert result.status == "incomplete" and "hash mismatch" in result.reason
    assert broker.sent == []


def test_out_of_scope_plan_never_reaches_broker(tmp_path):
    broker = FakeBroker()
    conn, result = _run(tmp_path, broker=broker, brains=FakeBrains(plan_path="/admin/users"))
    assert broker.sent == []
    assert result.findings == []
    states = {r["state"] for r in conn.execute("SELECT state FROM coverage_units").fetchall()}
    assert states == {"blocked"}
    reasons = [json.loads(r["rejected_paths"]) for r in conn.execute("SELECT rejected_paths FROM threads").fetchall()]
    assert all("out of scope" in paths[0] for paths in reasons)


def test_rate_limit_stops_run(tmp_path):
    broker = FakeBroker(status_for={"/api/orders/1001": 429})
    _, result = _run(tmp_path, broker=broker)
    assert result.status == "incomplete" and "429" in result.reason
    assert len(broker.sent) == 1  # stopped right after the first 429


def test_hunter_budget_exhaustion_is_incomplete(tmp_path):
    _, result = _run(tmp_path, budget=Budget(max_hunter_calls=1, max_validator_calls=10))
    assert result.status == "incomplete"
    assert "1 unit(s) deferred" in result.reason


def test_unfundable_validator_reserve_halts_before_hunting(tmp_path):
    broker = FakeBroker()
    _, result = _run(tmp_path, broker=broker, budget=Budget(max_hunter_calls=50, max_validator_calls=0))
    assert result.status == "incomplete" and "validator reserve" in result.reason
    assert broker.sent == []


def test_validator_disagreement_gives_needs_validation_without_severity(tmp_path):
    _, result = _run(tmp_path, brains=FakeBrains(validate_verdict="needs_validation"))
    assert result.status == "complete"
    f = result.findings[0]
    assert f["verdict"] == "needs_validation" and f["severity"] is None


def test_validator_rejection_drops_finding(tmp_path):
    _, result = _run(tmp_path, brains=FakeBrains(validate_verdict="rejected"))
    assert result.status == "complete" and result.findings == []


def test_non_reproducing_candidate_is_dropped(tmp_path):
    conn, result = _run(tmp_path, judge=FakeJudge(reproduces=False))
    assert result.findings == []
    statuses = {r["status"] for r in conn.execute("SELECT status FROM candidates").fetchall()}
    assert statuses == {"rejected"}


def test_missing_cleanup_downgrades_run(tmp_path):
    _, result = _run(tmp_path, judge=FakeJudge(cleanup=False))
    assert result.status == "incomplete" and "cleanup" in result.reason


def test_same_root_cause_reported_once(tmp_path):
    brains = FakeBrains(objects=[
        {"resource_type": "order", "endpoint": "/api/orders/1001", "method": "GET", "owner_identity": "user_A"},
        {"resource_type": "order", "endpoint": "/api/orders/1002", "method": "GET", "owner_identity": "user_A"},
    ])
    conn, result = _run(tmp_path, brains=brains)
    assert len(result.findings) == 1
    assert conn.execute("SELECT COUNT(*) AS n FROM candidates").fetchone()["n"] == 1


def test_validator_is_never_the_hunter(tmp_path):
    brains = FakeBrains()
    _run(tmp_path, brains=brains)
    assert brains.validated and all(t["hunter"].startswith("hunter-") for t in brains.validated)
