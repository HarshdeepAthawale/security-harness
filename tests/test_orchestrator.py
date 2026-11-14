import json

import pytest

from kernel.db import connect_and_init
from kernel.hooks import HookRegistry, HookVeto
from kernel.models import Contract, LedgerEntry, RequestPlan, new_id
from kernel.orchestrator import Orchestrator


class FakeBroker:
    """Minimal stand-in for the real broker workstream."""

    def __init__(self, status_code=200, resp_digest="deadbeef"):
        self.status_code = status_code
        self.resp_digest = resp_digest
        self.sent = []

    def send(self, plan: RequestPlan, contract: Contract) -> LedgerEntry:
        self.sent.append(plan)
        return LedgerEntry(
            run_id=contract.run_id,
            request_hash=f"hash-{plan.plan_id}",
            method=plan.method,
            url=f"https://{contract.target}{plan.path}",
            status_code=self.status_code,
            resp_digest=self.resp_digest,
            identity_id="id1",
        )

    def check_identity(self, contract: Contract) -> bool:
        return True


def _seeded(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    conn.execute(
        "INSERT INTO runs (run_id, target, contract_hash, budget_json, started_at) "
        "VALUES ('run1', 'target.test', 'h', '{}', 'now')"
    )
    conn.execute(
        "INSERT INTO identities (id, run_id, role, label, cred_ref) "
        "VALUES ('id1', 'run1', 'attacker', 'user_B', 'ref1')"
    )
    conn.execute(
        "INSERT INTO objects (id, run_id, resource_type, endpoint, method) "
        "VALUES ('obj1', 'run1', 'order', '/api/orders/1001', 'GET')"
    )
    conn.execute(
        "INSERT INTO coverage_units (id, run_id, object_id, action, identity_id) "
        "VALUES ('u1', 'run1', 'obj1', 'read', 'id1')"
    )
    return conn


def _contract():
    return Contract(
        run_id="run1", target="target.test", allowed_origins=["https://target.test"],
        allowed_paths=["/api/*"], allowed_methods=["GET", "POST"],
        identities=["user_B"], stop_conditions=["bot_challenge"], contract_hash="h",
    )


def test_dispatch_writes_ledger_row(tmp_path):
    conn = _seeded(tmp_path)
    orch = Orchestrator(conn)
    broker = FakeBroker()
    plan = RequestPlan(unit_id="u1", identity="user_B", method="GET", path="/api/orders/1001")

    entry = orch.dispatch(plan, _contract(), broker)

    row = conn.execute("SELECT * FROM ledger WHERE id = ?", (entry.id,)).fetchone()
    assert row is not None
    assert row["status_code"] == 200
    assert len(broker.sent) == 1


def test_pre_broker_request_hook_can_veto(tmp_path):
    conn = _seeded(tmp_path)
    hooks = HookRegistry()

    @hooks.on("pre_broker_request")
    def block_out_of_scope(ctx):
        if "/admin" in ctx["plan"].path:
            raise HookVeto("out of scope")

    orch = Orchestrator(conn, hooks)
    broker = FakeBroker()
    plan = RequestPlan(unit_id="u1", identity="user_B", method="GET", path="/admin/secret")

    with pytest.raises(HookVeto):
        orch.dispatch(plan, _contract(), broker)
    assert broker.sent == []  # never reached the broker


def test_accept_candidate_rejects_without_ledger_match(tmp_path):
    conn = _seeded(tmp_path)
    orch = Orchestrator(conn)
    conn.execute(
        "INSERT INTO candidates (fingerprint, run_id, unit_id, title, trace_json, created_at, updated_at) "
        "VALUES ('fp1', 'run1', 'u1', 'IDOR on order', ?, 'now', 'now')",
        (json.dumps({"request_hashes": ["hash-nonexistent"]}),),
    )

    accepted = orch.accept_candidate("fp1", "run1", json.dumps({"request_hashes": ["hash-nonexistent"]}))

    assert accepted is False
    row = conn.execute("SELECT status FROM candidates WHERE fingerprint='fp1'").fetchone()
    assert row["status"] == "rejected"


def test_accept_candidate_grounds_with_matching_ledger_row(tmp_path):
    conn = _seeded(tmp_path)
    orch = Orchestrator(conn)
    broker = FakeBroker()
    plan = RequestPlan(unit_id="u1", identity="user_B", method="GET", path="/api/orders/1001")
    entry = orch.dispatch(plan, _contract(), broker)

    conn.execute(
        "INSERT INTO candidates (fingerprint, run_id, unit_id, title, trace_json, created_at, updated_at) "
        "VALUES ('fp2', 'run1', 'u1', 'IDOR on order', ?, 'now', 'now')",
        (json.dumps({"request_hashes": [entry.request_hash]}),),
    )

    accepted = orch.accept_candidate("fp2", "run1", json.dumps({"request_hashes": [entry.request_hash]}))

    assert accepted is True
    row = conn.execute("SELECT status FROM candidates WHERE fingerprint='fp2'").fetchone()
    assert row["status"] == "grounded"


def test_assign_validator_refuses_same_identity(tmp_path):
    conn = _seeded(tmp_path)
    orch = Orchestrator(conn)
    with pytest.raises(HookVeto):
        orch.assign_validator("hunter_A", "hunter_A")


def test_assign_validator_allows_different_identity(tmp_path):
    conn = _seeded(tmp_path)
    orch = Orchestrator(conn)
    orch.assign_validator("hunter_A", "validator_B")  # should not raise
