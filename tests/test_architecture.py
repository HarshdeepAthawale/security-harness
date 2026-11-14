"""Architecture guarantees: safety can't be skipped, traffic is capped, the
broker's record is checked, and every attempted request is on record."""
import json

import pytest

from kernel.db import connect_and_init
from kernel.default_hooks import register_default_hooks
from kernel.hooks import HookRegistry, HookVeto
from kernel.models import Budget, RequestPlan
from kernel.orchestrator import Orchestrator
from tests.fakes import IDENTITIES, FakeBrains, FakeBroker, FakeJudge, make_contract


def _orch(tmp_path, hooks=None):
    conn = connect_and_init(tmp_path / "t.db")
    return conn, Orchestrator(conn, hooks)


def _run(orch, broker=None, brains=None, budget=None, **kw):
    return orch.run(make_contract(), budget or Budget(50, 10), broker or FakeBroker(), FakeJudge(),
                    brains or FakeBrains(), identities=IDENTITIES, **kw)


def _outcomes(conn):
    return [r["outcome"] for r in conn.execute("SELECT outcome FROM dispatches ORDER BY ts, rowid")]


# -- 1. safety can't be skipped ---------------------------------------------------

def test_scope_is_enforced_without_registering_hooks(tmp_path):
    conn, orch = _orch(tmp_path)                      # no hooks passed at all
    broker = FakeBroker()
    _run(orch, broker, FakeBrains(plan_path="/admin/users"))
    assert broker.sent == []
    assert set(_outcomes(conn)) == {"vetoed"}


def test_tampered_contract_refused_without_registering_hooks(tmp_path):
    _, orch = _orch(tmp_path)
    contract = make_contract()
    contract.allowed_paths.append("/*")
    result = orch.run(contract, Budget(50, 10), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    assert result.status == "incomplete" and "hash mismatch" in result.reason


def test_default_hooks_are_not_installed_twice(tmp_path):
    registry = register_default_hooks(HookRegistry())
    _, orch = _orch(tmp_path, registry)
    assert len(orch.hooks._hooks["pre_broker_request"]) == 1


def test_extra_hooks_still_run_on_top_of_defaults(tmp_path):
    extra = HookRegistry()
    seen = []
    extra.register("pre_broker_request", lambda ctx: seen.append(ctx["plan"].path))
    _, orch = _orch(tmp_path, extra)
    _run(orch)
    assert seen and all(p.startswith("/api/") for p in seen)


# -- 2. traffic is capped -------------------------------------------------------------

class ManyPlans(FakeBrains):
    def __init__(self, n, **kw):
        super().__init__(**kw)
        self.n = n

    def hunt(self, unit, contract):
        return [RequestPlan(unit_id=unit["unit_id"], identity=unit["identity"], method="GET",
                            path=unit["endpoint"], pack="idor-bola") for _ in range(self.n)]


def test_one_hunt_cannot_flood_the_target(tmp_path):
    _, orch = _orch(tmp_path)
    broker = FakeBroker()
    result = _run(orch, broker, ManyPlans(500))
    assert broker.sent == []
    assert result.status == "incomplete" and "limit is 20" in result.reason


def test_request_budget_counts_every_request_including_replays(tmp_path):
    conn, orch = _orch(tmp_path)
    broker = FakeBroker()
    result = _run(orch, broker, budget=Budget(50, 10, max_requests=2))
    # unit 1 sends 1 request, unit 2 sends 1, the replay would be the 3rd
    assert len(broker.sent) == 2
    assert result.status == "incomplete" and "request budget exhausted" in result.reason
    assert "over_budget" in _outcomes(conn)
    saved = json.loads(conn.execute("SELECT budget_json FROM runs").fetchone()["budget_json"])
    assert saved["used_requests"] == 2


class StopsDuringReplay(FakeJudge):
    """Its replay hits the request budget, so ground() never finishes."""

    def ground(self, trace, run_id, replay):
        replay(RequestPlan(**trace["plans"][0]))          # raises: budget is spent
        raise AssertionError("unreachable")


def test_candidate_interrupted_before_replay_is_never_validated(tmp_path):
    """The bug this guards: a candidate marked 'grounded' before its replay,
    then validated on resume without ever being reproduced."""
    conn, orch = _orch(tmp_path)
    contract = make_contract()
    brains = FakeBrains()
    # 1 object x 2 identities = 2 units; 2 requests lets both hunts through,
    # so whichever unit is the attack, its replay is request #3: over budget.
    result = orch.run(contract, Budget(50, 10, max_requests=2), FakeBroker(), StopsDuringReplay(), brains,
                      identities=IDENTITIES)
    assert result.status == "incomplete"
    statuses = [r["status"] for r in conn.execute("SELECT status FROM candidates")]
    assert "grounded" not in statuses                     # never reproduced, so never grounded

    resumed = orch.resume(contract, FakeBroker(), FakeJudge(), brains, add_requests=10)
    assert resumed.status == "complete", resumed.reason
    assert [f["verdict"] for f in resumed.findings] == ["confirmed"]
    assert all(f["cleanup_done"] for f in resumed.findings)   # it went through a real replay


def test_resume_can_add_request_budget(tmp_path):
    _, orch = _orch(tmp_path)
    contract = make_contract()
    orch.run(contract, Budget(50, 10, max_requests=2), FakeBroker(), FakeJudge(), FakeBrains(),
             identities=IDENTITIES)
    resumed = orch.resume(contract, FakeBroker(), FakeJudge(), FakeBrains(), add_requests=10)
    assert resumed.status == "complete", resumed.reason
    assert len(resumed.findings) == 1


# -- 3. the broker's record is checked -------------------------------------------------

class TamperingBroker(FakeBroker):
    def __init__(self, change):
        super().__init__()
        self.change = change

    def send(self, plan, contract):
        entry = super().send(plan, contract)
        self.change(entry)
        return entry


@pytest.mark.parametrize("change, expected", [
    (lambda e: setattr(e, "url", "https://other-host.example/api/orders/1001"), "allowed_origins"),
    (lambda e: setattr(e, "url", "http://target.test/api/orders/1001"), "allowed_origins"),   # scheme downgrade
    (lambda e: setattr(e, "url", "https://target.test/admin"), "path"),
    (lambda e: setattr(e, "url", "https://target.test/api/x/../orders/1001"), "path"),
    (lambda e: setattr(e, "method", "DELETE"), "method"),
])
def test_broker_record_that_differs_from_the_plan_stops_the_run(tmp_path, change, expected):
    conn, orch = _orch(tmp_path)
    result = _run(orch, TamperingBroker(change))
    assert result.status == "incomplete"
    assert "doesn't match the plan" in result.reason and expected in result.reason
    assert "record_mismatch" in _outcomes(conn)
    # what the broker reported is still kept as evidence, under this run
    assert conn.execute("SELECT run_id FROM ledger").fetchone()["run_id"] == "run1"


def test_kernel_assigns_ledger_ids_run_and_identity(tmp_path):
    conn, orch = _orch(tmp_path)
    broker = TamperingBroker(lambda e: (setattr(e, "id", "same-id-every-time"),
                                        setattr(e, "run_id", "run1")))
    result = _run(orch, broker)
    assert result.status == "complete", result.reason
    rows = conn.execute("SELECT id, identity_id FROM ledger").fetchall()
    assert len({r["id"] for r in rows}) == len(rows) >= 3      # no collisions
    labels = {r["label"] for r in conn.execute(
        "SELECT i.label FROM ledger l JOIN identities i ON i.id = l.identity_id")}
    assert labels == {"user_A", "user_B"}


def test_broker_returning_the_wrong_type_is_a_broker_fault(tmp_path):
    conn, orch = _orch(tmp_path)
    broker = FakeBroker()
    broker.send = lambda plan, contract: {"status": 200}
    result = _run(orch, broker)
    assert result.status == "incomplete" and "broker failed" in result.reason
    assert "broker_error" in _outcomes(conn)


# -- 4. every attempt is on record ------------------------------------------------------

def test_failed_send_is_still_on_record(tmp_path):
    conn, orch = _orch(tmp_path)
    _run(orch, FakeBroker(raise_error=TimeoutError("read timeout")))
    row = conn.execute("SELECT outcome, method, path, identity, detail FROM dispatches").fetchone()
    assert row["outcome"] == "broker_error"
    assert (row["method"], row["path"]) == ("GET", "/api/orders/1001")
    assert "read timeout" in row["detail"]


def test_every_recorded_dispatch_points_at_its_ledger_row(tmp_path):
    conn, orch = _orch(tmp_path)
    _run(orch)
    rows = conn.execute("SELECT outcome, ledger_id FROM dispatches").fetchall()
    assert rows and all(r["outcome"] == "recorded" and r["ledger_id"] for r in rows)
    assert len(rows) == conn.execute("SELECT COUNT(*) AS n FROM ledger").fetchone()["n"]


def test_dispatch_log_never_holds_secrets(tmp_path):
    conn, orch = _orch(tmp_path)
    _run(orch)
    columns = [c["name"] for c in conn.execute("PRAGMA table_info(dispatches)")]
    dump = json.dumps([dict(r) for r in conn.execute("SELECT * FROM dispatches")])
    assert not any("cred" in c or "token" in c for c in columns)
    assert "vault:" not in dump                                # cred_refs stay in identities
