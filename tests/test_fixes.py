"""Tests for the four kernel bug fixes: scope traversal, error handling,
resume, and cross-run dedup."""
import json

import pytest

from kernel.db import connect_and_init
from kernel.default_hooks import enforce_scope, register_default_hooks
from kernel.hooks import HookRegistry, HookVeto
from kernel.models import Budget, RequestPlan
from kernel.orchestrator import Orchestrator
from tests.fakes import IDENTITIES, FakeBrains, FakeBroker, FakeJudge, make_contract


def _orch(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    return conn, Orchestrator(conn, register_default_hooks(HookRegistry()))


def _budget(hunter=50, validator=10):
    return Budget(max_hunter_calls=hunter, max_validator_calls=validator)


# -- 1. scope traversal ------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/../admin/users",
    "/api/%2e%2e/admin",
    "/api/%252e%252e/admin",        # double-encoded
    "/api/..;/admin",               # Tomcat path parameter trick
    "/api/./orders",
    "/api//evil",
    "/api/%2fadmin",                # encoded slash
    "/api/x\\..\\admin",            # backslashes
    "/api/x%00.json",               # NUL byte
    "api/orders",                   # not relative to the root
])
def test_scope_blocks_path_tricks(path):
    plan = RequestPlan(unit_id="u", identity="user_B", method="GET", path=path)
    with pytest.raises(HookVeto):
        enforce_scope({"plan": plan, "contract": make_contract()})


@pytest.mark.parametrize("path", ["/api/orders/1", "/api/orders/", "/api/orders/1?next=../x", "/api/a%20b"])
def test_scope_allows_normal_paths(path):
    plan = RequestPlan(unit_id="u", identity="user_B", method="GET", path=path)
    enforce_scope({"plan": plan, "contract": make_contract()})


# -- 2. error handling ---------------------------------------------------------

def test_broker_error_ends_run_incomplete_and_frees_leases(tmp_path):
    conn, orch = _orch(tmp_path)
    result = orch.run(make_contract(), _budget(), FakeBroker(raise_error=ConnectionError("target down")),
                      FakeJudge(), FakeBrains(), identities=IDENTITIES)

    assert result.status == "incomplete"
    assert "broker failed" in result.reason and "target down" in result.reason
    assert conn.execute("SELECT status FROM runs").fetchone()["status"] == "incomplete"
    assert conn.execute("SELECT COUNT(*) AS n FROM leases").fetchone()["n"] == 0
    assert {r["state"] for r in conn.execute("SELECT state FROM coverage_units")} == {"planned"}


def test_brains_error_names_brains(tmp_path):
    _, orch = _orch(tmp_path)
    result = orch.run(make_contract(), _budget(), FakeBroker(), FakeJudge(),
                      FakeBrains(hunt_raises=RuntimeError("LLM timeout")), identities=IDENTITIES)
    assert result.status == "incomplete" and "brains failed" in result.reason


def test_existing_run_id_is_never_touched_by_run(tmp_path):
    conn, orch = _orch(tmp_path)
    first = orch.run(make_contract(), _budget(), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    assert first.status == "complete"
    again = orch.run(make_contract(), _budget(), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    assert again.status == "incomplete" and "already exists" in again.reason
    assert conn.execute("SELECT status FROM runs").fetchone()["status"] == "complete"


# -- 3. resume -------------------------------------------------------------------

def test_resume_after_error(tmp_path):
    _, orch = _orch(tmp_path)
    contract = make_contract()
    failed = orch.run(contract, _budget(), FakeBroker(raise_error=ConnectionError("down")),
                      FakeJudge(), FakeBrains(), identities=IDENTITIES)
    assert failed.status == "incomplete"

    resumed = orch.resume(contract, FakeBroker(), FakeJudge(), FakeBrains())
    assert resumed.status == "complete", resumed.reason
    assert [f["verdict"] for f in resumed.findings] == ["confirmed"]


def test_resume_after_hard_crash(tmp_path):
    """KeyboardInterrupt isn't caught (like the process being killed): the run
    stays in_progress with a held lease. resume() must recover it."""
    conn, orch = _orch(tmp_path)
    contract = make_contract()
    with pytest.raises(KeyboardInterrupt):
        orch.run(contract, _budget(), FakeBroker(), FakeJudge(),
                 FakeBrains(hunt_raises=KeyboardInterrupt()), identities=IDENTITIES)
    assert conn.execute("SELECT status FROM runs").fetchone()["status"] == "in_progress"
    assert conn.execute("SELECT COUNT(*) AS n FROM leases").fetchone()["n"] == 1

    resumed = orch.resume(contract, FakeBroker(), FakeJudge(), FakeBrains())
    assert resumed.status == "complete", resumed.reason
    assert len(resumed.findings) == 1
    assert conn.execute("SELECT COUNT(*) AS n FROM leases").fetchone()["n"] == 0


def test_resume_tops_up_budget_and_finishes_deferred_units(tmp_path):
    conn, orch = _orch(tmp_path)
    contract = make_contract()
    first = orch.run(contract, _budget(hunter=1), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    assert first.status == "incomplete" and "deferred" in first.reason

    resumed = orch.resume(contract, FakeBroker(), FakeJudge(), FakeBrains(), add_hunter_calls=5)
    assert resumed.status == "complete", resumed.reason
    saved = json.loads(conn.execute("SELECT budget_json FROM runs").fetchone()["budget_json"])
    assert saved["used_hunter_calls"] == 2 and saved["max_hunter_calls"] == 6


def test_budget_is_saved_as_spent(tmp_path):
    conn, orch = _orch(tmp_path)
    orch.run(make_contract(), _budget(), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    saved = json.loads(conn.execute("SELECT budget_json FROM runs").fetchone()["budget_json"])
    assert saved["used_hunter_calls"] == 2 and saved["used_validator_calls"] == 1


def test_resume_refuses_complete_run(tmp_path):
    _, orch = _orch(tmp_path)
    contract = make_contract()
    orch.run(contract, _budget(), FakeBroker(), FakeJudge(), FakeBrains(), identities=IDENTITIES)
    again = orch.resume(contract, FakeBroker(), FakeJudge(), FakeBrains())
    assert again.status == "complete" and "nothing to resume" in again.reason


def test_resume_refuses_changed_contract(tmp_path):
    _, orch = _orch(tmp_path)
    orch.run(make_contract(), _budget(), FakeBroker(raise_error=ConnectionError("down")),
             FakeJudge(), FakeBrains(), identities=IDENTITIES)
    wider = make_contract(allowed_paths=["/*"])
    result = orch.resume(wider, FakeBroker(), FakeJudge(), FakeBrains())
    assert "changed scope is a new run" in result.reason


def test_resume_unknown_run(tmp_path):
    _, orch = _orch(tmp_path)
    result = orch.resume(make_contract(run_id="nope"), FakeBroker(), FakeJudge(), FakeBrains())
    assert result.status == "incomplete" and "no run" in result.reason


# -- 4. cross-run dedup ------------------------------------------------------------

def test_known_bug_is_still_reported_in_a_later_run(tmp_path):
    _, orch = _orch(tmp_path)
    run1 = orch.run(make_contract(run_id="run1"), _budget(), FakeBroker(), FakeJudge(), FakeBrains(),
                    identities=IDENTITIES)
    run2 = orch.run(make_contract(run_id="run2"), _budget(), FakeBroker(), FakeJudge(), FakeBrains(),
                    identities=IDENTITIES)

    assert len(run1.findings) == 1 and run1.findings[0]["previously_confirmed_in"] is None
    assert len(run2.findings) == 1, "a known bug must not vanish from a re-run"
    assert run2.findings[0]["fingerprint"] == run1.findings[0]["fingerprint"]
    assert run2.findings[0]["previously_confirmed_in"] == "run1"
