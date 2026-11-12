import pytest

from kernel.db import connect_and_init
from kernel.default_hooks import check_contract, check_stop_conditions, enforce_scope, require_cleanup
from kernel.hooks import HookVeto, StopCondition
from kernel.models import LedgerEntry, RequestPlan
from tests.fakes import make_contract


def _plan(**kw):
    base = dict(unit_id="u1", identity="user_B", method="GET", path="/api/orders/1")
    base.update(kw)
    return RequestPlan(**base)


def _entry(status=200, flags=()):
    return LedgerEntry(run_id="run1", request_hash="h", method="GET", url="u",
                       status_code=status, resp_digest="d", identity_id=None, flags=list(flags))


def test_contract_ok():
    check_contract({"contract": make_contract()})


def test_contract_tampered_after_signing():
    contract = make_contract()
    contract.allowed_paths.append("/*")
    with pytest.raises(StopCondition, match="hash mismatch"):
        check_contract({"contract": contract})


def test_target_not_in_allowed_origins():
    with pytest.raises(StopCondition, match="not in allowed_origins"):
        check_contract({"contract": make_contract(target="evil.test")})


def test_scope_allows_in_scope_plan():
    enforce_scope({"plan": _plan(), "contract": make_contract()})


@pytest.mark.parametrize("plan_kw, msg", [
    ({"method": "DELETE"}, "method"),
    ({"path": "/admin/users"}, "path"),
    ({"path": "https://other.test/api/x"}, "relative"),
    ({"identity": "user_Z"}, "identity"),
])
def test_scope_blocks(plan_kw, msg):
    with pytest.raises(HookVeto, match=msg):
        enforce_scope({"plan": _plan(**plan_kw), "contract": make_contract()})


def test_rate_limit_stops_run():
    with pytest.raises(StopCondition, match="429"):
        check_stop_conditions({"entry": _entry(status=429), "contract": make_contract()})


def test_broker_flag_stops_run():
    with pytest.raises(StopCondition, match="bot_challenge"):
        check_stop_conditions({"entry": _entry(flags=["bot_challenge"]), "contract": make_contract()})


def test_normal_response_passes():
    check_stop_conditions({"entry": _entry(), "contract": make_contract()})


def test_cleanup_required_for_confirmed(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    conn.execute("INSERT INTO runs (run_id, target, contract_hash, budget_json, started_at) VALUES ('run1','t','h','{}','now')")
    conn.execute("INSERT INTO identities VALUES ('i1','run1','attacker','user_B','r')")
    conn.execute("INSERT INTO objects (id, run_id, resource_type, endpoint, method) VALUES ('o1','run1','order','/x','GET')")
    conn.execute("INSERT INTO coverage_units (id, run_id, object_id, action, identity_id) VALUES ('u1','run1','o1','read','i1')")
    conn.execute("INSERT INTO candidates (fingerprint, run_id, unit_id, title, trace_json, created_at, updated_at) "
                 "VALUES ('fp','run1','u1','t','{}','now','now')")
    conn.execute("INSERT INTO findings VALUES ('fp','run1','confirmed','high','[]',0)")
    with pytest.raises(HookVeto, match="cleanup"):
        require_cleanup({"conn": conn, "run_id": "run1"})
