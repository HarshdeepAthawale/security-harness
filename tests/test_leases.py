import time

from kernel.db import connect_and_init
from kernel import leases


def _seed_run_and_unit(conn, run_id="run1", unit_id="unit1"):
    conn.execute(
        "INSERT INTO runs (run_id, target, contract_hash, budget_json, started_at) "
        "VALUES (?, 't', 'h', '{}', 'now')",
        (run_id,),
    )
    conn.execute(
        "INSERT INTO identities (id, run_id, role, label, cred_ref) VALUES ('id1', ?, 'attacker', 'user_B', 'ref1')",
        (run_id,),
    )
    conn.execute(
        "INSERT INTO objects (id, run_id, resource_type, endpoint, method) "
        "VALUES ('obj1', ?, 'order', '/api/orders/1', 'GET')",
        (run_id,),
    )
    conn.execute(
        "INSERT INTO coverage_units (id, run_id, object_id, action, identity_id) "
        "VALUES (?, ?, 'obj1', 'read', 'id1')",
        (unit_id, run_id),
    )


def test_claim_succeeds_when_unleased(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    _seed_run_and_unit(conn)
    assert leases.claim(conn, "unit1", "agentA") is True
    row = conn.execute("SELECT state, owner_agent FROM coverage_units WHERE id='unit1'").fetchone()
    assert row["state"] == "in_progress"
    assert row["owner_agent"] == "agentA"


def test_claim_fails_when_held_by_another_agent(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    _seed_run_and_unit(conn)
    leases.claim(conn, "unit1", "agentA", ttl_seconds=300)
    assert leases.claim(conn, "unit1", "agentB", ttl_seconds=300) is False


def test_release_frees_unit(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    _seed_run_and_unit(conn)
    leases.claim(conn, "unit1", "agentA")
    leases.release(conn, "unit1", "agentA", new_state="covered")
    row = conn.execute("SELECT state, owner_agent FROM coverage_units WHERE id='unit1'").fetchone()
    assert row["state"] == "covered"
    assert row["owner_agent"] is None


def test_reap_expired_recovers_unit(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    _seed_run_and_unit(conn)
    leases.claim(conn, "unit1", "agentA", ttl_seconds=-1)  # already expired
    recovered = leases.reap_expired(conn, "run1")
    assert recovered == ["unit1"]
    row = conn.execute("SELECT state, owner_agent FROM coverage_units WHERE id='unit1'").fetchone()
    assert row["state"] == "planned"
    assert row["owner_agent"] is None


def test_same_agent_can_reclaim_own_lease(tmp_path):
    conn = connect_and_init(tmp_path / "t.db")
    _seed_run_and_unit(conn)
    leases.claim(conn, "unit1", "agentA", ttl_seconds=300)
    assert leases.claim(conn, "unit1", "agentA", ttl_seconds=300) is True
