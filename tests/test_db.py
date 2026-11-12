from kernel.db import connect_and_init


def test_schema_applies_cleanly(tmp_path):
    conn = connect_and_init(tmp_path / "test.db")
    tables = {
        r["name"]
        for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    expected = {
        "runs", "identities", "objects", "coverage_units", "candidates",
        "ledger", "findings", "leases", "threads", "thread_evidence",
    }
    assert expected.issubset(tables)


def test_schema_is_idempotent(tmp_path):
    conn = connect_and_init(tmp_path / "test.db")
    from kernel.db import init_db
    init_db(conn)  # re-apply, must not error (CREATE TABLE IF NOT EXISTS)
