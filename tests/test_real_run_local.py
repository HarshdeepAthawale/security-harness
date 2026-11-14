"""The first run with no fakes in the pipeline: the real kernel, the real
broker (scope, DNS pinning, credentials, executor) over real sockets, the
juniors' judge, and Brains, against a local order app with and without an
IDOR bug. Only the target is a stand-in."""
import pytest

from brains.adapter import IdorBrains
from broker.src.kernel_broker import KernelBroker
from broker.src.scope import ScopePolicy, ScopeValidator
from judge.idor import IdorJudge
from kernel.db import connect_and_init
from kernel.models import Budget, Contract
from kernel.orchestrator import Orchestrator
from tests.localserver import LocalServer, reply

OWNERS = {"1001": "user_A", "2002": "user_B"}
TOKENS = {"tok-A-1": "user_A", "tok-A-2": "user_A", "tok-B-1": "user_B", "tok-B-2": "user_B"}

IDENTITIES = [
    {"label": "user_A", "role": "victim", "cred_ref": "vault:user_A"},
    {"label": "user_B", "role": "attacker", "cred_ref": "vault:user_B"},
    {"label": "user_A_fresh", "role": "victim", "cred_ref": "vault:user_A_fresh"},
    {"label": "user_B_fresh", "role": "attacker", "cred_ref": "vault:user_B_fresh"},
]

# What the app's owner says is allowed: exact identity/method/path, signed into the contract.
RULES = [
    ("user_A", "/api/orders/1001", "allow"), ("user_B", "/api/orders/2002", "allow"),
    ("user_B", "/api/orders/1001", "deny"), ("user_A", "/api/orders/2002", "deny"),
    ("user_A_fresh", "/api/orders/1001", "allow"), ("user_B_fresh", "/api/orders/2002", "allow"),
    ("user_B_fresh", "/api/orders/1001", "deny"), ("user_A_fresh", "/api/orders/2002", "deny"),
]


def order_app(vulnerable, health="order-test-app", challenge=False):
    def app(handler):
        if handler.path == "/api/health":
            return reply(handler, 200, {"app": health})
        if challenge:
            return reply(handler, 403, b"Just a moment... verifying you are human")
        token = (handler.headers.get("Authorization") or "").removeprefix("Bearer ")
        user = TOKENS.get(token)
        order_id = handler.path.rsplit("/", 1)[-1]
        if user is None:
            return reply(handler, 401, {"error": "unauthenticated"})
        if order_id not in OWNERS:
            return reply(handler, 404, {"error": "no such order"})
        if vulnerable or OWNERS[order_id] == user:
            return reply(handler, 200, {"id": order_id, "owner": OWNERS[order_id], "total": 10 * int(order_id[0])})
        return reply(handler, 403, {"error": "forbidden"})
    return app


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    monkeypatch.setenv("BROKER_SECRET_USER_A", "tok-A-1")
    monkeypatch.setenv("BROKER_SECRET_USER_A_FRESH", "tok-A-2")
    monkeypatch.setenv("BROKER_SECRET_USER_B", "tok-B-1")
    monkeypatch.setenv("BROKER_SECRET_USER_B_FRESH", "tok-B-2")


def run(tmp_path, server, *, budget=None):
    contract = Contract(
        run_id="local1", target="127.0.0.1", allowed_origins=[server.origin], allowed_paths=["/api/*"],
        allowed_methods=["GET"], identities=[i["label"] for i in IDENTITIES], stop_conditions=[], contract_hash="",
        permission_rules=[{"identity": i, "method": "GET", "path": p, "decision": d, "source": "app owner's access policy"}
                          for i, p, d in RULES],
        fresh_identity_map={"user_A": "user_A_fresh", "user_B": "user_B_fresh"},
    )
    contract.contract_hash = contract.compute_hash()

    validator = ScopeValidator(ScopePolicy(
        base_url=server.origin, allowed_methods=frozenset({"GET"}), allowed_path_prefixes=("/api",),
        allowed_packs=frozenset({"idor-bola"}), allowed_identities=frozenset(i["label"] for i in IDENTITIES),
        allowed_cidrs=("127.0.0.0/8",), identity_probe_path="/api/health", identity_probe_marker="order-test-app"))

    brains = IdorBrains([{"method": "GET", "path": "/api/orders/{id}", "auth_required": True}],
                        {"orders": {"user_A": "1001", "user_B": "2002"}}, use_llm=False)
    conn = connect_and_init(tmp_path / "run.db")
    result = Orchestrator(conn).run(
        contract, budget or Budget(max_hunter_calls=50, max_validator_calls=10, max_requests=100),
        KernelBroker(validator), IdorJudge(), brains, identities=IDENTITIES)
    return conn, result


def test_the_idor_is_found_and_proved_end_to_end(tmp_path):
    with LocalServer(order_app(vulnerable=True)) as server:
        conn, result = run(tmp_path, server)

    assert result.status == "complete", result.reason
    assert sorted(f["verdict"] for f in result.findings) == ["confirmed", "confirmed"]     # B reads A's, A reads B's
    assert "Findings confirmed by judge" in result.report
    assert "GET /api/orders/1001" in result.report and "GET /api/orders/2002" in result.report

    # every confirmed finding is backed by real, recorded exchanges
    for finding in result.findings:
        for ledger_id in finding["evidence_refs"]:
            row = conn.execute("SELECT status_code, run_id FROM ledger WHERE id = ?", (ledger_id,)).fetchone()
            assert row is not None and row["status_code"] == 200 and row["run_id"] == "local1"
    # and the replay used the FRESH credentials, not the ones from the hunt
    fresh_used = {r["identity_id"] for r in conn.execute(
        "SELECT l.identity_id FROM ledger l JOIN identities i ON i.id = l.identity_id WHERE i.label LIKE '%fresh'")}
    assert fresh_used


def test_a_correct_app_produces_no_findings(tmp_path):
    with LocalServer(order_app(vulnerable=False)) as server:
        conn, result = run(tmp_path, server)
    assert result.status == "complete", result.reason
    assert result.findings == []
    assert "No judge-confirmed findings." in result.report
    # it did test: the attacks were really sent, and really denied
    assert conn.execute("SELECT COUNT(*) AS n FROM ledger WHERE status_code = 403").fetchone()["n"] >= 2


def test_the_wrong_app_on_the_port_stops_the_run_before_any_test_request(tmp_path):
    with LocalServer(order_app(vulnerable=True, health="some-other-service")) as server:
        conn, result = run(tmp_path, server)
        sent = [r["path"] for r in server.log]
    assert result.status == "incomplete" and "not the intended application" in result.reason
    assert sent == ["/api/health"]                           # only the readiness probe was sent


def test_a_bot_challenge_stops_the_run(tmp_path):
    with LocalServer(order_app(vulnerable=True, challenge=True)) as server:
        conn, result = run(tmp_path, server)
    assert result.status == "incomplete" and "bot_challenge" in result.reason


def test_the_request_budget_really_limits_traffic(tmp_path):
    with LocalServer(order_app(vulnerable=True)) as server:
        conn, result = run(tmp_path, server, budget=Budget(max_hunter_calls=50, max_validator_calls=10, max_requests=3))
        orders = [r for r in server.log if r["path"] != "/api/health"]
    assert result.status == "incomplete" and "request budget exhausted" in result.reason
    assert len(orders) == 3


def test_no_credential_is_stored_anywhere_in_the_run_database(tmp_path):
    with LocalServer(order_app(vulnerable=True)) as server:
        conn, result = run(tmp_path, server)
    dump = " ".join(str(tuple(row)) for table in ("ledger", "dispatches", "candidates", "findings", "threads", "identities")
                    for row in conn.execute(f"SELECT * FROM {table}"))
    for token in TOKENS:
        assert token not in dump
