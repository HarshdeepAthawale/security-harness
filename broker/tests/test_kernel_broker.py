"""KernelBroker: the kernel's Broker protocol on the broker pipeline."""
import pytest

from broker.src.errors import BrokerError
from broker.src.kernel_broker import KernelBroker, challenge_flags, expected_statuses
from broker.src.scope import ScopePolicy, ScopeValidator, ScopeViolation
from kernel.models import LedgerEntry, RequestPlan
from tests.fakes import make_contract
from tests.localserver import LocalServer, reply


@pytest.fixture(autouse=True)
def secrets(monkeypatch):
    monkeypatch.setenv("BROKER_SECRET_USER_A", "tok-A-1234567890")
    monkeypatch.setenv("BROKER_SECRET_USER_B", "tok-B-1234567890")


class MemoryLedger:
    """Stands in for the signed ledger, which needs `cryptography`."""

    def __init__(self):
        self.records = []

    def append(self, record):
        item = {**record, "seq": len(self.records) + 1}
        self.records.append(item)
        return item


def make_validator(server, **policy):
    base = dict(
        base_url=server.origin, allowed_methods=frozenset({"GET"}), allowed_path_prefixes=("/api",),
        allowed_packs=frozenset({"idor-bola"}), allowed_identities=frozenset({"user_A", "user_B"}),
        allowed_cidrs=("127.0.0.0/8",),
        identity_probe_path="/api/health", identity_probe_marker="order-test-app",
    )
    base.update(policy)
    return ScopeValidator(ScopePolicy(**base))


def app(handler):
    if handler.path == "/api/health":
        reply(handler, 200, {"app": "order-test-app"})
    else:
        reply(handler, 200, {"path": handler.path})


def kernel_plan(**kw):
    data = dict(unit_id="u1", identity="user_A", method="GET", path="/api/orders/1001",
                pack="idor-bola", expect="attack: 403 or 404")
    data.update(kw)
    return RequestPlan(**data)


# -- send -----------------------------------------------------------------------------

def test_send_returns_a_ledger_entry_the_kernel_will_accept():
    contract = make_contract(target="127.0.0.1")
    with LocalServer(app) as server:
        entry = KernelBroker(make_validator(server)).send(kernel_plan(), contract)

    assert isinstance(entry, LedgerEntry)
    assert entry.run_id == contract.run_id and entry.method == "GET"
    assert entry.url == f"{server.origin}/api/orders/1001"
    assert entry.status_code == 200 and len(entry.resp_digest) == 64
    assert entry.flags == []


def test_the_kernels_extra_fields_and_free_text_expect_are_handled():
    """unit_id / plan_id aren't broker fields, and 'attack: 403 or 404' isn't a status list."""
    with LocalServer(app) as server:
        KernelBroker(make_validator(server)).send(
            kernel_plan(expect="baseline: 200 with user_A's data"), make_contract(target="127.0.0.1"))


@pytest.mark.parametrize("text, expected", [
    ("attack: 403 or 404", "403/404"),
    ("baseline: 200 with user_A's data", "200"),
    ("control: 200, then 200 again", "200"),
    ("", "200"),
    ("no codes here", "200"),
])
def test_expected_statuses(text, expected):
    assert expected_statuses(text) == expected


def test_the_broker_checks_scope_itself_not_only_the_kernel():
    with LocalServer(app) as server:
        broker = KernelBroker(make_validator(server, allowed_path_prefixes=("/api/orders",)))
        with pytest.raises(ScopeViolation):
            broker.send(kernel_plan(path="/api/admin"), make_contract(target="127.0.0.1"))
        assert [r["path"] for r in server.log] == []


def test_an_identity_outside_the_scope_file_is_refused():
    with LocalServer(app) as server:
        with pytest.raises(ScopeViolation):
            KernelBroker(make_validator(server)).send(kernel_plan(identity="user_Z"), make_contract(target="127.0.0.1"))


def test_a_plan_without_a_pack_is_refused():
    with LocalServer(app) as server:
        with pytest.raises(BrokerError):
            KernelBroker(make_validator(server)).send(kernel_plan(pack=""), make_contract(target="127.0.0.1"))


def test_every_attempt_is_recorded_pending_then_complete():
    ledger = MemoryLedger()
    with LocalServer(app) as server:
        KernelBroker(make_validator(server), ledger=ledger).send(kernel_plan(), make_contract(target="127.0.0.1"))
    assert [r["state"] for r in ledger.records] == ["pending", "complete"]
    assert ledger.records[0]["request_hash"] == ledger.records[1]["request_hash"]
    assert "tok-A" not in str(ledger.records)


def test_a_failed_request_is_recorded_as_failed():
    ledger = MemoryLedger()

    def broken(request):
        raise BrokerError("upstream_timeout")

    with LocalServer(app) as server:
        broker = KernelBroker(make_validator(server), ledger=ledger, execute_fn=broken)
        with pytest.raises(BrokerError):
            broker.send(kernel_plan(), make_contract(target="127.0.0.1"))
    assert [r["state"] for r in ledger.records] == ["pending", "failed"]
    assert ledger.records[1]["error"] == "upstream_timeout"


# -- stop signals -------------------------------------------------------------------------

@pytest.mark.parametrize("result, expected", [
    ({"status": 403, "sample": "<title>Just a moment...</title>", "headers": {}}, ["bot_challenge"]),
    ({"status": 503, "sample": "Please complete the CAPTCHA", "headers": {}}, ["bot_challenge"]),
    ({"status": 200, "sample": "", "headers": {"cf-mitigated": "challenge"}}, ["bot_challenge"]),
    ({"status": 200, "sample": "my captcha settings", "headers": {}}, []),      # a normal page that mentions it
    ({"status": 403, "sample": "forbidden", "headers": {}}, []),                # an ordinary denial
])
def test_challenge_flags(result, expected):
    assert challenge_flags(result) == expected


def test_a_challenge_page_reaches_the_kernel_as_a_flag():
    with LocalServer(lambda h: reply(h, 403, b"Just a moment... checking your browser")) as server:
        entry = KernelBroker(make_validator(server)).send(kernel_plan(), make_contract(target="127.0.0.1"))
    assert entry.flags == ["bot_challenge"]


# -- readiness gate (PROJECT.md 7.1) ------------------------------------------------------------

def test_check_identity_passes_for_the_intended_app():
    with LocalServer(app) as server:
        assert KernelBroker(make_validator(server)).check_identity(make_contract(target="127.0.0.1")) is True
        assert server.header_values("Authorization") == []          # the probe carries no credential


def test_the_probe_path_need_not_be_in_the_allowed_prefixes_but_plans_still_must_be():
    with LocalServer(app) as server:
        broker = KernelBroker(make_validator(server, allowed_path_prefixes=("/api/orders",)))
        assert broker.check_identity(make_contract(target="127.0.0.1")) is True      # /api/health is outside the prefixes
        with pytest.raises(ScopeViolation):
            broker.send(kernel_plan(path="/api/health"), make_contract(target="127.0.0.1"))


def test_check_identity_fails_for_a_different_app_on_the_same_port():
    with LocalServer(lambda h: reply(h, 200, {"app": "something-else"})) as server:
        assert KernelBroker(make_validator(server)).check_identity(make_contract(target="127.0.0.1")) is False


def test_check_identity_fails_on_the_wrong_status():
    with LocalServer(lambda h: reply(h, 404, {"app": "order-test-app"})) as server:
        assert KernelBroker(make_validator(server)).check_identity(make_contract(target="127.0.0.1")) is False


def test_check_identity_fails_closed_when_no_fingerprint_is_configured():
    with LocalServer(app) as server:
        validator = make_validator(server, identity_probe_path=None, identity_probe_marker="")
        assert KernelBroker(validator).check_identity(make_contract(target="127.0.0.1")) is False
        assert server.log == []


def test_check_identity_surfaces_network_errors_instead_of_saying_wrong_app():
    with LocalServer(app) as server:
        broker = KernelBroker(make_validator(server))
    with pytest.raises(BrokerError):                                  # server is stopped
        broker.check_identity(make_contract(target="127.0.0.1"))
