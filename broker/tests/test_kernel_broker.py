import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from broker.src.errors import BrokerError
from broker.src.kernel_broker import (
    IdentityProbe,
    KernelBroker,
    challenge_flags,
    expected_statuses,
)
from kernel.models import Contract, RequestPlan

# Support running pytest with broker/tests as its test directory.
try:
    from test_service import build, ok, ORIGIN
except ImportError:
    from broker.tests.test_service import build, ok, ORIGIN


# ------------------------------------------------------------
# FIXTURES
# ------------------------------------------------------------

@pytest.fixture
def ledger(tmp_path):
    key = Ed25519PrivateKey.generate()

    key_path = tmp_path / "private.pem"
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    from broker.src.ledger import Ledger

    return Ledger(
        tmp_path / "ledger.jsonl",
        key_path,
    )


def make_contract(**overrides):
    fields = dict(
        run_id="run1",
        target="target.example.com",
        allowed_origins=[ORIGIN],
        allowed_paths=["/api/*"],
        allowed_methods=["GET", "POST"],
        identities=["user_A", "user_B", "anon"],
        stop_conditions=["bot_challenge"],
        contract_hash="",
    )

    fields.update(overrides)

    contract = Contract(**fields)
    contract.contract_hash = contract.compute_hash()

    return contract


def make_plan(**overrides):
    fields = dict(
        unit_id="unit-1",
        identity="user_A",
        method="GET",
        path="/api/orders/1",
        headers={},
        query={},
        body=None,
        pack="idor-bola",
        expect="403 or 404",
    )

    fields.update(overrides)

    return RequestPlan(**fields)


def make_broker(ledger, handler=None, **kwargs):
    created = {}

    if handler is None:
        handler = lambda request: ok()

    def service_factory():
        service, executor = build(
            ledger,
            handler=handler,
        )

        created["service"] = service
        created["executor"] = executor

        return service

    broker = KernelBroker(
        service_factory,
        **kwargs,
    )

    return broker, created


# ------------------------------------------------------------
# EXPECTED STATUS CONVERSION
# ------------------------------------------------------------

@pytest.mark.parametrize(
    "text, expected",
    [
        ("attack: 403 or 404", "403/404"),
        ("baseline: 200 with user_A's data", "200"),
        ("control: 200, then 200 again", "200"),
        ("", "200"),
        ("no codes here", "200"),
        ("statuses: 401, 403, 404", "401/403/404"),
    ],
)
def test_expected_statuses(text, expected):
    assert expected_statuses(text) == expected


def test_expected_statuses_non_string():
    assert expected_statuses(None) == "200"


# ------------------------------------------------------------
# CHALLENGE DETECTION
# ------------------------------------------------------------

@pytest.mark.parametrize(
    "result",
    [
        {
            "status": 403,
            "sample": "<title>Just a moment...</title>",
        },
        {
            "status": 503,
            "sample": "Please complete the CAPTCHA",
        },
        {
            "status": 200,
            "headers": [["cf-mitigated", "challenge"]],
        },
    ],
)
def test_detects_bot_challenge(result):
    assert challenge_flags(result) == ["bot_challenge"]


def test_does_not_flag_ordinary_captcha_mention():
    result = {
        "status": 200,
        "sample": "my captcha settings",
    }

    assert challenge_flags(result) == []


def test_does_not_flag_ordinary_forbidden_response():
    result = {
        "status": 403,
        "sample": "forbidden",
    }

    assert challenge_flags(result) == []


def test_challenge_detection_accepts_dictionary_headers():
    result = {
        "status": 200,
        "headers": {
            "CF-Mitigated": "challenge",
        },
    }

    assert challenge_flags(result) == ["bot_challenge"]


# ------------------------------------------------------------
# CONSTRUCTION
# ------------------------------------------------------------

def test_rejects_non_callable_factory():
    with pytest.raises(TypeError):
        KernelBroker(None)


def test_rejects_non_positive_timeout():
    with pytest.raises(ValueError):
        KernelBroker(
            lambda: None,
            operation_timeout=0,
        )


# ------------------------------------------------------------
# SUCCESSFUL REQUEST EXECUTION
# ------------------------------------------------------------

def test_send_returns_kernel_ledger_entry(ledger):
    broker, created = make_broker(ledger)

    try:
        entry = broker.send(
            make_plan(),
            make_contract(),
        )

        assert entry.run_id == "run1"
        assert entry.method == "GET"
        assert entry.url == ORIGIN + "/api/orders/1"
        assert entry.status_code == 200
        assert entry.request_hash
        assert entry.resp_digest
        assert entry.identity_id == "user_A"

    finally:
        broker.close()


def test_send_uses_broker_credentials(ledger):
    broker, created = make_broker(ledger)

    try:
        broker.send(
            make_plan(),
            make_contract(),
        )

        sent = created["executor"].sent

        assert len(sent) == 1

        authorization = sent[0].headers.get("authorization")

        assert authorization is not None
        assert authorization.startswith("Bearer ")

    finally:
        broker.close()


def test_send_preserves_query_parameters(ledger):
    broker, created = make_broker(ledger)

    try:
        broker.send(
            make_plan(
                query={"page": "2"},
            ),
            make_contract(),
        )

        request = created["executor"].sent[0]

        assert request.url.params["page"] == "2"

    finally:
        broker.close()


# ------------------------------------------------------------
# CONTRACT ENFORCEMENT
# ------------------------------------------------------------

def test_rejects_tampered_contract(ledger):
    broker, created = make_broker(ledger)

    contract = make_contract()
    contract.target = "attacker.example.com"

    try:
        with pytest.raises(BrokerError):
            broker.send(
                make_plan(),
                contract,
            )

        assert created["executor"].sent == []

    finally:
        broker.close()


def test_rejects_unauthorized_path(ledger):
    broker, created = make_broker(ledger)

    try:
        with pytest.raises(BrokerError):
            broker.send(
                make_plan(path="/admin/secrets"),
                make_contract(),
            )

        assert created["executor"].sent == []

    finally:
        broker.close()


def test_rejects_unauthorized_method(ledger):
    broker, created = make_broker(ledger)

    try:
        with pytest.raises(BrokerError):
            broker.send(
                make_plan(method="DELETE"),
                make_contract(),
            )

        assert created["executor"].sent == []

    finally:
        broker.close()


def test_rejects_unauthorized_identity(ledger):
    broker, created = make_broker(ledger)

    try:
        with pytest.raises(BrokerError):
            broker.send(
                make_plan(identity="administrator"),
                make_contract(),
            )

        assert created["executor"].sent == []

    finally:
        broker.close()


def test_rejects_wrong_contract_origin(ledger):
    broker, created = make_broker(ledger)

    try:
        contract = make_contract(
            allowed_origins=["https://other.example.com"],
        )

        with pytest.raises(BrokerError):
            broker.send(
                make_plan(),
                contract,
            )

        assert created["executor"].sent == []

    finally:
        broker.close()


# ------------------------------------------------------------
# RESPONSE MAPPING
# ------------------------------------------------------------

def test_maps_bot_challenge_to_ledger_flags(ledger):
    def handler(request):
        return ok(
            body=b"<title>Just a moment...</title>",
            status=403,
        )

    broker, created = make_broker(
        ledger,
        handler=handler,
    )

    try:
        entry = broker.send(
            make_plan(),
            make_contract(),
        )

        assert "bot_challenge" in entry.flags

    finally:
        broker.close()


# ------------------------------------------------------------
# IDENTITY VERIFICATION
# ------------------------------------------------------------

def test_identity_probe_requires_configuration(ledger):
    broker, created = make_broker(ledger)

    try:
        assert broker.check_identity(make_contract()) is False

        assert created["executor"].sent == []

    finally:
        broker.close()


def test_identity_probe_succeeds_with_valid_marker(ledger):
    def handler(request):
        return ok(
            body=b"order-test-app",
            status=200,
        )

    probe = IdentityProbe(
        identity="anon",
        path="/api/health",
        pack="idor-bola",
        marker="order-test-app",
        expected_status=200,
    )

    broker, created = make_broker(
        ledger,
        handler=handler,
        identity_probe=probe,
    )

    try:
        assert broker.check_identity(make_contract()) is True

        assert len(created["executor"].sent) == 1

        request = created["executor"].sent[0]

        assert "authorization" not in request.headers
        assert "cookie" not in request.headers

    finally:
        broker.close()


def test_identity_probe_fails_without_marker(ledger):
    def handler(request):
        return ok(body=b"unrelated application response")

    probe = IdentityProbe(
        identity="anon",
        path="/api/health",
        pack="idor-bola",
        marker="order-test-app",
    )

    broker, created = make_broker(
        ledger,
        handler=handler,
        identity_probe=probe,
    )

    try:
        assert broker.check_identity(make_contract()) is False

    finally:
        broker.close()


def test_identity_probe_does_not_run_for_unauthorized_identity(ledger):
    probe = IdentityProbe(
        identity="anon",
        path="/api/health",
        pack="idor-bola",
        marker="order-test-app",
    )

    broker, created = make_broker(
        ledger,
        identity_probe=probe,
    )

    try:
        contract = make_contract(
            identities=["user_A", "user_B"],
        )

        assert broker.check_identity(contract) is False
        assert created["executor"].sent == []

    finally:
        broker.close()


# ------------------------------------------------------------
# LIFECYCLE
# ------------------------------------------------------------

def test_close_is_idempotent(ledger):
    broker, created = make_broker(ledger)

    broker.close()
    broker.close()

    assert broker._closed is True


def test_send_after_close_is_rejected(ledger):
    broker, created = make_broker(ledger)

    broker.close()

    with pytest.raises(BrokerError):
        broker.send(
            make_plan(),
            make_contract(),
        )