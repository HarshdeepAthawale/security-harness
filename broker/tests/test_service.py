import asyncio
import io
import json
import os

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from broker.src.credentials import Credential
from broker.src.dns_guard import DNSGuard, DNSGuardError, DNSResult
from broker.src.executor import ExecutionConfig, HTTPExecutor
from broker.src.ledger import Ledger, LedgerError
from broker.src.limits import MAX_PLAN_BYTES
from broker.src.scope import ScopePolicy
from broker.src.service import (
    BrokerService, ConfigError, _read_line, load_credentials, load_scope, main,
)

ORIGIN = "https://target.example.com"
TOKEN_A = "tok-A-0123456789abcdef"
SID_B = "sid-B-9876543210fedcba"
PUBLIC = "93.184.216.34"


# ------------------------------------------------------------------ helpers
class SlowStream(httpx.AsyncByteStream):
    def __init__(self, delay):
        self.delay = delay

    async def __aiter__(self):
        await asyncio.sleep(self.delay)
        yield b"late"


class MockExecutor(HTTPExecutor):
    def __init__(self, handler, config=None, address_policy=None):
        self.sent = []

        def recording(request):
            self.sent.append(request)
            return handler(request)

        self._mock = httpx.MockTransport(recording)
        super().__init__(config, address_policy)

    def _make_transport(self, dns_result):
        return self._mock


class FakeGuard(DNSGuard):
    def __init__(self, addresses=(PUBLIC,), error=None):
        super().__init__()
        self._addresses, self._error = addresses, error

    async def resolve(self, hostname):
        if self._error:
            raise self._error
        return DNSResult(hostname, tuple(self._addresses))


def ok(body=b'{"ok":true}', status=200, headers=None):
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))


def policy(base_url=ORIGIN, identities=("user_A", "user_B", "anon")):
    return ScopePolicy(
        base_url=base_url,
        allowed_methods=frozenset({"GET", "POST", "DELETE", "HEAD"}),
        allowed_path_prefixes=("/api",),
        allowed_packs=frozenset({"idor-bola"}),
        allowed_identities=frozenset(identities),
    )


def creds():
    return {
        "user_A": Credential.bearer(TOKEN_A, [ORIGIN]),
        "user_B": Credential.cookie({"sid": SID_B}, [ORIGIN]),
        "anon": Credential.anonymous(),
    }


@pytest.fixture
def ledger(tmp_path):
    key = Ed25519PrivateKey.generate()
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return Ledger(tmp_path / "ledger.jsonl", tmp_path / "k.pem")


def build(ledger, handler=lambda r: ok(), *, guard=None, executor=None, **cfg):
    executor = executor or MockExecutor(handler, ExecutionConfig(**cfg) if cfg else None)
    return BrokerService(policy(), creds(), ledger, executor=executor,
                         guard=guard or FakeGuard()), executor


def plan(**o):
    d = {"identity": "user_A", "method": "GET", "path": "/api/orders/1",
         "pack": "idor-bola", "expect": "200"}
    d.update(o)
    return json.dumps(d).encode()


def records(ledger):
    return [json.loads(l) for l in ledger.path.read_bytes().splitlines()]


def states(ledger):
    return [r["state"] for r in records(ledger)]


def ledger_text(ledger):
    return ledger.path.read_text() if ledger.path.exists() else ""


# ============================================================ happy path
async def test_success_writes_pending_then_complete(ledger):
    svc, ex = build(ledger)
    out = await svc.handle(plan())
    assert out["outcome"] == "response" and out["status"] == 200
    assert out["expectation"] == "met" and out["possibly_delivered"] is True
    assert states(ledger) == ["pending", "complete"]
    p, c = records(ledger)
    assert c["seq_pending"] == p["seq"] and c["request_hash"] == p["request_hash"]
    assert p["dns"] == {"hostname": "target.example.com", "addresses": [PUBLIC]}
    assert len(ex.sent) == 1 and str(ex.sent[0].url) == f"{ORIGIN}/api/orders/1"


async def test_bearer_cookie_and_anonymous_auth_applied(ledger):
    svc, ex = build(ledger)
    await svc.handle(plan(identity="user_A"))
    await svc.handle(plan(identity="user_B"))
    await svc.handle(plan(identity="anon"))
    a, b, anon = ex.sent
    assert a.headers["authorization"] == f"Bearer {TOKEN_A}"
    assert b.headers["cookie"] == f"sid={SID_B}"
    assert "authorization" not in anon.headers and "cookie" not in anon.headers


async def test_query_is_sent_encoded(ledger):
    svc, ex = build(ledger)
    await svc.handle(plan(query={"q": "a b&c", "n": 5}))
    assert ex.sent[0].url.params["q"] == "a b&c" and ex.sent[0].url.params["n"] == "5"


async def test_json_body_serialized_with_content_type(ledger):
    svc, ex = build(ledger)
    await svc.handle(plan(method="POST", body={"a": 1, "b": [2]}))
    assert ex.sent[0].content == b'{"a":1,"b":[2]}'
    assert ex.sent[0].headers["content-type"] == "application/json"


async def test_plan_content_type_is_respected(ledger):
    svc, ex = build(ledger)
    await svc.handle(plan(method="POST", body={"a": 1},
                          headers={"content-type": "application/vnd.api+json"}))
    assert ex.sent[0].headers["content-type"] == "application/vnd.api+json"


async def test_body_not_allowed_on_get_and_head(ledger):
    svc, ex = build(ledger)
    for m in ("GET", "HEAD"):
        out = await svc.handle(plan(method=m, body={"a": 1}))
        assert out["code"] == "body_not_allowed"
    assert ex.sent == []


async def test_redirect_is_not_followed(ledger):
    svc, ex = build(ledger, lambda r: ok(b"", 302, {"Location": "http://169.254.169.254/"}))
    out = await svc.handle(plan(expect="302"))
    assert out["status"] == 302 and out["expectation"] == "met" and len(ex.sent) == 1


async def test_request_hash_deterministic_and_discriminating(ledger):
    svc, _ = build(ledger)
    a1 = await svc.handle(plan())
    a2 = await svc.handle(plan())
    b = await svc.handle(plan(path="/api/orders/2"))
    assert a1["request_hash"] == a2["request_hash"] != b["request_hash"]


# ============================================================ expectations
async def test_expectation_met_and_unmet(ledger):
    svc, _ = build(ledger, lambda r: ok(b"no", 403))
    assert (await svc.handle(plan(expect="403/404")))["expectation"] == "met"
    assert (await svc.handle(plan(expect="200")))["expectation"] == "unmet"


async def test_network_error_is_inconclusive_and_recorded(ledger):
    def boom(req):
        raise httpx.ReadTimeout("slow")
    svc, _ = build(ledger, boom)
    out = await svc.handle(plan())
    assert out["outcome"] == "error" and out["error_code"] == "read_timeout"
    assert out["expectation"] == "inconclusive" and out["possibly_delivered"] is True
    assert records(ledger)[-1]["possibly_delivered"] is True


async def test_connect_failure_not_delivered(ledger):
    def refused(req):
        raise httpx.ConnectError("refused")
    svc, _ = build(ledger, refused)
    out = await svc.handle(plan())
    assert out["error_code"] == "connection_error" and out["possibly_delivered"] is False


# ============================================================ rejections
@pytest.mark.parametrize("override,code", [
    ({"method": "PUT"}, "scope_violation"),
    ({"path": "/admin"}, "scope_violation"),
    ({"pack": "other"}, "scope_violation"),
    ({"identity": "nobody"}, "scope_violation"),
    ({"headers": {"Authorization": "Bearer x"}}, "invalid_plan"),
    ({"headers": {"Host": "evil.example"}}, "invalid_plan"),
    ({"path": "/api/../admin"}, "invalid_plan"),
    ({"path": "/api/caf\u00e9"}, "invalid_plan"),
    ({"unknown": 1}, "invalid_plan"),
])
async def test_rejections_send_nothing_and_are_logged(ledger, override, code):
    svc, ex = build(ledger)
    out = await svc.handle(plan(**override))
    assert out["outcome"] == "rejected" and out["code"] == code
    assert ex.sent == []
    assert states(ledger) == ["rejected"] and records(ledger)[0]["code"] == code


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b'{"identity":',
                                 b"\xff\xfe", b"{" * 5000])
async def test_malformed_input_rejected(ledger, raw):
    svc, ex = build(ledger)
    assert (await svc.handle(raw))["code"] == "invalid_plan" and ex.sent == []


async def test_oversized_plan_rejected(ledger):
    svc, ex = build(ledger)
    out = await svc.handle(plan(query={"q": "x" * (MAX_PLAN_BYTES + 10)}))
    assert out["code"] == "invalid_plan" and ex.sent == []


async def test_error_responses_never_echo_input_or_exception_text(ledger):
    svc, ex = build(ledger)
    out = json.dumps(await svc.handle(plan(unknown="SENTINEL-INPUT-VALUE")))
    assert "SENTINEL" not in out and "extra" not in out.lower()
    assert "SENTINEL" not in ledger_text(ledger)       # nor in the ledger


async def test_dns_block_rejects_and_sends_nothing(ledger):
    svc, ex = build(ledger, guard=FakeGuard(error=DNSGuardError("Loopback not allowed")))
    out = await svc.handle(plan())
    assert out["code"] == "dns_blocked" and ex.sent == []
    assert states(ledger) == ["rejected"]


async def test_executor_address_policy_is_independent_of_the_guard(ledger):
    """Even if the service's guard misbehaves, the executor re-validates."""
    svc, ex = build(ledger, guard=FakeGuard(addresses=("127.0.0.1",)))
    out = await svc.handle(plan())
    assert out["outcome"] == "not_sent" and out["error_code"] == "executor_rejected"
    assert out["possibly_delivered"] is False and ex.sent == []
    assert states(ledger) == ["pending", "complete"]


async def test_unexpected_executor_exception_is_unknown_and_not_leaked(ledger):
    class Boom(MockExecutor):
        async def execute_request(self, request, dns_result):
            raise RuntimeError("internal secret detail")
    svc, _ = build(ledger, executor=Boom(lambda r: ok()))
    out = await svc.handle(plan())
    assert out["outcome"] == "internal_error" and out["possibly_delivered"] is True
    assert "internal secret detail" not in json.dumps(out)
    assert states(ledger) == ["pending", "complete"]


# ============================================================ ledger discipline
async def test_ledger_failure_before_send_fails_closed(ledger, monkeypatch):
    svc, ex = build(ledger)

    async def boom(record):
        raise LedgerError("ledger_write_failed")
    monkeypatch.setattr(ledger, "append_async", boom)
    out = await svc.handle(plan())
    assert out["code"] == "ledger_unavailable" and ex.sent == []


async def test_ledger_failure_after_send_is_reported_not_hidden(ledger, monkeypatch):
    svc, ex = build(ledger)
    real, calls = ledger.append_async, {"n": 0}

    async def flaky(record):
        calls["n"] += 1
        if calls["n"] == 2:
            raise LedgerError("ledger_write_failed")
        return await real(record)
    monkeypatch.setattr(ledger, "append_async", flaky)
    out = await svc.handle(plan())
    assert out["status"] == 200 and out["ledger"] == "complete_not_recorded"
    assert len(ex.sent) == 1 and states(ledger) == ["pending"]
    assert len(ledger.unfinished_pending()) == 1


async def test_cancellation_leaves_pending_as_unknown(ledger):
    svc, ex = build(ledger, lambda r: httpx.Response(200, stream=SlowStream(5)),
                    timeout_seconds=10)
    task = asyncio.create_task(svc.handle(plan()))
    await asyncio.sleep(0.2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert states(ledger) == ["pending"]
    assert len(ledger.unfinished_pending()) == 1


# ============================================================ secrets
async def test_secrets_never_reach_ledger_or_caller(ledger):
    echo = f'{{"you_sent": "{TOKEN_A}", "other": "{SID_B}", "ok": 1}}'.encode()
    svc, _ = build(ledger, lambda r: ok(echo))
    out = await svc.handle(plan(identity="user_B"))     # B's request echoes A's token
    blob = json.dumps(out) + ledger_text(ledger)
    assert TOKEN_A not in blob and SID_B not in blob


async def test_echo_in_html_and_headers_is_scrubbed(ledger):
    svc, _ = build(ledger, lambda r: ok(
        f"<p>{TOKEN_A}</p>".encode(), headers={"X-Debug": f"token {TOKEN_A}"}))
    out = await svc.handle(plan())
    assert TOKEN_A not in json.dumps(out) + ledger_text(ledger)


async def test_plan_secrets_in_body_and_query_are_redacted_in_ledger(ledger):
    svc, _ = build(ledger)
    await svc.handle(plan(method="POST", body={"password": "hunter2hunter2", "n": 1},
                          query={"api_key": "QUERYKEY-123456"}))
    text = ledger_text(ledger)
    assert "hunter2hunter2" not in text and "QUERYKEY-123456" not in text
    assert '"n":1' in text


async def test_pending_record_has_no_auth_header(ledger):
    svc, _ = build(ledger)
    await svc.handle(plan(headers={"X-Trace": "abc"}))
    req = records(ledger)[0]["request"]
    assert req["headers"] == [["X-Trace", "abc"]]


# ============================================================ serve loop
async def test_serve_handles_lines_blank_lines_and_oversized(ledger):
    svc, ex = build(ledger)
    stdin = io.BytesIO(plan() + b"\n\n" + b"x" * (MAX_PLAN_BYTES + 500) + b"\n"
                       + plan(path="/api/orders/2") + b"\n")
    stdout = io.BytesIO()
    await svc.serve(stdin, stdout)
    outs = [json.loads(l) for l in stdout.getvalue().splitlines()]
    assert [o["outcome"] for o in outs] == ["response", "rejected", "response"]
    assert outs[1]["code"] == "invalid_plan" and len(ex.sent) == 2


async def test_serve_final_line_without_newline(ledger):
    svc, _ = build(ledger)
    stdout = io.BytesIO()
    await svc.serve(io.BytesIO(plan()), stdout)
    assert json.loads(stdout.getvalue())["outcome"] == "response"


async def test_read_line_never_buffers_unbounded():
    s = io.BytesIO(b"x" * 1_000_000 + b"\nnext\n")
    assert _read_line(s, 100) == (b"", True)
    assert _read_line(s, 100) == (b"next", False)
    assert _read_line(s, 100) == (None, False)


async def test_read_line_boundaries():
    assert _read_line(io.BytesIO(b"a" * 100 + b"\n"), 100) == (b"a" * 100, False)
    assert _read_line(io.BytesIO(b"a" * 101 + b"\n"), 100) == (b"", True)
    assert _read_line(io.BytesIO(b"a" * 100 + b"\r\n"), 100) == (b"a" * 100, False)


# ============================================================ configuration
def write(path, obj, mode=0o600):
    path.write_text(json.dumps(obj)); os.chmod(path, mode); return path


GOOD_SCOPE = {"base_url": ORIGIN, "allowed_methods": ["GET"], "allowed_path_prefixes": ["/api"],
              "allowed_packs": ["idor-bola"], "allowed_identities": ["user_A"]}


async def test_load_scope_valid(tmp_path):
    p = load_scope(write(tmp_path / "s.json", GOOD_SCOPE))
    assert p.base_url == ORIGIN and p.allowed_identities == frozenset({"user_A"})


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("base_url"),
    lambda d: d.update(extra=1),
    lambda d: d.update(allowed_methods="GET"),
    lambda d: d.update(allowed_methods=[]),
    lambda d: d.update(allowed_packs=[1]),
    lambda d: d.update(base_url="https://x.example/with/path"),
])
async def test_load_scope_invalid(tmp_path, mutate):
    d = dict(GOOD_SCOPE); mutate(d)
    with pytest.raises(ConfigError):
        load_scope(write(tmp_path / "s.json", d))


async def test_load_scope_missing_or_garbage(tmp_path):
    with pytest.raises(ConfigError):
        load_scope(tmp_path / "nope.json")
    (tmp_path / "g.json").write_text("{not json")
    with pytest.raises(ConfigError):
        load_scope(tmp_path / "g.json")


CRED_FILE = {
    "user_A": {"type": "bearer", "token": TOKEN_A},
    "user_B": {"type": "cookie", "cookies": {"sid": SID_B}},
    "svc": {"type": "custom", "headers": {"X-API-Key": "key-0123456789"}},
    "anon": {"type": "anonymous"},
}


async def test_load_credentials_valid_defaults_to_scope_origin(tmp_path):
    c = load_credentials(write(tmp_path / "c.json", CRED_FILE), default_origin=ORIGIN)
    assert set(c) == {"user_A", "user_B", "svc", "anon"}
    assert c["user_A"].render() == {"Authorization": f"Bearer {TOKEN_A}"}
    assert c["user_A"].origins == frozenset({"https://target.example.com:443"})


async def test_credentials_with_loose_permissions_refused(tmp_path):
    p = write(tmp_path / "c.json", CRED_FILE, mode=0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        load_credentials(p, default_origin=ORIGIN)
    assert load_credentials(p, default_origin=ORIGIN, allow_loose_permissions=True)


@pytest.mark.parametrize("bad", [
    {"u": {"type": "bearer"}},
    {"u": {"type": "bearer", "token": "x y"}},
    {"u": {"type": "bearer", "token": "abc", "extra": 1}},
    {"u": {"type": "unknown"}},
    {"u": {"token": "abc"}},
    {"u": "string"},
    {},
])
async def test_load_credentials_invalid(tmp_path, bad):
    with pytest.raises(ConfigError):
        load_credentials(write(tmp_path / "c.json", bad), default_origin=ORIGIN)


async def test_config_errors_never_contain_secret_values(tmp_path):
    bad = {"u": {"type": "bearer", "token": "SECRET TOKEN WITH SPACES"}}
    with pytest.raises(ConfigError) as e:
        load_credentials(write(tmp_path / "c.json", bad), default_origin=ORIGIN)
    assert "SECRET TOKEN" not in str(e.value)


async def test_http_origin_requires_and_derives_insecure(tmp_path):
    c = load_credentials(write(tmp_path / "c.json", {"u": {"type": "bearer", "token": "abcd1234"}}),
                         default_origin="http://localhost:8080")
    assert c["u"].allow_insecure is True


async def test_identity_without_credentials_is_a_startup_error(ledger):
    with pytest.raises(ConfigError, match="no credentials"):
        BrokerService(policy(identities=("user_A", "ghost")), creds(), ledger,
                      guard=FakeGuard())


async def test_http_scope_enables_insecure_executor(ledger):
    pol = policy(base_url="http://localhost:8080", identities=("anon",))
    svc = BrokerService(pol, {"anon": Credential.anonymous()}, ledger, guard=FakeGuard())
    assert svc.executor.config.allow_insecure_http is True
    assert BrokerService(policy(), creds(), ledger, guard=FakeGuard()
                         ).executor.config.allow_insecure_http is False


def test_main_returns_2_on_config_error(tmp_path):
    rc = main(["--scope", str(tmp_path / "missing.json"),
               "--credentials", str(tmp_path / "c.json"),
               "--ledger", str(tmp_path / "l.jsonl"),
               "--signing-key", str(tmp_path / "k.pem")])
    assert rc == 2


async def test_invalid_scope_at_construction_is_config_error(ledger):
    bad = ScopePolicy(base_url="ftp://nope", allowed_methods=frozenset({"GET"}),
                      allowed_path_prefixes=("/",), allowed_packs=frozenset({"p"}),
                      allowed_identities=frozenset({"anon"}))
    with pytest.raises(ConfigError):
        BrokerService(bad, {"anon": Credential.anonymous()}, ledger, guard=FakeGuard())


async def test_sent_url_must_equal_the_scope_approved_url(ledger, monkeypatch):
    """Defense in depth: if scope ever approves a string the executor would
    re-encode, the service must refuse rather than send a different URL."""
    svc, ex = build(ledger)
    monkeypatch.setattr(svc.scope, "validate", lambda plan: f"{ORIGIN}/api/orders/a b")
    out = await svc.handle(plan())
    assert out["code"] == "build_error" and ex.sent == []
