"""The executor against a real local HTTP server: real sockets, real headers,
real timeouts. (This file used to be a skipped placeholder.)"""
import json
import time

import pytest

from broker.src import executor as executor_module
from broker.src import limits
from broker.src.dns_guard import DNSPolicyError
from broker.src.errors import BrokerError
from broker.src.executor import execute
from broker.src.plan import RequestPlan
from broker.src.scope import ScopePolicy, ScopeValidator, ValidatedRequest
from tests.localserver import LocalServer, reply

TOKEN = "tok-user-A-1234567890"


@pytest.fixture(autouse=True)
def secrets(monkeypatch):
    monkeypatch.setenv("BROKER_SECRET_USER_A", TOKEN)


def validator_for(server, **policy):
    base = dict(
        base_url=server.origin, allowed_methods=frozenset({"GET", "POST"}), allowed_path_prefixes=("/api",),
        allowed_packs=frozenset({"idor-bola"}), allowed_identities=frozenset({"user_A"}),
        allowed_cidrs=("127.0.0.0/8",),
    )
    base.update(policy)
    return ScopeValidator(ScopePolicy(**base))


def build(validator, path="/api/x", **plan):
    data = dict(identity="user_A", method="GET", path=path, pack="idor-bola", expect="200")
    data.update(plan)
    return validator.build(RequestPlan(**data))


def echo(handler):
    reply(handler, 200, {"ok": True})


# -- the basics -----------------------------------------------------------------------

def test_sends_the_credential_the_broker_owns_and_returns_a_digest():
    with LocalServer(echo) as server:
        result = execute(build(validator_for(server)))
    assert result["status"] == 200 and len(result["digest"]) == 64
    assert server.header_values("Authorization") == ["Bearer " + TOKEN]
    assert server.header_values("Host") == [f"127.0.0.1:{server.port}"]


def test_plan_headers_cannot_override_authorization():
    with LocalServer(echo) as server:
        with pytest.raises(Exception):
            build(validator_for(server), headers={"Authorization": "Bearer stolen"})


def test_query_and_json_body_are_sent():
    seen = {}

    def app(handler):
        length = int(handler.headers.get("Content-Length") or 0)
        seen["body"] = handler.rfile.read(length)
        seen["ctype"] = handler.headers.get("Content-Type")
        reply(handler, 200, {})

    with LocalServer(app) as server:
        execute(build(validator_for(server), method="POST", query={"q": "a b", "n": 3}, body={"k": 1}))
        assert server.log[0]["path"] == "/api/x?q=a+b&n=3"
    assert json.loads(seen["body"]) == {"k": 1} and seen["ctype"] == "application/json"


# -- the secrets bug ----------------------------------------------------------------------

def test_a_token_in_a_large_response_is_not_stored():
    secret = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyX0EifQ.sig-value-123"
    big = json.dumps({"access_token": secret, "items": ["x" * 60] * 200}).encode()
    with LocalServer(lambda h: reply(h, 200, big, {"Content-Type": "application/json"})) as server:
        result = execute(build(validator_for(server)))
    assert secret not in json.dumps(result)
    assert len(result["digest"]) == 64                       # the judge can still compare responses


def test_a_server_echoing_our_credential_back_does_not_leak_it():
    with LocalServer(lambda h: reply(h, 200, f"you sent {h.headers['Authorization']}".encode())) as server:
        result = execute(build(validator_for(server)))
    assert TOKEN not in json.dumps(result)


# -- the Host bug ---------------------------------------------------------------------------

def test_a_host_override_replaces_the_default_it_does_not_add_a_second():
    with LocalServer(echo) as server:
        validator = validator_for(server, allow_host_header_override=True)
        execute(build(validator, headers={"host": "vhost.example.com"}))
        assert server.header_values("Host") == ["vhost.example.com"]


def test_without_an_override_the_plan_cannot_set_host():
    with LocalServer(echo) as server:
        with pytest.raises(Exception):
            build(validator_for(server), headers={"Host": "evil.example.com"})


# -- containment ---------------------------------------------------------------------------------

def test_redirects_are_returned_not_followed():
    other = []

    with LocalServer(lambda h: (other.append(h.path), reply(h, 200, b"secret"))) as elsewhere:
        with LocalServer(lambda h: reply(h, 302, b"", {"Location": elsewhere.origin + "/api/stolen"})) as server:
            result = execute(build(validator_for(server)))
    assert result["status"] == 302
    assert other == []                                       # the redirect target was never contacted


def test_a_target_on_a_private_address_is_refused_unless_listed():
    with LocalServer(echo) as server:
        with pytest.raises(DNSPolicyError, match="dns_address_denied"):
            execute(build(validator_for(server, allowed_cidrs=())))
        assert server.log == []


def test_an_oversized_response_is_refused(monkeypatch):
    monkeypatch.setattr(limits, "MAX_RESPONSE_BYTES", 1000)
    with LocalServer(lambda h: reply(h, 200, b"x" * 5000)) as server:
        with pytest.raises(BrokerError) as caught:
            execute(build(validator_for(server)))
    assert caught.value.code == "response_too_large"


def test_a_slow_drip_response_hits_the_total_deadline(monkeypatch):
    """One byte every 0.3 s never trips a per-read timeout. The total deadline must."""
    monkeypatch.setattr(limits, "TOTAL_TIMEOUT_SECONDS", 1.0)
    monkeypatch.setattr(limits, "READ_TIMEOUT_SECONDS", 5.0)

    def drip(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "100")
        handler.end_headers()
        for _ in range(100):
            handler.wfile.write(b"x")
            handler.wfile.flush()
            time.sleep(0.3)

    with LocalServer(drip) as server:
        started = time.monotonic()
        with pytest.raises(BrokerError) as caught:
            execute(build(validator_for(server)))
        elapsed = time.monotonic() - started
    assert caught.value.code == "upstream_timeout"
    assert elapsed < 4, f"the 1 s deadline took {elapsed:.1f}s to fire"


def test_a_connection_cut_mid_body_is_not_a_complete_response():
    """http.client returns a half body without an error. The digest of half a
    body would look like a real response, so the executor must refuse it."""
    def cut(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "1000")
        handler.end_headers()
        handler.wfile.write(b"x" * 10)
        handler.wfile.flush()
        handler.connection.shutdown(2)

    with LocalServer(cut) as server:
        with pytest.raises(BrokerError) as caught:
            execute(build(validator_for(server)))
    assert caught.value.code == "upstream_truncated"


def test_a_dead_server_is_an_upstream_error_not_a_crash():
    with LocalServer(echo) as server:
        validator = validator_for(server)
        request = build(validator)
    with pytest.raises(BrokerError) as caught:               # the server is stopped now
        execute(request)
    assert caught.value.code in {"upstream_error", "upstream_timeout"}


# -- a plan can't skip the scope check ---------------------------------------------------------------

def test_a_validated_request_cannot_be_constructed_by_hand():
    with LocalServer(echo) as server:
        request = build(validator_for(server))
        with pytest.raises(TypeError):
            ValidatedRequest(method="GET", url="https://evil.example.com/", path="/", query={}, headers={},
                             body=None, identity="user_A", pack="x", replay_safe=True, request_hash="h",
                             target=request.target)


def test_the_executor_refuses_anything_but_a_validated_request():
    with pytest.raises(TypeError):
        execute({"method": "GET", "url": "http://127.0.0.1/"})


def test_a_tampered_request_is_refused():
    with LocalServer(echo) as server:
        request = build(validator_for(server))
        object.__setattr__(request, "url", request.url.replace("/api/x", "/api/y"))
        with pytest.raises(ValueError, match="request_tampered"):
            execute(request)
        assert server.log == []
