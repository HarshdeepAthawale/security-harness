"""The stdin/stdout service: every failure is a stable code, and anything that
may have reached the target leaves a record."""
import json

import pytest

from broker.src.errors import BrokerError, error_code
from broker.src.scope import ScopePolicy, ScopeValidator
from broker.src.service import handle

PLAN = {"identity": "user_A", "method": "GET", "path": "/api/orders/1", "pack": "idor-bola", "expect": "200"}


class MemoryLedger:
    def __init__(self, fail_on=None):
        self.records, self.fail_on = [], fail_on

    def append(self, record):
        if record["state"] == self.fail_on:
            raise RuntimeError("disk full")
        item = {**record, "seq": len(self.records) + 1}
        self.records.append(item)
        return item


@pytest.fixture
def validator():
    return ScopeValidator(ScopePolicy(
        base_url="https://target.example.com", allowed_methods=frozenset({"GET"}),
        allowed_path_prefixes=("/api",), allowed_packs=frozenset({"idor-bola"}),
        allowed_identities=frozenset({"user_A"})))


def ok(request):
    return {"status": 200, "digest": "d" * 64, "sample": "{}", "headers": {}}


def plan(**kw):
    return json.dumps({**PLAN, **kw}).encode()


def test_success_is_recorded_pending_then_complete(validator):
    ledger = MemoryLedger()
    out = handle(plan(), validator, ledger, execute_fn=ok)
    assert out["status"] == 200 and out["digest"] == "d" * 64
    assert [r["state"] for r in ledger.records] == ["pending", "complete"]


@pytest.mark.parametrize("raw, code", [
    (b"not json", "invalid_plan"),
    (b"[1, 2]", "invalid_plan"),
    (plan(path="/api/..;/admin"), "invalid_plan"),
    (plan(extra=1), "invalid_plan"),
    (plan(identity="user_Z"), "out_of_scope"),
    (plan(pack="xss"), "out_of_scope"),
    (plan(method="POST"), "out_of_scope"),
    (plan(path="/other/x"), "out_of_scope"),
])
def test_a_bad_plan_gets_a_specific_code_and_touches_nothing(validator, raw, code):
    ledger = MemoryLedger()
    sent = []
    out = handle(raw, validator, ledger, execute_fn=lambda r: sent.append(r))
    assert out == {"error": code}
    assert sent == [] and ledger.records == []


@pytest.mark.parametrize("raised, code", [
    (BrokerError("upstream_timeout"), "upstream_timeout"),
    (BrokerError("response_too_large"), "response_too_large"),
    (RuntimeError("something odd with https://secret.internal/token=abc"), "internal_error"),
])
def test_an_execution_failure_is_a_code_never_a_message_and_is_recorded(validator, raised, code):
    ledger = MemoryLedger()

    def boom(request):
        raise raised

    out = handle(plan(), validator, ledger, execute_fn=boom)
    assert out == {"error": code}
    assert "secret.internal" not in json.dumps(out)
    assert [r["state"] for r in ledger.records] == ["pending", "failed"]
    assert ledger.records[1]["error"] == code


def test_a_ledger_that_cannot_write_stops_the_request_before_it_is_sent(validator):
    sent = []
    out = handle(plan(), validator, MemoryLedger(fail_on="pending"), execute_fn=lambda r: sent.append(r))
    assert out == {"error": "internal_error"} and sent == []


def test_error_code_mapping():
    assert error_code(BrokerError("x")) == "x"
    assert error_code(KeyError("k")) == "internal_error"
