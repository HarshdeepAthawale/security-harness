"""The Brains adapter driven by the real kernel, end to end.

A fake LLM (no network) and two fake apps: one with an IDOR bug, one that
enforces ownership. The kernel must confirm the bug in the first and find
nothing in the second.
"""
import pytest

from brains.adapter import ATTACK, BASELINE, IdorBrains, plan_role
from kernel.db import connect_and_init
from kernel.default_hooks import register_default_hooks
from kernel.hooks import HookRegistry
from kernel.models import Budget, LedgerEntry, RequestPlan
from kernel.orchestrator import Orchestrator
from tests.fakes import IDENTITIES, make_contract

RAW_ENDPOINTS = [
    {"method": "GET", "path": "/api/orders/{id}", "auth_required": True},
    {"method": "GET", "path": "/api/me", "auth_required": True},          # no object id: not an IDOR target
]


def fake_llm(prompt, user_content):
    return {"hypotheses": [{
        "id": "hyp-0001", "type": "IDOR",
        "endpoint": {"method": "GET", "path": "/api/orders/{id}", "path_params": ["id"], "auth_required": True},
        "rationale": "Order ids are sequential and user-specific.",
        "test_plan": {"actor_a": "user_A", "actor_b": "user_B", "steps": ["B reads A's order"],
                      "expected_if_vulnerable": "200 with A's order", "expected_if_safe": "403 or 404"},
        "confidence": "high", "status": "unverified",
    }]}


class FakeApp:
    """A broker over a fake order API. owners: path -> identity that owns it."""

    def __init__(self, owners, vulnerable):
        self.owners, self.vulnerable, self.sent = owners, vulnerable, []

    def send(self, plan: RequestPlan, contract) -> LedgerEntry:
        self.sent.append(plan)
        allowed = self.vulnerable or self.owners.get(plan.path) == plan.identity
        return LedgerEntry(
            run_id=contract.run_id, request_hash=f"h-{plan.plan_id}-{len(self.sent)}",
            method=plan.method, url=f"https://{contract.target}{plan.path}",
            status_code=200 if allowed else 403,
            resp_digest=f"body:{plan.path}" if allowed else None, identity_id=None,
        )

    def check_identity(self, contract):
        return True


class DiffJudge:
    """Minimal real-shaped judge: attacker got the owner's exact body."""

    @staticmethod
    def _diff(trace):
        roles = [plan_role(p) for p in trace["plans"]]
        b, a = roles.index(BASELINE), roles.index(ATTACK)
        s, d = trace["status_codes"], trace["resp_digests"]
        return s[a] == 200 and d[a] is not None and d[a] == d[b]

    def evaluate(self, trace):
        return "confirmed" if self._diff(trace) else "rejected"

    def ground(self, trace, run_id, replay):
        entries = [replay(RequestPlan(**p)) for p in trace["plans"]]
        trace["cleanup_done"] = True        # read-only GETs: nothing to undo
        trace["severity_hint"] = "high"
        return entries[1].status_code == 200 and entries[1].resp_digest == entries[0].resp_digest


def _run(tmp_path, *, vulnerable, object_ids):
    owners = {f"/api/orders/{oid}": who for who, oid in object_ids["orders"].items()}
    app = FakeApp(owners, vulnerable)
    brains = IdorBrains(RAW_ENDPOINTS, object_ids, llm_client=fake_llm)
    orch = Orchestrator(connect_and_init(tmp_path / "t.db"), register_default_hooks(HookRegistry()))
    result = orch.run(make_contract(), Budget(max_hunter_calls=50, max_validator_calls=10),
                      app, DiffJudge(), brains, identities=IDENTITIES)
    return result, app, brains


def test_vulnerable_app_is_confirmed_end_to_end(tmp_path):
    result, app, _ = _run(tmp_path, vulnerable=True, object_ids={"orders": {"user_A": "1001"}})

    assert result.status == "complete", result.reason
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["verdict"] == "confirmed" and finding["severity"] == "high"
    assert "Findings confirmed by judge" in result.report
    assert "GET /api/orders/1001" in result.report
    assert "Order ids are sequential" in result.report          # the LLM's rationale reaches the report
    # /api/me has no object id, so recon drops it and it is never requested
    assert all(p.path.startswith("/api/orders/") for p in app.sent)


def test_safe_app_reports_nothing(tmp_path):
    result, _, _ = _run(tmp_path, vulnerable=False, object_ids={"orders": {"user_A": "1001"}})
    assert result.status == "complete", result.reason
    assert result.findings == []
    assert "No judge-confirmed findings." in result.report


def test_both_directions_are_hunted(tmp_path):
    result, app, _ = _run(tmp_path, vulnerable=True,
                          object_ids={"orders": {"user_A": "1001", "user_B": "2002"}})
    attacks = {(p.identity, p.path) for p in app.sent if plan_role({"expect": p.expect}) == ATTACK}
    assert attacks == {("user_B", "/api/orders/1001"), ("user_A", "/api/orders/2002")}
    assert len(result.findings) == 2   # roles differ (victim/attacker), so two fingerprints


def test_owner_reading_own_object_is_not_an_attack():
    brains = IdorBrains(RAW_ENDPOINTS, {"orders": {"user_A": "1001"}}, use_llm=False)
    unit = {"unit_id": "u1", "method": "GET", "endpoint": "/api/orders/1001",
            "identity": "user_A", "owner_identity": "user_A"}
    assert brains.hunt(unit, make_contract()) == []


def test_llm_cannot_hide_an_endpoint(tmp_path):
    """No hypothesis from the model: the endpoint is still tested."""
    brains = IdorBrains(RAW_ENDPOINTS, {"orders": {"user_A": "1001"}},
                        llm_client=lambda p, u: {"status": "insufficient_data", "hypotheses": []})
    objects = brains.surface_map(make_contract())
    assert [o["endpoint"] for o in objects] == ["/api/orders/1001"]


def test_object_id_cannot_add_path_segments():
    brains = IdorBrains(RAW_ENDPOINTS, {"orders": {"user_A": "../admin"}}, use_llm=False)
    objects = brains.surface_map(make_contract())
    assert objects[0]["endpoint"] == "/api/orders/..%2Fadmin"


def test_identity_outside_contract_gets_no_objects():
    brains = IdorBrains(RAW_ENDPOINTS, {"orders": {"user_Z": "9"}}, use_llm=False)
    assert brains.surface_map(make_contract()) == []


@pytest.mark.parametrize("status, same_body, verdict", [
    (200, True, "confirmed"),
    (403, False, "rejected"),
    (200, False, "needs_validation"),
])
def test_validate_is_deterministic(status, same_body, verdict):
    trace = {
        "plans": [{"expect": "baseline: 200"}, {"expect": "attack: 403"}],
        "status_codes": [200, status],
        "resp_digests": ["body", "body" if same_body else "other"],
    }
    assert IdorBrains([], {}, use_llm=False).validate(trace) == verdict
