from kernel.models import LedgerEntry
from judge import IdorJudge
from brains.adapter import IdorBrains
from kernel.db import connect_and_init
from kernel.default_hooks import register_default_hooks
from kernel.hooks import HookRegistry
from kernel.models import Budget, RequestPlan
from kernel.orchestrator import Orchestrator
from tests.fakes import make_contract


def _permission_rules(*, include_fresh=False):
    rules = [
        {"identity": "user_A", "method": "GET", "path": "/api/orders/1001", "decision": "allow", "source": "signed test policy"},
        {"identity": "user_B", "method": "GET", "path": "/api/orders/2002", "decision": "allow", "source": "signed test policy"},
        {"identity": "user_B", "method": "GET", "path": "/api/orders/1001", "decision": "deny", "source": "signed test policy"},
    ]
    if include_fresh:
        rules.extend([
            {"identity": "user_A_fresh", "method": "GET", "path": "/api/orders/1001", "decision": "allow", "source": "signed test policy"},
            {"identity": "user_B_fresh", "method": "GET", "path": "/api/orders/2002", "decision": "allow", "source": "signed test policy"},
            {"identity": "user_B_fresh", "method": "GET", "path": "/api/orders/1001", "decision": "deny", "source": "signed test policy"},
        ])
    return rules


def make_trace(*, attack_status=200, attack_digest="owner-body", include_control=True,
               with_policy=False, with_fresh_identities=False):
    plans = [
        {
            "unit_id": "unit-1", "identity": "user_A", "method": "GET",
            "path": "/api/orders/1001", "headers": {}, "query": {}, "body": None,
            "pack": "idor-bola", "expect": "baseline: own object", "plan_id": "plan-base",
        },
        {
            "unit_id": "unit-1", "identity": "user_B", "method": "GET",
            "path": "/api/orders/1001", "headers": {}, "query": {}, "body": None,
            "pack": "idor-bola", "expect": "attack: denied", "plan_id": "plan-attack",
        },
    ]
    statuses = [200, attack_status]
    digests = ["owner-body", attack_digest]
    if include_control:
        plans.append({
            "unit_id": "unit-1", "identity": "user_B", "method": "GET",
            "path": "/api/orders/2002", "headers": {}, "query": {}, "body": None,
            "pack": "idor-bola", "expect": "control: own object", "plan_id": "plan-control",
        })
        statuses.append(200)
        digests.append("actor-body")
    trace = {
        "pack": "idor-bola", "plans": plans,
        "status_codes": statuses, "resp_digests": digests,
        "request_hashes": [f"hash-{i}" for i in range(len(plans))],
        "ledger_ids": [f"ledger-{i}" for i in range(len(plans))],
    }
    if with_policy:
        trace["permission_rules"] = _permission_rules(include_fresh=with_fresh_identities)
    if with_fresh_identities:
        trace["fresh_identity_map"] = {"user_A": "user_A_fresh", "user_B": "user_B_fresh"}
    return trace


def test_reproducible_disclosure_stays_needs_validation_without_trusted_policy():
    assert IdorJudge().evaluate(make_trace()) == "needs_validation"


def test_signed_deny_policy_without_fresh_credentials_stays_needs_validation():
    assert IdorJudge().evaluate(make_trace(with_policy=True)) == "needs_validation"


def test_signed_policy_and_fresh_identity_map_confirm_candidate():
    trace = make_trace(with_policy=True, with_fresh_identities=True)
    assert IdorJudge().evaluate(trace) == "confirmed"


def test_missing_fresh_identity_policy_stays_unconfirmed_and_uses_original_replay():
    trace = make_trace(with_policy=True, with_fresh_identities=True)
    trace["permission_rules"] = _permission_rules(include_fresh=False)
    assert IdorJudge().evaluate(trace) == "needs_validation"
    replayed_identities = []

    def replay(plan):
        replayed_identities.append(plan.identity)
        digest = "actor-body" if plan.path.endswith("2002") else "owner-body"
        return LedgerEntry(
            run_id="run-1", request_hash="hash", method=plan.method,
            url=f"https://target.test{plan.path}", status_code=200,
            resp_digest=digest, identity_id=plan.identity,
        )

    assert IdorJudge().ground(trace, "run-1", replay)
    assert set(replayed_identities) == {"user_A", "user_B"}


def test_denied_attack_is_rejected():
    assert IdorJudge().evaluate(make_trace(attack_status=403, attack_digest=None)) == "rejected"


def test_missing_control_cannot_confirm():
    assert IdorJudge().evaluate(make_trace(include_control=False)) == "needs_validation"


def test_attack_must_match_owner_and_differ_from_control():
    assert IdorJudge().evaluate(make_trace(attack_digest="different-body")) == "rejected"
    trace = make_trace()
    trace["resp_digests"][2] = "owner-body"
    assert IdorJudge().evaluate(trace) == "rejected"


def test_ground_replays_minimal_triad_and_keeps_only_replay_evidence():
    trace = make_trace(with_policy=True, with_fresh_identities=True)
    replayed = []

    def replay(plan):
        replayed.append((plan.identity, plan.path))
        digest = "actor-body" if plan.path.endswith("2002") else "owner-body"
        return LedgerEntry(
            run_id="run-1", request_hash=f"hash-{len(replayed)}",
            method=plan.method, url=f"https://target.test{plan.path}",
            status_code=200, resp_digest=digest, identity_id=plan.identity,
            id=f"replay-{len(replayed)}",
        )

    assert IdorJudge().ground(trace, "run-1", replay)
    assert replayed == [
        ("user_A_fresh", "/api/orders/1001"),
        ("user_B_fresh", "/api/orders/2002"),
        ("user_B_fresh", "/api/orders/1001"),
    ]
    assert trace["cleanup_done"] is True
    assert trace["ledger_ids"] == ["replay-1", "replay-2", "replay-3"]


def test_ground_rejects_nonreproducing_attack():
    trace = make_trace()

    def replay(plan):
        if plan.path.endswith("2002"):
            digest = "actor-body"
        elif plan.identity == "user_B":
            digest = "different-owner-body"
        else:
            digest = "owner-body"
        return LedgerEntry(
            run_id="run-1", request_hash="hash", method=plan.method,
            url=f"https://target.test{plan.path}", status_code=200,
            resp_digest=digest, identity_id=plan.identity,
        )

    assert not IdorJudge().ground(trace, "run-1", replay)
    assert "cleanup_done" not in trace


def test_ground_can_preserve_reproducing_legacy_pair_as_unconfirmed_evidence():
    trace = make_trace(include_control=False)

    def replay(plan):
        return LedgerEntry(
            run_id="run-1", request_hash="hash", method=plan.method,
            url=f"https://target.test{plan.path}", status_code=200,
            resp_digest="owner-body", identity_id=plan.identity,
        )

    assert IdorJudge().ground(trace, "run-1", replay)
    assert len(trace["ledger_ids"]) == 2


def test_mutating_request_is_not_replayed():
    trace = make_trace()
    for plan in trace["plans"]:
        plan["method"] = "POST"
    called = False

    def replay(_plan):
        nonlocal called
        called = True
        raise AssertionError("mutating request must not be replayed")

    assert not IdorJudge().ground(trace, "run-1", replay)
    assert not called


def _integration_policy(*, include_fresh=True):
    decisions = [
        ("user_A", "/api/orders/1001", "allow"),
        ("user_B", "/api/orders/2002", "allow"),
        ("user_B", "/api/orders/1001", "deny"),
        ("user_A", "/api/orders/2002", "deny"),
    ]
    if include_fresh:
        decisions.extend([
            ("user_A_fresh", "/api/orders/1001", "allow"),
            ("user_B_fresh", "/api/orders/2002", "allow"),
            ("user_B_fresh", "/api/orders/1001", "deny"),
            ("user_A_fresh", "/api/orders/2002", "deny"),
        ])
    return [
        {"identity": identity, "method": "GET", "path": path,
         "decision": decision, "source": "operator-approved test policy"}
        for identity, path, decision in decisions
    ]


class _PolicyFakeApp:
    def __init__(self, vulnerable):
        self.vulnerable = vulnerable
        self.sent = []
        self.principal = {
            "user_A": "user_A", "user_A_fresh": "user_A",
            "user_B": "user_B", "user_B_fresh": "user_B",
        }
        self.owner = {"/api/orders/1001": "user_A", "/api/orders/2002": "user_B"}

    def check_identity(self, _contract):
        return True

    def send(self, plan: RequestPlan, contract):
        self.sent.append(plan)
        allowed = self.vulnerable or self.owner.get(plan.path) == self.principal[plan.identity]
        return LedgerEntry(
            run_id=contract.run_id, request_hash=f"{plan.plan_id}-{plan.identity}",
            method=plan.method, url=f"https://{contract.target}{plan.path}",
            status_code=200 if allowed else 403,
            resp_digest=f"body:{plan.path}" if allowed else None,
            identity_id=None,
        )


def _run_integrated(tmp_path, *, vulnerable, with_policy=True, with_fresh_map=True):
    labels = ["user_A", "user_B"]
    if with_fresh_map:
        labels.extend(["user_A_fresh", "user_B_fresh"])
    identities = [
        {"label": label, "role": "victim" if label.startswith("user_A") else "attacker",
         "cred_ref": f"test-vault:{label}"}
        for label in labels
    ]
    contract = make_contract(
        identities=labels,
        allowed_methods=["GET"],
        permission_rules=_integration_policy(include_fresh=with_fresh_map) if with_policy else [],
        fresh_identity_map=(
            {"user_A": "user_A_fresh", "user_B": "user_B_fresh"}
            if with_fresh_map else {}
        ),
    )
    brains = IdorBrains(
        [{"method": "GET", "path": "/api/orders/{id}", "auth_required": True}],
        {"orders": {"user_A": "1001", "user_B": "2002"}},
        use_llm=False,
    )
    app = _PolicyFakeApp(vulnerable)
    orchestrator = Orchestrator(
        connect_and_init(tmp_path / "run.db"),
        register_default_hooks(HookRegistry()),
    )
    return orchestrator.run(
        contract,
        Budget(max_hunter_calls=100, max_validator_calls=20, max_requests=200),
        app,
        IdorJudge(),
        brains,
        identities=identities,
    ), app


def test_real_judge_end_to_end_confirms_only_policy_denied_fresh_reproduction(tmp_path):
    result, app = _run_integrated(tmp_path, vulnerable=True)
    assert result.status == "complete", result.reason
    assert len(result.findings) == 2
    assert all(finding["verdict"] == "confirmed" for finding in result.findings)
    assert sum(plan.identity.endswith("_fresh") for plan in app.sent) == 6


def test_real_judge_end_to_end_rejects_safe_app(tmp_path):
    result, _app = _run_integrated(tmp_path, vulnerable=False)
    assert result.status == "complete", result.reason
    assert result.findings == []


def test_real_judge_needs_validation_without_operator_policy(tmp_path):
    result, _app = _run_integrated(tmp_path, vulnerable=True, with_policy=False)
    assert result.status == "complete", result.reason
    assert result.findings
    assert all(finding["verdict"] == "needs_validation" for finding in result.findings)
    assert all(finding["severity"] is None for finding in result.findings)


def test_real_judge_needs_validation_without_fresh_credentials(tmp_path):
    result, app = _run_integrated(tmp_path, vulnerable=True, with_fresh_map=False)
    assert result.status == "complete", result.reason
    assert result.findings
    assert all(finding["verdict"] == "needs_validation" for finding in result.findings)
    assert all(not plan.identity.endswith("_fresh") for plan in app.sent)
