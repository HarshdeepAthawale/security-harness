"""Fake Broker / Judge / Brains for testing the kernel without the real
workstreams. Also a reference for what each protocol has to do."""
from __future__ import annotations

from kernel.models import Contract, LedgerEntry, RequestPlan


def make_contract(run_id="run1", **overrides) -> Contract:
    fields = dict(
        run_id=run_id,
        target="target.test",
        allowed_origins=["https://target.test"],
        allowed_paths=["/api/*"],
        allowed_methods=["GET", "POST"],
        identities=["user_A", "user_B"],
        stop_conditions=["bot_challenge"],
        contract_hash="",
    )
    fields.update(overrides)
    contract = Contract(**fields)
    contract.contract_hash = contract.compute_hash()
    return contract


IDENTITIES = [
    {"label": "user_A", "role": "victim", "cred_ref": "vault:user_A"},
    {"label": "user_B", "role": "attacker", "cred_ref": "vault:user_B"},
]


class FakeBroker:
    """Answers 200 to everything unless told otherwise per path."""

    def __init__(self, identity_ok=True, status_for=None, flags_for=None, raise_error=None):
        self.identity_ok = identity_ok
        self.status_for = status_for or {}
        self.flags_for = flags_for or {}
        self.raise_error = raise_error      # e.g. ConnectionError("down"): simulate a network failure
        self.sent: list[RequestPlan] = []

    def send(self, plan: RequestPlan, contract: Contract) -> LedgerEntry:
        if self.raise_error is not None:
            raise self.raise_error
        self.sent.append(plan)
        n = len(self.sent)
        return LedgerEntry(
            run_id=contract.run_id,
            request_hash=f"hash-{plan.plan_id}-{n}",
            method=plan.method,
            url=f"https://{contract.target}{plan.path}",
            status_code=self.status_for.get(plan.path, 200),
            resp_digest=f"digest-{plan.identity}-{plan.path}",
            identity_id=None,
            flags=list(self.flags_for.get(plan.path, [])),
        )

    def check_identity(self, contract: Contract) -> bool:
        return self.identity_ok


class FakeBrains:
    def __init__(self, objects=None, validate_verdict="confirmed", plan_path=None, hunt_raises=None):
        self.objects = objects if objects is not None else [
            {"resource_type": "order", "endpoint": "/api/orders/1001", "method": "GET", "owner_identity": "user_A"},
        ]
        self.validate_verdict = validate_verdict
        self.plan_path = plan_path
        self.hunt_raises = hunt_raises      # raised on the first hunt() call only
        self.hunts = 0
        self.validated: list[dict] = []

    def surface_map(self, contract):
        return self.objects

    def hunt(self, unit, contract):
        self.hunts += 1
        if self.hunt_raises is not None and self.hunts == 1:
            raise self.hunt_raises
        return [RequestPlan(
            unit_id=unit["unit_id"], identity=unit["identity"], method=unit["method"],
            path=self.plan_path or unit["endpoint"], pack="idor-bola", expect="403/404",
        )]

    def validate(self, trace):
        self.validated.append(trace)
        return self.validate_verdict

    def report(self, findings):
        return f"{len(findings)} reportable finding(s)"


class FakeJudge:
    """IDOR logic: a hit is real when someone who isn't the owner got a 200."""

    def __init__(self, owner="user_A", reproduces=True, cleanup=True):
        self.owner = owner
        self.reproduces = reproduces
        self.cleanup = cleanup
        self.replayed = 0

    def evaluate(self, trace):
        plan = trace["plans"][0]
        if plan["identity"] != self.owner and trace["status_codes"][0] == 200:
            return "confirmed"
        return "rejected"

    def ground(self, trace, run_id, replay):
        plan = RequestPlan(**trace["plans"][0])
        entry = replay(plan)
        self.replayed += 1
        trace["cleanup_done"] = self.cleanup
        trace["severity_hint"] = "high"
        return self.reproduces and entry.status_code == 200
