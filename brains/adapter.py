"""
Adapter: plugs the Brains modules (recon, hunt, report) into the kernel's
`Brains` protocol (kernel/orchestrator.py), without changing those modules.

    kernel                      this adapter                 brains modules
    surface_map(contract)  ->   recon + LLM hypotheses  ->   recon.build_recon_map, hunt.generate_hypotheses
    hunt(unit, contract)   ->   baseline + attack plans
    validate(trace)        ->   deterministic body check (no LLM)
    report(findings)       ->   findings -> JudgeResults ->  report.build_report

Design rules kept from the Brains package:
  - The LLM only proposes. It never decides whether a bug is real.
  - The LLM can only ADD context, never hide an endpoint: every endpoint
    with an object ID is tested, hypothesis or not. A hypothesis just
    supplies the rationale and the "expected if safe" text.
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import quote

from kernel.models import Contract, RequestPlan

from .hunt import generate_hypotheses
from .recon import _PLACEHOLDER, build_recon_map
from .report import build_report
from .schemas import Endpoint, Hypothesis, JudgeResult, TestPlan

LLMClient = Callable[[str, str], dict]

BASELINE = "baseline"   # owner reads their own object
ATTACK = "attack"       # another identity reads the owner's object


def _default_llm() -> LLMClient:
    # Imported lazily so the kernel and tests don't need `requests` or an API key.
    from .llm_client import call_llm
    return call_llm


def _fill(template: str, object_id: str) -> str:
    """/api/orders/{id} + 1001 -> /api/orders/1001. The id is URL-encoded so
    a weird id can't add path segments (the kernel's scope check would block
    that anyway)."""
    return _PLACEHOLDER.sub(lambda _m: quote(str(object_id), safe=""), template, count=1)


def plan_role(plan: dict) -> str:
    """'baseline' or 'attack' for a plan dict in a candidate trace."""
    return plan.get("expect", "").split(":", 1)[0]


class IdorBrains:
    """The IDOR/BOLA Brains, in the shape the kernel calls.

    raw_endpoints: endpoint records for recon, e.g. from an OpenAPI spec or a
        crawl: [{"method": "GET", "path": "/api/orders/{id}", "auth_required": True}, ...]
    object_ids: which object each identity owns, by resource type, e.g.
        {"orders": {"user_A": "1001", "user_B": "2002"}}. IDOR needs a real
        object that belongs to someone else, so the run must know these.
    llm_client: (prompt, user_content) -> dict. Defaults to OpenRouter.
        Pass use_llm=False to skip the model entirely.
    """

    def __init__(
        self,
        raw_endpoints: list[dict],
        object_ids: dict[str, dict[str, str]],
        llm_client: LLMClient | None = None,
        use_llm: bool = True,
    ) -> None:
        self.raw_endpoints = raw_endpoints
        self.object_ids = object_ids
        self.use_llm = use_llm
        self.llm_client = llm_client
        self.hypotheses: dict[tuple[str, str], Hypothesis] = {}
        self._template: dict[tuple[str, str], str] = {}   # (method, concrete path) -> template path

    # -- kernel protocol -------------------------------------------------------

    def surface_map(self, contract: Contract) -> list[dict]:
        recon = build_recon_map(self.raw_endpoints)
        if self.use_llm:
            llm = self.llm_client or _default_llm()
            for h in generate_hypotheses(recon, llm):
                self.hypotheses[(h.endpoint.method, h.endpoint.path)] = h

        allowed = set(contract.identities)
        objects = []
        for group in recon["resources"]:
            owners = self.object_ids.get(group["resource_type"], {})
            for ep in group["endpoints"]:
                if len(ep["path_params"]) != 1:
                    continue  # multi-id paths need per-param ids; not supported yet
                for owner, object_id in owners.items():
                    if owner not in allowed:
                        continue
                    concrete = _fill(ep["path"], object_id)
                    self._template[(ep["method"], concrete)] = ep["path"]
                    objects.append({
                        "resource_type": group["resource_type"],
                        "endpoint": concrete,
                        "method": ep["method"],
                        "owner_identity": owner,
                    })
        return objects

    def hunt(self, unit: dict, contract: Contract) -> list[RequestPlan]:
        owner, actor = unit.get("owner_identity"), unit["identity"]
        if owner is None or owner == actor:
            return []  # nothing to cross: the owner reading their own object
        hypothesis = self.hypotheses.get((unit["method"], self._template.get((unit["method"], unit["endpoint"]), "")))
        expect_safe = hypothesis.test_plan.expected_if_safe if hypothesis else "403 or 404"
        common = dict(unit_id=unit["unit_id"], method=unit["method"], path=unit["endpoint"], pack="idor-bola")
        return [
            RequestPlan(identity=owner, expect=f"{BASELINE}: 200 with {owner}'s data", **common),
            RequestPlan(identity=actor, expect=f"{ATTACK}: {expect_safe}", **common),
        ]

    def validate(self, trace: dict) -> str:
        """Independent second opinion, without an LLM: did the attacker get
        exactly the owner's response body?"""
        roles = [plan_role(p) for p in trace.get("plans", [])]
        if BASELINE not in roles or ATTACK not in roles:
            return "needs_validation"
        base, attack = roles.index(BASELINE), roles.index(ATTACK)
        status, digests = trace["status_codes"], trace["resp_digests"]
        if status[attack] in (401, 403, 404):
            return "rejected"
        if status[base] == status[attack] == 200 and digests[attack] and digests[attack] == digests[base]:
            return "confirmed"
        return "needs_validation"

    def report(self, findings: list[dict]) -> str:
        hypotheses, results = [], []
        for f in findings:
            plans = f["trace"].get("plans", [])
            attack = next((p for p in plans if plan_role(p) == ATTACK), plans[0] if plans else {})
            method, path = attack.get("method", ""), attack.get("path", "")
            template = self._template.get((method, path), path)
            known = self.hypotheses.get((method, template))
            hypotheses.append(Hypothesis(
                id=f["fingerprint"], type="IDOR",
                endpoint=Endpoint(method, path),
                rationale=known.rationale if known else "Object endpoint tested for cross-user access.",
                test_plan=known.test_plan if known else TestPlan("owner", "other user", [], "200 with owner's data", "403 or 404"),
                confidence=known.confidence if known else "medium",
            ))
            note = f"verdict={f['verdict']}"
            if f.get("severity"):
                note += f", severity={f['severity']}"
            if f.get("previously_confirmed_in"):
                note += f", previously confirmed in {f['previously_confirmed_in']}"
            results.append(JudgeResult(
                hypothesis_id=f["fingerprint"],
                reproduced=f["verdict"] == "confirmed",
                evidence={"ledger_ids": f["evidence_refs"], "cleanup_done": f["cleanup_done"]},
                notes=note,
            ))
        return build_report(hypotheses, results)
