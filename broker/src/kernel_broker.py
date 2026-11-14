"""The kernel's `Broker` protocol, on top of the scope -> executor -> ledger pipeline.

    from broker.src.kernel_broker import KernelBroker
    from broker.src.scope import load_scope

    broker = KernelBroker(load_scope("scope.json"))          # + ledger=Ledger(...) for the signed log
    orchestrator.run(contract, budget, broker, judge, brains, identities=[...])

The kernel hands over ITS RequestPlan and gets a LedgerEntry back. The broker
validates the plan against its own scope file as a second, independent check
(the kernel's hooks run first), sends it, and records what happened.
"""
from __future__ import annotations

import re

from kernel.models import Contract, LedgerEntry, RequestPlan as KernelPlan

from .errors import BrokerError
from .executor import execute
from .plan import RequestPlan
from .scope import ScopeValidator, ValidatedRequest

_STATUS = re.compile(r"\b[1-5]\d\d\b")

# Only trusted when the response is already an error/challenge status.
_CHALLENGE_STATUSES = {403, 429, 503}
_CHALLENGE_MARKERS = ("captcha", "cf-challenge", "just a moment", "verify you are human", "attention required")


def expected_statuses(expect: str) -> str:
    """The kernel's free-text expectation ("attack: 403 or 404") as the broker's
    status list ("403/404"). `expect` is documentation for the judge, not a
    security input, so a plan with none falls back to "200"."""
    found = list(dict.fromkeys(_STATUS.findall(expect or "")))
    return "/".join(found) if found else "200"


def challenge_flags(result: dict) -> list[str]:
    """Signals the kernel treats as a reason to stop the run."""
    headers = {str(k).lower(): str(v).lower() for k, v in result.get("headers", {}).items()}
    if headers.get("cf-mitigated") == "challenge":
        return ["bot_challenge"]
    if result["status"] in _CHALLENGE_STATUSES:
        sample = result.get("sample", "").lower()
        if any(marker in sample for marker in _CHALLENGE_MARKERS):
            return ["bot_challenge"]
    return []


class KernelBroker:
    def __init__(self, validator: ScopeValidator, ledger=None, execute_fn=execute):
        self.validator = validator
        self.ledger = ledger                  # optional signed, hash-chained log
        self.execute_fn = execute_fn

    # -- kernel protocol -----------------------------------------------------

    def send(self, plan: KernelPlan, contract: Contract) -> LedgerEntry:
        if not plan.pack:
            raise BrokerError("invalid_plan")

        broker_plan = RequestPlan(
            identity=plan.identity,
            method=plan.method.upper(),
            path=plan.path,
            headers=dict(plan.headers),
            query=dict(plan.query),
            body=plan.body,
            pack=plan.pack,
            expect=expected_statuses(plan.expect),
        )
        request = self.validator.build(broker_plan)
        result = self._execute_and_record(request)

        return LedgerEntry(
            run_id=contract.run_id,
            request_hash=request.request_hash,
            method=request.method,
            url=request.url,
            status_code=result["status"],
            resp_digest=result["digest"],
            identity_id=None,                 # the kernel fills this in from its own identities table
            flags=challenge_flags(result),
        )

    def check_identity(self, contract: Contract) -> bool:
        """Readiness gate (PROJECT.md 7.1): is this the intended application?

        False if the scope file has no identity fingerprint (can't prove it)
        or the target doesn't match it. Network errors raise, so the run's
        reason says what went wrong instead of "wrong application"."""
        probe = self.validator.build_probe()
        if probe is None:
            return False

        policy = self.validator.policy
        result = self._execute_and_record(probe)
        return result["status"] == policy.identity_probe_status and policy.identity_probe_marker in result["sample"]

    # -- internals -----------------------------------------------------------

    def _execute_and_record(self, request: ValidatedRequest) -> dict:
        pending = None
        if self.ledger is not None:
            pending = self.ledger.append({
                "state": "pending", "request_hash": request.request_hash,
                "request": {"method": request.method, "path": request.path, "identity": request.identity,
                            "pack": request.pack, "replay_safe": request.replay_safe},
            })
        try:
            result = self.execute_fn(request)
        except Exception as exc:
            if pending is not None:
                self._record_failure(request, pending, exc)
            raise
        if self.ledger is not None:
            self.ledger.append({"state": "complete", "request_hash": request.request_hash,
                                "seq_pending": pending["seq"], "response": result})
        return result

    def _record_failure(self, request: ValidatedRequest, pending: dict, exc: Exception) -> None:
        from .errors import error_code
        try:
            self.ledger.append({"state": "failed", "request_hash": request.request_hash,
                                "seq_pending": pending["seq"], "error": error_code(exc)})
        except Exception:
            pass                              # the original error is the one worth raising
