"""Conservative deterministic verifier for the current IDOR/BOLA trace format.

The IDOR/BOLA adapter emits an owner baseline, a second identity's own-object
control, and that identity's cross-owner attack. The Judge checks the
permission differential and replays the exact read-only sequence through the
Kernel. Incomplete two-request traces remain ``needs_validation``.
"""
from __future__ import annotations

from dataclasses import fields

from kernel.models import LedgerEntry, RequestPlan


_SUCCESS = 200
_DENIED = {401, 403, 404}
_PLAN_FIELDS = {field.name for field in fields(RequestPlan)}


def _sequence(trace: dict, key: str, count: int) -> list:
    value = trace.get(key)
    if not isinstance(value, list) or len(value) != count:
        return []
    return value


def _roles(plans: list[dict]) -> dict[str, int] | None:
    found: dict[str, int] = {}
    for index, plan in enumerate(plans):
        if not isinstance(plan, dict):
            return None
        role = str(plan.get("expect", "")).split(":", 1)[0].strip().lower()
        if role in {"baseline", "control", "attack"}:
            if role in found:
                return None
            found[role] = index
    if "baseline" not in found or "attack" not in found:
        return None
    return found


def _is_pair(plans: list[dict], roles: dict[str, int]) -> bool:
    baseline, attack = plans[roles["baseline"]], plans[roles["attack"]]
    if baseline.get("identity") == attack.get("identity"):
        return False
    if baseline.get("method", "").upper() not in {"GET", "HEAD"}:
        return False
    if baseline.get("method", "").upper() != attack.get("method", "").upper():
        return False
    if baseline.get("path") != attack.get("path"):
        return False
    for key in ("headers", "query", "body"):
        if baseline.get(key) != attack.get(key):
            return False
    if baseline.get("pack") != "idor-bola" or attack.get("pack") != "idor-bola":
        return False
    return True


def _same_path_shape(left: str, right: str) -> bool:
    left_parts, right_parts = left.split("/"), right.split("/")
    if len(left_parts) != len(right_parts):
        return False
    return sum(a != b for a, b in zip(left_parts, right_parts)) == 1


def _has_enforcing_control(plans: list[dict], roles: dict[str, int]) -> bool:
    if "control" not in roles:
        return False
    baseline = plans[roles["baseline"]]
    control = plans[roles["control"]]
    attack = plans[roles["attack"]]
    return (
        control.get("identity") == attack.get("identity")
        and control.get("identity") != baseline.get("identity")
        and control.get("method", "").upper() == baseline.get("method", "").upper()
        and control.get("method", "").upper() == attack.get("method", "").upper()
        and isinstance(control.get("path"), str)
        and isinstance(baseline.get("path"), str)
        and _same_path_shape(control["path"], baseline["path"])
        and control.get("headers", {}) == baseline.get("headers", {}) == attack.get("headers", {})
        and control.get("query", {}) == baseline.get("query", {}) == attack.get("query", {})
        and control.get("body") == baseline.get("body") == attack.get("body")
        and control.get("pack") == "idor-bola"
    )


class IdorJudge:
    """Kernel ``Judge`` protocol implementation for read-only IDOR/BOLA.

    ``evaluate`` is deliberately conservative: the owner and actor controls
    must both succeed with different bodies, while the cross-owner attack
    must reproduce the owner's body. Only read-only requests are supported.
    """

    def evaluate(self, candidate_trace: dict) -> str:
        if not isinstance(candidate_trace, dict) or candidate_trace.get("pack") != "idor-bola":
            return "rejected"

        plans = candidate_trace.get("plans")
        if not isinstance(plans, list) or not plans:
            return "rejected"
        count = len(plans)
        statuses = _sequence(candidate_trace, "status_codes", count)
        digests = _sequence(candidate_trace, "resp_digests", count)
        ledger_ids = _sequence(candidate_trace, "ledger_ids", count)
        hashes = _sequence(candidate_trace, "request_hashes", count)
        if not statuses or not digests or not ledger_ids or not hashes:
            return "rejected"
        if any(not isinstance(item, str) or not item for item in ledger_ids + hashes):
            return "rejected"
        roles = _roles(plans)
        if roles is None or not _is_pair(plans, roles):
            return "rejected"
        base_i, attack_i = roles["baseline"], roles["attack"]
        base_status, attack_status = statuses[base_i], statuses[attack_i]
        if base_status != _SUCCESS or attack_status in _DENIED:
            return "rejected"
        if attack_status != _SUCCESS:
            return "needs_validation"
        if not _has_enforcing_control(plans, roles):
            return "needs_validation"

        control_i = roles["control"]
        control_status = statuses[control_i]
        if control_status != _SUCCESS:
            return "needs_validation"
        if not isinstance(digests[base_i], str) or not digests[base_i]:
            return "needs_validation"
        if not isinstance(digests[control_i], str) or not digests[control_i]:
            return "needs_validation"
        if not isinstance(digests[attack_i], str) or not digests[attack_i]:
            return "needs_validation"
        if digests[base_i] == digests[control_i] or digests[base_i] != digests[attack_i]:
            return "rejected"

        baseline, control, attack = (plans[base_i], plans[control_i], plans[attack_i])
        decisions = [_permission_decision(candidate_trace, plan) for plan in (baseline, control, attack)]
        if any(decision is None for decision in decisions):
            return "needs_validation"
        if decisions != ["allow", "allow", "deny"]:
            return "rejected"

        # A signed contract policy proves the access is prohibited. A finding
        # can only be confirmed if the replay also uses fresh identity handles.
        if not _has_fresh_identity_map(candidate_trace, plans, roles):
            return "needs_validation"
        fresh_map = candidate_trace["fresh_identity_map"]
        fresh_plans = {
            role: {**plans[index], "identity": fresh_map[plans[index]["identity"]]}
            for role, index in roles.items()
        }
        fresh_decisions = [
            _permission_decision(candidate_trace, fresh_plans[role])
            for role in ("baseline", "control", "attack")
        ]
        if any(decision is None for decision in fresh_decisions):
            return "needs_validation"
        if fresh_decisions != ["allow", "allow", "deny"]:
            return "rejected"
        return "confirmed"

    def ground(self, candidate_trace: dict, run_id: str, replay) -> bool:
        """Replay the baseline/control/attack sequence through Kernel callback."""
        del run_id  # identity and run association are set by Kernel dispatch.
        if not isinstance(candidate_trace, dict) or candidate_trace.get("pack") != "idor-bola":
            return False
        plans = candidate_trace.get("plans")
        if not isinstance(plans, list):
            return False
        roles = _roles(plans)
        if roles is None or not _is_pair(plans, roles):
            return False

        has_control = _has_enforcing_control(plans, roles)
        replay_roles = ("baseline", "control", "attack") if has_control else ("baseline", "attack")
        fresh_map = candidate_trace.get("fresh_identity_map", {})
        has_fresh_map = has_control and _has_fresh_identity_map(candidate_trace, plans, roles)
        original_policy = (
            [_permission_decision(candidate_trace, plans[roles[role]])
             for role in ("baseline", "control", "attack")]
            if has_control else []
        )
        use_fresh = has_fresh_map and original_policy == ["allow", "allow", "deny"]
        if use_fresh:
            mapped_plans = {
                role: {**plans[index], "identity": fresh_map[plans[index]["identity"]]}
                for role, index in roles.items()
            }
            replay_policy = [
                _permission_decision(candidate_trace, mapped_plans[role])
                for role in ("baseline", "control", "attack")
            ]
            if any(decision is None for decision in replay_policy):
                use_fresh = False
            elif replay_policy != ["allow", "allow", "deny"]:
                return False

        replayed: list[LedgerEntry] = []
        try:
            # Replay only the minimal proof sequence; never replay arbitrary extra plans.
            for role in replay_roles:
                raw = plans[roles[role]]
                replay_plan = dict(raw)
                if use_fresh:
                    replay_plan["identity"] = fresh_map[raw["identity"]]
                plan = RequestPlan(**{key: value for key, value in replay_plan.items() if key in _PLAN_FIELDS})
                entry = replay(plan)
                if not isinstance(entry, LedgerEntry):
                    return False
                replayed.append(entry)
        except (TypeError, ValueError):
            return False

        baseline = replayed[0]
        attack = replayed[-1]
        reproduced = (
            baseline.status_code == _SUCCESS
            and attack.status_code == _SUCCESS
            and isinstance(baseline.resp_digest, str)
            and bool(baseline.resp_digest)
            and baseline.resp_digest == attack.resp_digest
        )
        if has_control:
            control = replayed[1]
            reproduced = reproduced and (
                control.status_code == _SUCCESS
                and isinstance(control.resp_digest, str)
                and bool(control.resp_digest)
                and baseline.resp_digest != control.resp_digest
            )
        if not reproduced:
            return False

        # These are safe read-only requests, so no state-changing cleanup is
        # needed. Claim only the two newly recorded replay exchanges.
        candidate_trace["cleanup_done"] = True
        candidate_trace["ledger_ids"] = [entry.id for entry in replayed]
        return True


def _permission_decision(trace: dict, plan: dict) -> str | None:
    """Return the unique operator-signed policy decision for a request."""
    rules = trace.get("permission_rules")
    if not isinstance(rules, list):
        return None
    matches = [
        rule for rule in rules
        if isinstance(rule, dict)
        and rule.get("identity") == plan.get("identity")
        and rule.get("method") == str(plan.get("method", "")).upper()
        and rule.get("path") == plan.get("path")
        and rule.get("decision") in {"allow", "deny"}
        and isinstance(rule.get("source"), str)
        and bool(rule["source"].strip())
    ]
    return matches[0]["decision"] if len(matches) == 1 else None


def _has_fresh_identity_map(trace: dict, plans: list[dict], roles: dict[str, int]) -> bool:
    mapping = trace.get("fresh_identity_map")
    if not isinstance(mapping, dict):
        return False
    original_ids = {plans[roles[role]].get("identity") for role in ("baseline", "control", "attack")}
    if not all(isinstance(identity, str) and identity for identity in original_ids):
        return False
    if not original_ids.issubset(mapping):
        return False
    fresh_ids = [mapping[identity] for identity in original_ids]
    return (
        all(isinstance(identity, str) and identity for identity in fresh_ids)
        and len(set(fresh_ids)) == len(fresh_ids)
        and not original_ids.intersection(fresh_ids)
    )
