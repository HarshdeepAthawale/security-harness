"""
Default hooks: the Constitution (PROJECT.md §4) as code.

`register_default_hooks(registry)` installs the rules every run gets:

  session_start         contract hash matches + target is in allowed origins
  pre_broker_request    method / path / identity must be inside the contract
  post_broker_request   rate limit or a broker-flagged signal stops the run
  session_end           every confirmed finding must have verified cleanup

Scope violations raise HookVeto (that one request is blocked, logged, never
retried). Stop conditions raise StopCondition (the whole run halts as
incomplete).
"""
from __future__ import annotations

from fnmatch import fnmatch
from urllib.parse import urlparse

from kernel.hooks import HookRegistry, HookVeto, StopCondition

# Broker-set flags that always stop a run, whatever the contract says.
ALWAYS_STOP_FLAGS = {"bot_challenge", "auth_ambiguity", "destructive_effect"}
RATE_LIMIT_STATUS = 429


def _host(value: str) -> str | None:
    if "://" not in value:
        value = "https://" + value
    return urlparse(value).hostname


def check_contract(ctx: dict) -> None:
    contract = ctx["contract"]
    if contract.compute_hash() != contract.contract_hash:
        raise StopCondition("contract hash mismatch: scope was changed after signing")
    if not (contract.allowed_origins and contract.allowed_paths and contract.allowed_methods):
        raise StopCondition("contract has an empty allowlist")
    target_host = _host(contract.target)
    if target_host not in {_host(o) for o in contract.allowed_origins}:
        raise StopCondition(f"target {contract.target!r} is not in allowed_origins")


def enforce_scope(ctx: dict) -> None:
    plan, contract = ctx["plan"], ctx["contract"]
    if plan.method.upper() not in {m.upper() for m in contract.allowed_methods}:
        raise HookVeto(f"method {plan.method} is out of scope")
    if not plan.path.startswith("/"):
        raise HookVeto(f"path {plan.path!r} must be relative to the target (start with '/')")
    if not any(fnmatch(plan.path, pattern) for pattern in contract.allowed_paths):
        raise HookVeto(f"path {plan.path} is out of scope")
    if plan.identity not in contract.identities:
        raise HookVeto(f"identity {plan.identity!r} is not permitted this run")


def check_stop_conditions(ctx: dict) -> None:
    entry = ctx["entry"]
    if entry.status_code == RATE_LIMIT_STATUS:
        raise StopCondition("rate limit signal (HTTP 429)")
    hit = ALWAYS_STOP_FLAGS.intersection(entry.flags)
    if hit:
        raise StopCondition(f"stop condition: {', '.join(sorted(hit))}")
    contract = ctx.get("contract")
    if contract is not None:
        extra = set(contract.stop_conditions).intersection(entry.flags)
        if extra:
            raise StopCondition(f"stop condition: {', '.join(sorted(extra))}")


def require_cleanup(ctx: dict) -> None:
    conn, run_id = ctx["conn"], ctx["run_id"]
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM findings WHERE run_id = ? AND verdict = 'confirmed' AND cleanup_done = 0",
        (run_id,),
    ).fetchone()
    if row["n"]:
        raise HookVeto(f"cleanup not verified for {row['n']} confirmed finding(s)")


def register_default_hooks(registry: HookRegistry) -> HookRegistry:
    registry.register("session_start", check_contract)
    registry.register("pre_broker_request", enforce_scope)
    registry.register("post_broker_request", check_stop_conditions)
    registry.register("session_end", require_cleanup)
    return registry
