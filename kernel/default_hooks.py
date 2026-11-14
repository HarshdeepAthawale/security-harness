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
from urllib.parse import unquote, urlparse

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

    if not isinstance(contract.permission_rules, list):
        raise StopCondition("permission_rules must be a list")
    rule_keys = {"identity", "method", "path", "decision", "source"}
    seen_rules = set()
    for index, rule in enumerate(contract.permission_rules):
        if not isinstance(rule, dict) or set(rule) != rule_keys:
            raise StopCondition(
                f"permission rule {index} must contain exactly {sorted(rule_keys)}"
            )
        identity, method, path = rule["identity"], rule["method"], rule["path"]
        decision, source = rule["decision"], rule["source"]
        if not all(isinstance(value, str) and value for value in (identity, method, path, decision, source)):
            raise StopCondition(f"permission rule {index} contains an empty or non-string value")
        if not source.strip():
            raise StopCondition(f"permission rule {index} source must not be whitespace")
        if identity not in contract.identities:
            raise StopCondition(f"permission rule {index} names an identity outside the contract")
        if method != method.upper() or method not in {m.upper() for m in contract.allowed_methods}:
            raise StopCondition(f"permission rule {index} names a method outside the contract")
        try:
            canonical = canonical_path(path)
        except HookVeto as veto:
            raise StopCondition(f"permission rule {index} has an unsafe path: {veto.reason}") from veto
        if canonical != path or any(token in path for token in "*?[") or not any(
            fnmatch(path, pattern) for pattern in contract.allowed_paths
        ):
            raise StopCondition(f"permission rule {index} path is not an exact in-scope path")
        if decision not in {"allow", "deny"}:
            raise StopCondition(f"permission rule {index} decision must be 'allow' or 'deny'")
        key = (identity, method, path)
        if key in seen_rules:
            raise StopCondition(f"duplicate permission rule for {identity} {method} {path}")
        seen_rules.add(key)

    fresh_map = contract.fresh_identity_map
    if not isinstance(fresh_map, dict):
        raise StopCondition("fresh_identity_map must be an object")
    if any(
        not isinstance(original, str) or not isinstance(fresh, str)
        or not original or not fresh or original == fresh
        or original not in contract.identities or fresh not in contract.identities
        for original, fresh in fresh_map.items()
    ):
        raise StopCondition("fresh_identity_map must map distinct permitted identity handles")
    if len(set(fresh_map.values())) != len(fresh_map) or set(fresh_map).intersection(fresh_map.values()):
        raise StopCondition("fresh_identity_map must use unique, non-chained fresh identity handles")
    conn = ctx.get("conn")
    if fresh_map and conn is not None:
        for original, fresh in fresh_map.items():
            rows = conn.execute(
                "SELECT label, cred_ref FROM identities WHERE run_id = ? AND label IN (?, ?)",
                (contract.run_id, original, fresh),
            ).fetchall()
            refs = {row["label"]: row["cred_ref"] for row in rows}
            if original not in refs or fresh not in refs:
                raise StopCondition("fresh_identity_map references identities not seeded for this run")
            if not refs[original] or not refs[fresh] or refs[original] == refs[fresh]:
                raise StopCondition("fresh replay identity must use a distinct credential reference")


MAX_DECODE_ROUNDS = 5


def canonical_path(path: str) -> str:
    """Decode a plan path the way a server might, and refuse anything that
    could resolve somewhere other than where it looks like it goes.

    Without this, "/api/../admin" or "/api/%2e%2e/admin" matches "/api/*"
    but the server serves /admin. Raises HookVeto on any such path.
    """
    raw = path.split("#", 1)[0].split("?", 1)[0]
    decoded = raw
    for _ in range(MAX_DECODE_ROUNDS):
        once_more = unquote(decoded)
        if once_more == decoded:
            break
        decoded = once_more
    else:
        raise HookVeto(f"path {path!r} is percent-encoded too many times")

    if not decoded.startswith("/"):
        raise HookVeto(f"path {path!r} must be relative to the target (start with '/')")
    if "\\" in decoded or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded):
        raise HookVeto(f"path {path!r} contains a backslash or control character")

    segments = decoded.split("/")[1:]
    for i, segment in enumerate(segments):
        name = segment.split(";", 1)[0]          # "..;" is ".." to Tomcat and friends
        if name in (".", ".."):
            raise HookVeto(f"path {path!r} contains a dot segment")
        if segment == "" and i != len(segments) - 1:
            raise HookVeto(f"path {path!r} contains an empty segment (//)")
    return decoded


def enforce_scope(ctx: dict) -> None:
    plan, contract = ctx["plan"], ctx["contract"]
    if plan.method.upper() not in {m.upper() for m in contract.allowed_methods}:
        raise HookVeto(f"method {plan.method} is out of scope")
    path = canonical_path(plan.path)
    if not any(fnmatch(path, pattern) for pattern in contract.allowed_paths):
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
    """Install the Constitution hooks. Idempotent: calling it twice on the
    same registry doesn't run each rule twice."""
    if getattr(registry, "_defaults_installed", False):
        return registry
    registry.register("session_start", check_contract)
    registry.register("pre_broker_request", enforce_scope)
    registry.register("post_broker_request", check_stop_conditions)
    registry.register("session_end", require_cleanup)
    registry._defaults_installed = True
    return registry
