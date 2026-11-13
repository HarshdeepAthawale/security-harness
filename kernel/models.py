"""
Contract #2: the REQUEST PLAN format.

This is the ONLY thing an agent (brains) ever hands to the kernel. It is a
plan, never a raw network call — the kernel forwards it to the broker, which
is the only thing that actually touches the target (PROJECT.md §7).

Rules baked into the shape itself:
  - `identity` is a HANDLE (points at a row in `identities`), never a real
    token/secret. The broker resolves it at send-time.
  - No field here can carry a literal credential. If you're tempted to add
    one, it's a broker-side concern, not a plan field.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass
class RequestPlan:
    """What an agent asks the broker to send. Never a raw request."""
    unit_id: str          # the coverage_unit this plan targets
    identity: str         # identity handle, e.g. "user_B" -> identities.id
    method: str           # "GET" | "POST" | ...
    path: str             # relative path on the target, e.g. "/api/orders/1001"
    headers: dict = field(default_factory=dict)   # NEVER an Authorization/cookie header
    query: dict = field(default_factory=dict)
    body: dict | None = None
    pack: str = ""        # which detector pack produced this, e.g. "idor-bola"
    expect: str = ""      # human-readable expectation, e.g. "403/404"
    plan_id: str = field(default_factory=lambda: new_id("plan"))

    def __post_init__(self) -> None:
        forbidden = {"authorization", "cookie", "x-api-key"}
        for h in self.headers:
            if h.lower() in forbidden:
                raise ValueError(
                    f"RequestPlan.headers may not carry a credential header ({h!r}). "
                    "Use `identity` — the broker injects the real secret."
                )


@dataclass
class LedgerEntry:
    """One real exchange the broker performed, as recorded (read-only to agents)."""
    run_id: str
    request_hash: str
    method: str
    url: str
    status_code: int | None
    resp_digest: str | None
    identity_id: str | None
    id: str = field(default_factory=lambda: new_id("ledg"))
    ts: str = field(default_factory=now_iso)
    # Signals the broker detected on the response, e.g. "bot_challenge",
    # "auth_ambiguity", "destructive_effect". Any of these stops the run.
    flags: list[str] = field(default_factory=list)


@dataclass
class Candidate:
    """A proposed finding, pre/post grounding."""
    run_id: str
    unit_id: str
    title: str
    trace_json: str            # serialized claimed request/response sequence
    fingerprint: str
    proposed_verdict: str | None = None
    status: str = "proposed"   # proposed|grounded|validated|confirmed|needs_validation|rejected
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)


@dataclass
class Budget:
    """Reserved before hunting starts — hunters can never eat validator reserve."""
    max_hunter_calls: int
    max_validator_calls: int
    used_hunter_calls: int = 0
    used_validator_calls: int = 0

    def reserve_validator(self, n: int) -> bool:
        if self.used_validator_calls + n > self.max_validator_calls:
            return False
        self.used_validator_calls += n
        return True

    def spend_hunter(self, n: int = 1) -> bool:
        if self.used_hunter_calls + n > self.max_hunter_calls:
            return False
        self.used_hunter_calls += n
        return True


@dataclass
class Contract:
    """The immutable scope contract for a run. A change = a new run."""
    run_id: str
    target: str
    allowed_origins: list[str]
    allowed_paths: list[str]       # glob patterns, e.g. "/api/*"
    allowed_methods: list[str]
    identities: list[str]          # identity labels permitted this run
    stop_conditions: list[str]     # e.g. "bot_challenge", "rate_limit"
    contract_hash: str

    def compute_hash(self) -> str:
        """Hash of every scope field. session_start refuses a contract whose
        stored contract_hash doesn't match (i.e. it was edited after signing)."""
        payload = json.dumps(
            {
                "target": self.target,
                "allowed_origins": sorted(self.allowed_origins),
                "allowed_paths": sorted(self.allowed_paths),
                "allowed_methods": sorted(m.upper() for m in self.allowed_methods),
                "identities": sorted(self.identities),
                "stop_conditions": sorted(self.stop_conditions),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()
