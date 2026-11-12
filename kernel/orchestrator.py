"""
The Orchestrator — the kernel itself (PROJECT.md §6).

Single-writer coordinator. Owns state, hands out work, holds the scope
contract + budget, fires hooks, decides when a run is done. NEVER calls an
LLM. Broker / Judge / Brains are injected as plain protocols so this module
has zero dependency on how those three workstreams are implemented —
that's the whole point of freezing these contracts first.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Protocol

from kernel import leases
from kernel.hooks import HookRegistry, HookVeto
from kernel.models import Budget, Contract, LedgerEntry, RequestPlan, now_iso


# --------------------------------------------------------------------------
# Protocols other workstreams implement. The kernel only calls these methods
# — it never reaches into broker/judge/brains internals.
# --------------------------------------------------------------------------

class Broker(Protocol):
    def send(self, plan: RequestPlan, contract: Contract) -> LedgerEntry: ...
    def check_identity(self, contract: Contract) -> bool:
        """Target-identity readiness gate (PROJECT.md §7.1). True = this is
        the intended app, False = halt the run as incomplete."""
        ...


class Judge(Protocol):
    def ground(self, candidate_trace: dict, run_id: str) -> bool:
        """Re-execute the claimed sequence; True if it reproduces."""
        ...

    def evaluate(self, candidate_trace: dict) -> str:
        """Return 'confirmed' | 'needs_validation' | 'rejected'."""
        ...


class Brains(Protocol):
    def surface_map(self, contract: Contract) -> list[dict]:
        """Return discovered objects: [{resource_type, endpoint, method, owner_identity}, ...]"""
        ...

    def hunt(self, unit: dict, contract: Contract) -> list[RequestPlan]:
        ...

    def validate(self, candidate_trace: dict) -> str:
        ...

    def report(self, findings: list[dict]) -> str:
        ...


class RunIncomplete(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class Orchestrator:
    def __init__(self, conn: sqlite3.Connection, hooks: HookRegistry | None = None) -> None:
        self.conn = conn
        self.hooks = hooks or HookRegistry()

    # -- run lifecycle -----------------------------------------------------

    def start_run(self, contract: Contract, budget: Budget, profile: str = "") -> None:
        self.conn.execute(
            "INSERT INTO runs (run_id, target, contract_hash, profile, budget_json, status, started_at) "
            "VALUES (?, ?, ?, ?, ?, 'in_progress', ?)",
            (contract.run_id, contract.target, contract.contract_hash, profile,
             json.dumps(budget.__dict__), now_iso()),
        )
        self.hooks.fire("session_start", {"contract": contract, "conn": self.conn})

    def finish_run(self, run_id: str, status: str, reason: str | None = None) -> None:
        self.hooks.fire("session_end", {"run_id": run_id, "status": status, "conn": self.conn})
        self.conn.execute(
            "UPDATE runs SET status = ?, reason = ?, ended_at = ? WHERE run_id = ?",
            (status, reason, now_iso(), run_id),
        )

    # -- broker dispatch (fires the enforcement hooks) ----------------------

    def dispatch(self, plan: RequestPlan, contract: Contract, broker: Broker) -> LedgerEntry:
        """Send one request plan through the broker, with hook enforcement
        on both sides. This is the ONLY path a plan takes to the network."""
        self.hooks.fire("pre_broker_request", {"plan": plan, "contract": contract})
        entry = broker.send(plan, contract)
        self._write_ledger_entry(entry)
        self.hooks.fire("post_broker_request", {"entry": entry, "contract": contract})
        return entry

    def _write_ledger_entry(self, entry: LedgerEntry) -> None:
        self.conn.execute(
            "INSERT INTO ledger (id, run_id, request_hash, method, url, status_code, "
            "resp_digest, identity_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (entry.id, entry.run_id, entry.request_hash, entry.method, entry.url,
             entry.status_code, entry.resp_digest, entry.identity_id, entry.ts),
        )

    # -- candidate acceptance (the anti-hallucination gate) ------------------

    def accept_candidate(self, fingerprint: str, run_id: str, trace_json: str) -> bool:
        """pre_candidate_accept: a candidate whose claimed requests have no
        matching ledger row is rejected. Enforced here via a JOIN-style check
        before any hook even runs, then hooks get a chance to veto further."""
        trace = json.loads(trace_json)
        request_hashes = trace.get("request_hashes", [])
        if request_hashes:
            rows = self.conn.execute(
                f"SELECT request_hash FROM ledger WHERE run_id = ? AND request_hash IN "
                f"({','.join('?' * len(request_hashes))})",
                (run_id, *request_hashes),
            ).fetchall()
            matched = {r["request_hash"] for r in rows}
            if not set(request_hashes).issubset(matched):
                self.conn.execute(
                    "UPDATE candidates SET status = 'rejected', updated_at = ? WHERE fingerprint = ?",
                    (now_iso(), fingerprint),
                )
                return False

        try:
            self.hooks.fire("pre_candidate_accept", {"fingerprint": fingerprint, "run_id": run_id, "trace": trace})
        except HookVeto:
            self.conn.execute(
                "UPDATE candidates SET status = 'rejected', updated_at = ? WHERE fingerprint = ?",
                (now_iso(), fingerprint),
            )
            return False

        self.conn.execute(
            "UPDATE candidates SET status = 'grounded', updated_at = ? WHERE fingerprint = ?",
            (now_iso(), fingerprint),
        )
        return True

    # -- validator assignment (Hunter != Validator invariant) ----------------

    def assign_validator(self, candidate_identity: str, validator_identity: str) -> None:
        """pre_validate: refuse to let the hunting identity validate its own find."""
        if candidate_identity == validator_identity:
            raise HookVeto("validator identity must differ from the hunting identity")
        self.hooks.fire("pre_validate", {
            "candidate_identity": candidate_identity,
            "validator_identity": validator_identity,
        })

    # -- leases --------------------------------------------------------------

    def claim_unit(self, unit_id: str, agent_id: str) -> bool:
        return leases.claim(self.conn, unit_id, agent_id)

    def release_unit(self, unit_id: str, agent_id: str, new_state: str) -> None:
        leases.release(self.conn, unit_id, agent_id, new_state)

    def reap_expired_leases(self, run_id: str) -> list[str]:
        return leases.reap_expired(self.conn, run_id)
