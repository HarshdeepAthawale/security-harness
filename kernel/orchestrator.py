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
from dataclasses import asdict, dataclass, field
from typing import Callable, Protocol

from kernel import findings, leases, state
from kernel.hooks import HookRegistry, HookVeto, StopCondition
from kernel.models import Budget, Contract, LedgerEntry, RequestPlan, new_id, now_iso


# --------------------------------------------------------------------------
# Protocols other workstreams implement. The kernel only calls these methods
# — it never reaches into broker/judge/brains internals.
# --------------------------------------------------------------------------

Replay = Callable[[RequestPlan], LedgerEntry]


class Broker(Protocol):
    def send(self, plan: RequestPlan, contract: Contract) -> LedgerEntry: ...

    def check_identity(self, contract: Contract) -> bool:
        """Target-identity readiness gate (PROJECT.md §7.1). True = this is
        the intended app, False = halt the run as incomplete."""
        ...


class Judge(Protocol):
    def evaluate(self, candidate_trace: dict) -> str:
        """Look at a hunt's recorded exchanges. Return 'confirmed' |
        'needs_validation' | 'rejected' (rejected = no real differential)."""
        ...

    def ground(self, candidate_trace: dict, run_id: str, replay: Replay) -> bool:
        """Re-execute the claimed sequence and return True if it reproduces.
        Replays MUST go through `replay(plan)` — it routes through the kernel
        and broker, so replays are scope-checked and logged like any request.
        The judge may write these keys into candidate_trace and the kernel
        saves them: cleanup_done (bool), severity_hint (str), and ledger_ids
        (the minimized reproducing exchanges)."""
        ...


class Brains(Protocol):
    def surface_map(self, contract: Contract) -> list[dict]:
        """Return discovered objects:
        [{resource_type, endpoint, method, owner_identity?, actions?}, ...]"""
        ...

    def hunt(self, unit: dict, contract: Contract) -> list[RequestPlan]: ...

    def validate(self, candidate_trace: dict) -> str:
        """Independent second opinion: 'confirmed' | 'needs_validation' | 'rejected'."""
        ...

    def report(self, findings: list[dict]) -> str: ...


class RunIncomplete(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass
class RunResult:
    run_id: str
    status: str                      # complete | incomplete
    reason: str | None = None
    report: str | None = None
    findings: list[dict] = field(default_factory=list)


_METHOD_ACTION = {"GET": "read", "HEAD": "read", "POST": "create", "PUT": "update",
                  "PATCH": "update", "DELETE": "delete"}


class Orchestrator:
    def __init__(self, conn: sqlite3.Connection, hooks: HookRegistry | None = None) -> None:
        self.conn = conn
        self.hooks = hooks or HookRegistry()

    # -- run lifecycle -----------------------------------------------------

    def start_run(
        self,
        contract: Contract,
        budget: Budget,
        profile: str = "",
        identities: list[dict] | None = None,
    ) -> None:
        """Write the run row, seed identities, fire session_start.
        identities: [{label, role, cred_ref}] — cred_ref is a handle the broker
        resolves, never the secret itself."""
        self.conn.execute(
            "INSERT INTO runs (run_id, target, contract_hash, profile, budget_json, status, started_at) "
            "VALUES (?, ?, ?, ?, ?, 'in_progress', ?)",
            (contract.run_id, contract.target, contract.contract_hash, profile,
             json.dumps(budget.__dict__), now_iso()),
        )
        for ident in identities or []:
            self.seed_identity(contract.run_id, ident["label"], ident["role"], ident["cred_ref"])
        self.hooks.fire("session_start", {"contract": contract, "conn": self.conn})

    def finish_run(self, run_id: str, status: str, reason: str | None = None) -> tuple[str, str | None]:
        """Close the run. A session_end veto (e.g. cleanup not verified)
        downgrades it to incomplete instead of silently completing."""
        try:
            self.hooks.fire("session_end", {"run_id": run_id, "status": status, "conn": self.conn})
        except HookVeto as veto:
            status, reason = "incomplete", veto.reason
        self.conn.execute(
            "UPDATE runs SET status = ?, reason = ?, ended_at = ? WHERE run_id = ?",
            (status, reason, now_iso(), run_id),
        )
        return status, reason

    # -- seeding -----------------------------------------------------------

    def seed_identity(self, run_id: str, label: str, role: str, cred_ref: str) -> str:
        identity_id = new_id("idn")
        self.conn.execute(
            "INSERT INTO identities (id, run_id, role, label, cred_ref) VALUES (?, ?, ?, ?, ?)",
            (identity_id, run_id, role, label, cred_ref),
        )
        return identity_id

    def seed_from_recon(self, run_id: str, objects: list[dict], wave: int = 1) -> int:
        """Turn Surface Mapper output into objects + coverage_units.
        One coverage unit per (object, action, identity). Returns units created."""
        idents = self.conn.execute(
            "SELECT id, label FROM identities WHERE run_id = ?", (run_id,)
        ).fetchall()
        by_label = {r["label"]: r["id"] for r in idents}
        created = 0
        for obj in objects:
            method = obj["method"].upper()
            object_id = new_id("obj")
            self.conn.execute(
                "INSERT INTO objects (id, run_id, resource_type, owner_identity, endpoint, method) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (object_id, run_id, obj["resource_type"], by_label.get(obj.get("owner_identity")),
                 obj["endpoint"], method),
            )
            actions = obj.get("actions") or [_METHOD_ACTION.get(method, method.lower())]
            for action in actions:
                for identity_id in by_label.values():
                    self.conn.execute(
                        "INSERT INTO coverage_units (id, run_id, object_id, action, identity_id, state, wave) "
                        "VALUES (?, ?, ?, ?, ?, 'planned', ?)",
                        (new_id("unit"), run_id, object_id, action, identity_id, wave),
                    )
                    created += 1
        return created

    def _unit_view(self, unit_id: str) -> dict:
        """What Brains sees for a unit: no ids it can't use, no secrets."""
        r = self.conn.execute(
            """
            SELECT c.id AS unit_id, c.action, c.wave, o.id AS object_id, o.resource_type, o.endpoint,
                   o.method, i.label AS identity, i.role AS identity_role, own.label AS owner_identity
            FROM coverage_units c
            JOIN objects o ON o.id = c.object_id
            JOIN identities i ON i.id = c.identity_id
            LEFT JOIN identities own ON own.id = o.owner_identity
            WHERE c.id = ?
            """,
            (unit_id,),
        ).fetchone()
        return dict(r)

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
        matching ledger row is rejected. Enforced here before any hook runs,
        then hooks get a chance to veto further."""
        trace = json.loads(trace_json)
        request_hashes = trace.get("request_hashes", [])
        if not request_hashes:
            findings.set_candidate_status(self.conn, fingerprint, "rejected")
            return False
        rows = self.conn.execute(
            f"SELECT request_hash FROM ledger WHERE run_id = ? AND request_hash IN "
            f"({','.join('?' * len(request_hashes))})",
            (run_id, *request_hashes),
        ).fetchall()
        matched = {r["request_hash"] for r in rows}
        if not set(request_hashes).issubset(matched):
            findings.set_candidate_status(self.conn, fingerprint, "rejected")
            return False

        try:
            self.hooks.fire("pre_candidate_accept", {"fingerprint": fingerprint, "run_id": run_id, "trace": trace})
        except HookVeto:
            findings.set_candidate_status(self.conn, fingerprint, "rejected")
            return False

        findings.set_candidate_status(self.conn, fingerprint, "grounded")
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

    # -- the run loop (PROJECT.md §10) --------------------------------------

    def run(
        self,
        contract: Contract,
        budget: Budget,
        broker: Broker,
        judge: Judge,
        brains: Brains,
        *,
        identities: list[dict],
        profile: str = "",
        batch_size: int = 10,
        min_validator_reserve: int = 1,
    ) -> RunResult:
        run_id = contract.run_id
        try:
            # 1. load + verify contract, write run row (session_start hooks)
            try:
                self.start_run(contract, budget, profile, identities)
            except HookVeto as veto:
                raise RunIncomplete(veto.reason)

            # 2. readiness gate: are we talking to the intended app?
            if not broker.check_identity(contract):
                raise RunIncomplete("target identity check failed: not the intended application")

            # 3. recon -> objects + coverage units
            units_created = self.seed_from_recon(run_id, brains.surface_map(contract))
            if units_created == 0:
                raise RunIncomplete("recon produced no coverage units")

            # 4. budget gate: validation must be fundable before any hunting
            if budget.max_validator_calls - budget.used_validator_calls < min_validator_reserve:
                raise RunIncomplete(
                    f"budget cannot fund the minimum validator reserve ({min_validator_reserve})"
                )

            # 5. hunt -> dispatch -> judge -> ground, until units or budget run out
            hunter_budget_out = self._hunt_loop(run_id, contract, budget, broker, judge, brains, batch_size)

            # 6. independent validation of every grounded candidate
            self._validate_all(run_id, budget, brains)

            # 7. report (confirmed + needs_validation only)
            reportable = findings.reportable_findings(self.conn, run_id)
            report = brains.report(reportable)

            # 8. terminal decision
            if hunter_budget_out:
                left = self.conn.execute(
                    "SELECT COUNT(*) AS n FROM coverage_units WHERE run_id = ? AND state = 'deferred'",
                    (run_id,),
                ).fetchone()["n"]
                status, reason = self.finish_run(run_id, "incomplete", f"hunter budget exhausted; {left} unit(s) deferred")
            else:
                status, reason = self.finish_run(run_id, "complete")
            return RunResult(run_id, status, reason, report, reportable)

        except RunIncomplete as stop:
            exists = self.conn.execute("SELECT 1 FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if exists:
                status, reason = self.finish_run(run_id, "incomplete", stop.reason)
            else:
                status, reason = "incomplete", stop.reason
            return RunResult(run_id, status, reason, None, findings.reportable_findings(self.conn, run_id))

    def _hunt_loop(self, run_id, contract, budget, broker, judge, brains, batch_size) -> bool:
        """Returns True if the hunter budget ran out with units still planned."""
        budget_out = False
        while True:
            self.reap_expired_leases(run_id)
            batch = self.conn.execute(
                "SELECT id FROM coverage_units WHERE run_id = ? AND state = 'planned' ORDER BY wave, id LIMIT ?",
                (run_id, batch_size),
            ).fetchall()
            if not batch:
                return budget_out
            for row in batch:
                unit_id = row["id"]
                agent_id = f"hunter-{unit_id}"
                if not self.claim_unit(unit_id, agent_id):
                    continue
                if not budget.spend_hunter():
                    self.release_unit(unit_id, agent_id, "deferred")
                    budget_out = True
                    continue
                try:
                    new_state = self._hunt_unit(run_id, unit_id, agent_id, contract, broker, judge, brains)
                except StopCondition as stop:
                    self.release_unit(unit_id, agent_id, "blocked")
                    raise RunIncomplete(stop.reason)
                self.release_unit(unit_id, agent_id, new_state)

    def _hunt_unit(self, run_id, unit_id, agent_id, contract, broker, judge, brains) -> str:
        unit = self._unit_view(unit_id)
        plans = brains.hunt(unit, contract)
        if not plans:
            return "covered"

        entries: list[LedgerEntry] = []
        sent: list[RequestPlan] = []
        blocked: list[str] = []
        for plan in plans:
            try:
                entries.append(self.dispatch(plan, contract, broker))
                sent.append(plan)
            except StopCondition:
                raise
            except HookVeto as veto:
                # out-of-scope plan: blocked, recorded below, never retried
                blocked.append(f"blocked {plan.method} {plan.path}: {veto.reason}")
        if not entries:
            thread_id = state.create_thread(
                self.conn, run_id=run_id, unit_id=unit_id,
                hypothesis=f"{unit['method']} {unit['endpoint']} as {unit['identity']}",
            )
            for reason in blocked:
                state.add_rejected_path(self.conn, thread_id, reason)
            state.update_thread(self.conn, thread_id, status="rejected")
            return "blocked"

        pack = sent[0].pack or "unknown"
        title = f"{pack}: {unit['method']} {unit['endpoint']} as {unit['identity']}"
        trace = {
            "unit_id": unit_id,
            "pack": pack,
            "title": title,
            "hunter": agent_id,
            "plans": [asdict(p) for p in sent],
            "request_hashes": [e.request_hash for e in entries],
            "ledger_ids": [e.id for e in entries],
            "status_codes": [e.status_code for e in entries],
            "resp_digests": [e.resp_digest for e in entries],
        }

        thread_id = state.create_thread(self.conn, run_id=run_id, hypothesis=title, unit_id=unit_id)
        for entry in entries:
            state.link_evidence(self.conn, thread_id, entry.id)
        trace["thread_id"] = thread_id

        verdict = judge.evaluate(trace)
        if verdict == "rejected":
            state.update_thread(self.conn, thread_id, status="rejected")
            state.add_rejected_path(self.conn, thread_id, f"{pack} on {unit['method']} {unit['endpoint']}: no differential")
            return "covered"

        fingerprint = findings.compute_fingerprint(pack, unit["method"], unit["endpoint"], unit["identity_role"])
        if not findings.record_candidate(
            self.conn, fingerprint=fingerprint, run_id=run_id, unit_id=unit_id,
            title=title, trace=trace, proposed_verdict=verdict,
        ):
            state.update_thread(self.conn, thread_id, status="rejected")
            state.add_rejected_path(self.conn, thread_id, f"duplicate of {fingerprint}")
            return "covered"

        if not self.accept_candidate(fingerprint, run_id, json.dumps(trace)):
            state.update_thread(self.conn, thread_id, status="rejected")
            return "covered"

        replay: Replay = lambda plan: self.dispatch(plan, contract, broker)
        if not judge.ground(trace, run_id, replay):
            findings.set_candidate_status(self.conn, fingerprint, "rejected")
            state.update_thread(self.conn, thread_id, status="rejected")
            state.add_rejected_path(self.conn, thread_id, "did not reproduce on replay")
            return "covered"

        # The judge may annotate the trace during ground() (cleanup_done,
        # severity_hint, minimized ledger_ids) — persist what it wrote.
        self.conn.execute(
            "UPDATE candidates SET trace_json = ?, updated_at = ? WHERE fingerprint = ?",
            (json.dumps(trace), now_iso(), fingerprint),
        )
        state.update_thread(self.conn, thread_id, status="holding", next_step="independent validation")
        return "candidate"

    def _validate_all(self, run_id: str, budget: Budget, brains: Brains) -> None:
        rows = self.conn.execute(
            "SELECT fingerprint, trace_json, proposed_verdict FROM candidates WHERE run_id = ? AND status = 'grounded'",
            (run_id,),
        ).fetchall()
        for row in rows:
            fingerprint = row["fingerprint"]
            trace = json.loads(row["trace_json"])
            judge_verdict = row["proposed_verdict"]

            if not budget.reserve_validator(1):
                final = "needs_validation"   # no budget left for a second opinion
            else:
                self.assign_validator(trace["hunter"], f"validator-{fingerprint}")
                validator_verdict = brains.validate(trace)
                if "rejected" in (judge_verdict, validator_verdict):
                    final = "rejected"
                elif judge_verdict == validator_verdict == "confirmed":
                    final = "confirmed"
                else:
                    final = "needs_validation"

            findings.write_finding(
                self.conn,
                fingerprint=fingerprint,
                run_id=run_id,
                verdict=final,
                evidence_refs=trace["ledger_ids"],
                severity=trace.get("severity_hint") if final == "confirmed" else None,
                cleanup_done=bool(trace.get("cleanup_done", False)),
            )
            thread_status = {"confirmed": "confirmed", "rejected": "rejected"}.get(final, "holding")
            state.update_thread(self.conn, trace["thread_id"], status=thread_status)
