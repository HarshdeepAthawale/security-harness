# Kernel

The boss. No AI lives here — pure, deterministic Python. Owns the DB, hands
out work, enforces the Constitution via hooks, decides when a run is done.

See `PROJECT.md` §6, §9, §10 for the full design. This README is the
**frozen contracts** the other 3 workstreams (Broker, Judge, Brains) build
against. Changing any of these three is a breaking change for everyone —
raise it with the team before you do.

## Contract #1 — the DB schema (`kernel/schema.sql`)

SQLite is the single source of truth. **Only the kernel writes to it.**
Broker/Judge/Brains never open the `.db` file directly — they call kernel
methods (`Orchestrator.dispatch`, `.accept_candidate`, etc.) which do the
writing. If you need a new column or table, propose it, don't just add it.

Key tables: `runs`, `identities`, `objects`, `coverage_units`, `candidates`,
`ledger` (the grounding ledger — anti-hallucination spine), `findings`,
`leases`, `threads` + `thread_evidence` (curated research state).

## Contract #2 — the Request Plan (`kernel/models.py::RequestPlan`)

This is the **only** thing Brains ever hands to the kernel/broker. It's a
plan, never a raw network call:

```python
RequestPlan(
    unit_id="u1",            # which coverage_unit this targets
    identity="user_B",       # a HANDLE, never a real token
    method="GET",
    path="/api/orders/1001",
    headers={"Content-Type": "application/json"},  # NEVER Authorization/Cookie
    query={},
    body=None,
    pack="idor-bola",
    expect="403/404",
)
```

The `__post_init__` on `RequestPlan` **hard-rejects** any `Authorization`,
`Cookie`, or `X-Api-Key` header — that's not a style nit, it's how we
guarantee credentials never enter agent/LLM context. The broker resolves
`identity` to a real secret at send-time (`identities.cred_ref`).

## Contract #3 — the Hook API (`kernel/hooks.py`)

Fixed veto points, no LLM inside any of them:

| Hook point | Fires when | Can veto |
|---|---|---|
| `session_start` | before any work | contract/target-identity problems |
| `pre_broker_request` | before a plan is sent | out-of-scope, bad identity |
| `post_broker_request` | after a response is logged | stop-condition detection |
| `pre_candidate_accept` | before a candidate leaves `proposed` | no ledger match → auto-handled before hooks even run; hooks add more checks |
| `pre_validate` | before a Validator is assigned | hunter == validator identity |
| `session_end` | before a run closes | cleanup not verified |

Register with `registry.on("pre_broker_request")` as a decorator, or
`registry.register(point, fn)`. Raise `HookVeto("reason")` to block.

## How the other 3 plug in

The kernel depends on three `Protocol`s in `kernel/orchestrator.py` —
implement these, nothing else, and you're compatible:

```python
class Broker(Protocol):
    def send(self, plan: RequestPlan, contract: Contract) -> LedgerEntry: ...
    def check_identity(self, contract: Contract) -> bool: ...

class Judge(Protocol):
    def ground(self, candidate_trace: dict, run_id: str) -> bool: ...
    def evaluate(self, candidate_trace: dict) -> str: ...

class Brains(Protocol):
    def surface_map(self, contract: Contract) -> list[dict]: ...
    def hunt(self, unit: dict, contract: Contract) -> list[RequestPlan]: ...
    def validate(self, candidate_trace: dict) -> str: ...
    def report(self, findings: list[dict]) -> str: ...
```

`tests/test_orchestrator.py::FakeBroker` is a working example of the
`Broker` protocol you can copy as a starting stub.

## Running the kernel's tests

```bash
pip install -r requirements.txt
pytest
```

## What's NOT here yet

The full `Orchestrator.run()` loop (PROJECT.md §10, steps 1–8) wiring
Broker+Judge+Brains together end-to-end — that lands once all three
protocols have a real (even minimal) implementation to test against.
Today's scope is: schema, request-plan contract, hook enforcement,
leases, and the dispatch/accept/validate primitives the run loop will call.
