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
    def evaluate(self, candidate_trace: dict) -> str: ...
    def ground(self, candidate_trace: dict, run_id: str, replay) -> bool: ...

class Brains(Protocol):
    def surface_map(self, contract: Contract) -> list[dict]: ...
    def hunt(self, unit: dict, contract: Contract) -> list[RequestPlan]: ...
    def validate(self, candidate_trace: dict) -> str: ...
    def report(self, findings: list[dict]) -> str: ...
```

**`tests/fakes.py`** has a working fake of all three. Copy the one for your
part as a starting stub, and run `tests/test_run_loop.py` to see how the
kernel drives it.

### Per-workstream notes

**Broker**
- `send()` returns a `LedgerEntry`. The kernel writes it to the ledger;
  you don't touch the DB.
- **The kernel checks your record against the plan.** `method` must match,
  the URL's origin must be in `allowed_origins` (scheme, host and port), and
  the URL's path must be exactly `plan.path`. Any difference stops the run.
  The kernel sets the ledger `id`, `run_id` and `identity_id` itself, so
  don't bother filling those in.
- Send `plan.path` **exactly as given**. The kernel validated it in that
  form (dot segments, `//`, encoded slashes, backslashes are rejected).
  Don't re-decode or normalize it, or the scope check no longer holds.
- If `send()` raises (network down, timeout), the run ends `incomplete`
  with your error in the reason and can be resumed. Don't swallow errors.
- Resolve `plan.identity` (a label like `"user_B"`) to a real secret using
  the identity's `cred_ref`. That's the only place a real token ever exists.
- Set `LedgerEntry.flags` when you detect `bot_challenge`,
  `auth_ambiguity` or `destructive_effect`. Any of these stops the run.
  A `429` stops it too.
- `check_identity()` is the readiness gate (PROJECT.md §7.1). Return
  `False` if the thing answering isn't the intended app.

**Judge**
- `evaluate(trace)` looks at a hunt's exchanges (`status_codes`,
  `resp_digests`, `plans`). Return `"rejected"` if there's no real
  differential, otherwise `"confirmed"` or `"needs_validation"`.
- `ground(trace, run_id, replay)` re-runs the sequence. **Every replay must
  go through `replay(plan)`**, never straight to the network. That keeps
  replays scope-checked and logged.
- You get a **copy** of the trace. Changing anything else in it has no
  effect. Only `cleanup_done` (bool), `severity_hint` (str) and a minimized
  `ledger_ids` list come back, and they're checked: every id must be one of
  this candidate's exchanges or a replay you made. Citing any other id
  rejects the candidate. A confirmed finding without `cleanup_done=True`
  makes the run `incomplete`.
- Replays count against the run's request budget like any other request.

**Brains**
- `surface_map()` returns
  `[{resource_type, endpoint, method, owner_identity?, actions?}, ...]`.
  The kernel turns each into one coverage unit per (object, action, identity).
- `hunt(unit)` gets
  `{unit_id, object_id, resource_type, endpoint, method, action, identity, identity_role, owner_identity, wave}`
  and returns `RequestPlan`s. Paths must be relative (`/api/...`). At most
  `max_plans_per_unit` (default 20) per unit; more is treated as a Brains
  fault and stops the run.
- `validate(trace)` is the independent second opinion. Only
  `confirmed` + `confirmed` (judge + validator) gives a confirmed finding.

## Running a full harness run

```python
from kernel.db import connect_and_init
from kernel.models import Budget, Contract
from kernel.orchestrator import Orchestrator

conn = connect_and_init("run.db")
orch = Orchestrator(conn)   # default safety hooks are always installed
contract = Contract(run_id="run1", target="crapi.local", allowed_origins=["http://crapi.local"],
                    allowed_paths=["/api/*"], allowed_methods=["GET"],
                    identities=["user_A", "user_B"], stop_conditions=[], contract_hash="")
contract.contract_hash = contract.compute_hash()   # "sign" the scope

result = orch.run(
    contract, Budget(max_hunter_calls=100, max_validator_calls=20, max_requests=500),
    broker, judge, brains,
    identities=[{"label": "user_A", "role": "victim", "cred_ref": "vault:user_A"},
                {"label": "user_B", "role": "attacker", "cred_ref": "vault:user_B"}],
)
print(result.status, result.reason, result.report)
```

`run()` follows PROJECT.md §10: contract check → readiness gate → recon →
budget gate → hunt/dispatch/judge/ground loop → independent validation →
report → `complete` / `incomplete` with the exact reason.

**A run never hangs.** If Broker, Judge or Brains raises, the run ends
`incomplete` with a reason like `broker failed: ConnectionError: ...`,
and its leases are freed.

**Resuming.** A run that stopped (`incomplete`) or crashed (left
`in_progress`) continues with:

```python
result = orch.resume(contract, broker, judge, brains, add_hunter_calls=50)
```

It re-queues interrupted units, retries units the budget skipped, keeps
everything already grounded or confirmed, and loads the spent budget from
the DB (`add_*` tops it up). It refuses a changed contract, because a
different scope is a new run.

**Known bugs in re-runs.** A fingerprint is stable across runs, so a
later run still reports a bug found before, with
`previously_confirmed_in` set to the earlier run's id.

**Traffic limits.** `Budget.max_requests` (default 1000) caps every request
the run sends to the target, replays included. The hunter/validator caps
only count AI calls. A run that hits it ends `incomplete`, and
`resume(..., add_requests=N)` continues it.

**Dispatch log.** Every request the kernel is asked to send gets a row in
`dispatches` **before** the broker is called: `vetoed`, `over_budget`,
`sent`, then `recorded` (with its ledger id), `broker_error` or
`record_mismatch`. A request that dies mid-flight is still on record. The
log holds identity labels, never secrets.

## Default hooks (`kernel/default_hooks.py`)

These are **always installed**: `Orchestrator(conn)` adds them itself, and
any `hooks` you pass are added on top. Safety can't be switched off by
forgetting to register it.

| Hook | Rule |
|---|---|
| `session_start` | contract hash must match (scope not edited after signing); target must be in `allowed_origins` |
| `pre_broker_request` | method, path and identity must be in the contract. The path is decoded first; `..`, `.`, `//`, `%2f`, `..;`, backslashes and control characters are refused |
| `post_broker_request` | `429` or a broker flag (`bot_challenge`, `auth_ambiguity`, `destructive_effect`, plus any listed in the contract) stops the run |
| `session_end` | every confirmed finding needs verified cleanup, otherwise the run is `incomplete` |

## Running the kernel's tests

```bash
pip install -r requirements.txt
pytest
```

## What's NOT here yet

- Real Broker / Judge / Brains. The kernel is tested end-to-end against
  the fakes in `tests/fakes.py` only.
- Parallel hunters. `run()` hunts units one at a time; leases are in place
  so it can fan out later.
- Per-unit database transactions. A crash mid-unit can leave partial
  rows; `resume()` cleans those up, but writes aren't atomic.
- Hunter ≠ validator is enforced on agent ids only. Using a different
  model/context for validation is up to Brains.
- A CLI / config file for starting a run.
