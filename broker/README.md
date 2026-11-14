# Broker

The only part of the harness that talks to the target. It checks every
request against a scope file, attaches the credential itself, sends the
request to an address it resolved and approved, and records what happened.

```
kernel RequestPlan
   -> KernelBroker.send()                       broker/src/kernel_broker.py
   -> RequestPlan (pydantic, strict)            broker/src/plan.py
   -> ScopeValidator.build() -> ValidatedRequest   broker/src/scope.py
   -> execute()                                  broker/src/executor.py
        resolve_pinned()   DNS guard, connects to the checked IP only
        get_credential()   BROKER_SECRET_<IDENTITY> from the environment
        response_summary() digest of the raw body, redacted sample
   -> ledger (optional, Ed25519-signed hash chain)  broker/src/ledger.py
   -> LedgerEntry back to the kernel
```

## Use it from the kernel

```python
from broker.src.kernel_broker import KernelBroker
from broker.src.scope import load_scope

broker = KernelBroker(load_scope("scope.json"))        # add ledger=Ledger(path, key) for the signed log
orchestrator.run(contract, budget, broker, judge, brains, identities=[...])
```

Credentials come from the environment, one per identity label:
`BROKER_SECRET_USER_A`, `BROKER_SECRET_USER_A_FRESH`, ... They never go in
the scope file, the plan, the ledger or the database.

## The scope file

```json
{
  "base_url": "http://127.0.0.1:8888",
  "allowed_methods": ["GET"],
  "allowed_path_prefixes": ["/api"],
  "allowed_packs": ["idor-bola"],
  "allowed_identities": ["user_A", "user_B", "user_A_fresh", "user_B_fresh"],
  "allowed_cidrs": ["127.0.0.0/8"],
  "identity_probe": {"path": "/api/health", "status": 200, "marker": "my-app-name"}
}
```

- `allowed_cidrs`: needed only when the target is on a private or loopback
  address (a local crAPI). Public targets need nothing. Without it a private
  address is refused, which stops a hostile name from pointing the broker at
  your internal network or a cloud metadata address.
- `identity_probe`: the readiness gate (PROJECT.md 7.1). A GET, sent with no
  credential, must return this status with this marker in the body. **Without
  it `check_identity()` fails closed and the run won't start.**

## What it refuses

| Case | Result |
|---|---|
| method, path, pack or identity outside the scope file | `out_of_scope`, nothing sent |
| `..`, `..;`, `//`, `%00`, `%2f`, backslash, nested encoding | rejected, in the plan model AND the scope check |
| plan sets `Authorization`, `Cookie`, `Host` (unless the scope allows a Host override) | rejected |
| target resolves to a private / link-local / metadata address | `dns_address_denied` |
| redirect | returned as the response, never followed |
| response over 2 MB | `response_too_large` |
| server slower than 30 s in total, even one byte at a time | `upstream_timeout` |
| connection cut before the promised body arrived | `upstream_truncated` |

Errors leave the broker as short stable codes, never messages.

## What is stored

The ledger and the returned sample hold a **redacted** sample (4 KB): JSON
keys like `token`/`secret`/`password`/`session`, JWTs, `Bearer ...`, and the
credential the broker itself sent are removed from the whole body before it is
cut down. The **digest** is of the raw body, so the judge can still compare
two responses exactly.

## Tests

`pytest` from the repo root runs `broker/tests` too. `test_ledger.py` is
skipped where `cryptography` can't be installed (Windows on ARM has no
wheel); it runs everywhere else.

## Known limits

- One request at a time; no connection reuse.
- The signing key is read from disk by the same process that signs, so the
  ledger shows tampering with the file, not a compromise of the broker.
- Flags: only `bot_challenge` is detected. `auth_ambiguity` and
  `destructive_effect` are not set yet.
