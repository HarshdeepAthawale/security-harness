# Brains package

Brains prepares IDOR/BOLA hypotheses; it never confirms a bug. Hypotheses start
as unverified. Only the judge can return a reproduced verdict.

## Brains -> kernel -> broker -> judge

1. recon.py cleans broker or scraped endpoint records into a resource map.
2. hunt.py asks a model through OpenRouter for hypotheses and drops endpoints absent from that map.
3. validate.py prepares request templates for the kernel and broker; it sends no requests.
4. The kernel sends the spec to the broker. The broker alone contacts the target and logs traffic.
5. The judge replays broker evidence and returns a JudgeResult.
6. report.py puts reproduced results in findings and others in an Unverified / not reproduced section.

## Plugging into the kernel: `brains/adapter.py`

The kernel calls Brains through the `Brains` protocol in
`kernel/orchestrator.py`. `IdorBrains` implements it on top of the modules
below, without changing them:

| Kernel calls | IdorBrains does |
|---|---|
| `surface_map(contract)` | `recon.build_recon_map` + one LLM call for hypotheses, then fills each endpoint template with a real object id per owner |
| `hunt(unit, contract)` | two `RequestPlan`s: **baseline** (owner reads own object) and **attack** (other identity reads it). Owner-on-own-object units get no plans. |
| `validate(trace)` | deterministic, no LLM: attacker got the owner's exact body → `confirmed`; 401/403/404 → `rejected`; anything else → `needs_validation` |
| `report(findings)` | turns kernel findings into `JudgeResult`s and uses `report.build_report` |

```python
from brains.adapter import IdorBrains

brains = IdorBrains(
    raw_endpoints=[{"method": "GET", "path": "/api/orders/{id}", "auth_required": True}],
    object_ids={"orders": {"user_A": "1001", "user_B": "2002"}},   # which object each user owns
)
result = orch.run(contract, budget, broker, judge, brains, identities=[...])
```

Rules it keeps:
- The LLM only proposes. It adds the rationale; it can't hide an endpoint,
  because every endpoint with an object id is tested whatever the model says.
- Each plan's `expect` starts with `baseline:` or `attack:`; the judge can
  read the role with `brains.adapter.plan_role(plan)`.
- Object ids are URL-encoded into the path, so an id can't add path segments.
- `use_llm=False` runs with no model at all.

Limits: paths with more than one id (e.g. `/users/{uid}/orders/{oid}`) are
skipped for now, and `object_ids` must be supplied by whoever sets up the run.

## What each file does

- brains/schemas.py: Python dataclasses shared across stages.
- brains/schemas.json: JSON data contract for the kernel teammate.
- brains/recon.py: deterministic endpoint cleanup and grouping.
- brains/hunt.py: hypothesis generation and endpoint anti-hallucination check.
- brains/validate.py: replayable request template preparation without a verdict.
- brains/report.py: report separated by judge result.
- brains/llm_client.py: model client, OpenRouter (cloud) or Ollama (local), with one JSON retry.
- brains/adapter.py: plugs the modules above into the kernel.
- brains/prompts/: stage instructions and JSON examples.
- brains/tests/: fake-data tests with no API call and no network.

## Choosing the model: cloud or local

Brains talks to a model through `brains/llm_client.py`. Pick one with
`LLM_PROVIDER`:

| `LLM_PROVIDER` | Where it runs | Needs |
|---|---|---|
| `openrouter` (default) | cloud | `OPENROUTER_API_KEY`; optional `OPENROUTER_MODEL` |
| `ollama` | **this machine**: recon data never leaves it | Ollama running; optional `OLLAMA_URL`, `OLLAMA_MODEL` |

Local setup:

    ollama serve
    ollama pull qwen2.5:7b
    LLM_PROVIDER=ollama python your_run_script.py

Or pick it in code:

```python
from brains.llm_client import make_llm_client
brains = IdorBrains(raw_endpoints, object_ids, llm_client=make_llm_client("ollama", model="qwen2.5:7b"))
```

The Ollama client sends `format: "json"` and `temperature: 0`. It refuses an
`OLLAMA_URL` that isn't on this machine unless `OLLAMA_ALLOW_REMOTE=1`, so a
typo can't quietly send target data to another host. Smaller local models
may give fewer or weaker hypotheses; that only affects the report's
rationale, because the adapter tests every object endpoint anyway.

## Install and run tests

Use Python 3.10 or newer. From this project directory:

    python -m pip install -r requirements.txt
    python -m pytest brains/tests

The tests need no API key and no Ollama. For a real model call, set the
variables shown in .env.example. Never treat a hypothesis or validation spec
as a finding.
