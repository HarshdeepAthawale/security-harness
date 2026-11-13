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

## What each file does

- brains/schemas.py: Python dataclasses shared across stages.
- brains/schemas.json: JSON data contract for the kernel teammate.
- brains/recon.py: deterministic endpoint cleanup and grouping.
- brains/hunt.py: hypothesis generation and endpoint anti-hallucination check.
- brains/validate.py: replayable request template preparation without a verdict.
- brains/report.py: report separated by judge result.
- brains/llm_client.py: OpenRouter HTTP client using OPENROUTER_API_KEY with one JSON retry.
- brains/prompts/: stage instructions and JSON examples.
- brains/tests/test_hunt.py: fake-data tests with no API call.

## Install and run tests

Use Python 3.10 or newer. From this project directory:

    python -m pip install -r requirements.txt
    python -m pytest brains/tests

The tests need no API key. For a real model call, set OPENROUTER_API_KEY as
shown in .env.example. Never treat a hypothesis or validation spec as a finding.
