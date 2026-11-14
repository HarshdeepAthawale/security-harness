from __future__ import annotations
import argparse
import json
import logging
import sys
from .ledger import Ledger
from .limits import MAX_PLAN_BYTES
from .plan import PlanError, parse_plan
from .redact import redact_headers
from .scope import load_scope
from .executor import execute

LOG = logging.getLogger("broker")


def handle(raw: bytes, scope, ledger: Ledger) -> dict:
    request = None
    try:
        request = parse_plan(raw, scope)
        entry = ledger.append({"state": "pending", "request_hash": request.request_hash, "request": {"method": request.method, "path": request.path, "query": dict(request.query), "headers": redact_headers(dict(request.headers)), "identity": request.identity, "pack": request.pack, "replay_safe": request.replay_safe}})
        result = execute(request)
        ledger.append({"state": "complete", "request_hash": request.request_hash, "seq_pending": entry["seq"], "response": result})
        return {"status": result["status"], "digest": result["digest"], "sample": result["sample"], "request_hash": request.request_hash}
    except Exception as exc:
        LOG.warning("broker_failure code=%s", getattr(exc, "code", type(exc).__name__))
        return {"error": "invalid plan"}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--signing-key", default="/etc/broker/keys/ledger_signing.key")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    scope = load_scope(args.scope)
    ledger = Ledger(args.ledger, args.signing_key)
    for line in sys.stdin.buffer:
        if len(line) > MAX_PLAN_BYTES:
            output = {"error": "invalid plan"}
        else:
            output = handle(line.rstrip(b"\r\n"), scope, ledger)
        sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n"); sys.stdout.flush()


if __name__ == "__main__": main()