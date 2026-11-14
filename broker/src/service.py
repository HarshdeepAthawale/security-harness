from __future__ import annotations
import argparse
import json
import logging
import sys
from .errors import error_code
from .executor import execute
from .limits import MAX_PLAN_BYTES
from .redact import redact_headers
from .scope import load_scope, parse_plan

LOG = logging.getLogger("broker")


def handle(raw: bytes, scope, ledger, execute_fn=execute) -> dict:
    """One plan in, one result out. Every failure returns a stable error code
    (never a message), and a request that may have reached the target always
    leaves a record: pending, then complete or failed."""
    request = None
    pending = None
    try:
        request = parse_plan(raw, scope)
        pending = ledger.append({"state": "pending", "request_hash": request.request_hash, "request": {"method": request.method, "path": request.path, "query": dict(request.query), "headers": redact_headers(dict(request.headers)), "identity": request.identity, "pack": request.pack, "replay_safe": request.replay_safe}})
        result = execute_fn(request)
        ledger.append({"state": "complete", "request_hash": request.request_hash, "seq_pending": pending["seq"], "response": result})
        return {"status": result["status"], "digest": result["digest"], "sample": result["sample"], "request_hash": request.request_hash}
    except Exception as exc:
        code = error_code(exc)
        LOG.warning("broker_failure code=%s", code)
        if pending is not None:
            try:
                ledger.append({"state": "failed", "request_hash": request.request_hash, "seq_pending": pending["seq"], "error": code})
            except Exception:
                LOG.error("broker_failure could not record the failure of %s", request.request_hash)
        return {"error": code}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--signing-key", default="/etc/broker/keys/ledger_signing.key")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    from .ledger import Ledger          # needs `cryptography`; imported here so handle() doesn't
    scope = load_scope(args.scope)
    ledger = Ledger(args.ledger, args.signing_key)
    for line in sys.stdin.buffer:
        if len(line) > MAX_PLAN_BYTES:
            output = {"error": "invalid_plan"}
        else:
            output = handle(line.rstrip(b"\r\n"), scope, ledger)
        sys.stdout.write(json.dumps(output, separators=(",", ":")) + "\n"); sys.stdout.flush()


if __name__ == "__main__": main()
