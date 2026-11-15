"""Run the harness against the local crAPI (the first run on a real target).

    python crapi/seed.py             # once: accounts + one order each
    python crapi/run_harness.py      # as often as you like
    python crapi/run_harness.py --llm   # also ask the model for hypotheses (LLM_PROVIDER=ollama|openrouter)

What it does: logs in twice as each test user (the second login is the
"fresh" credential the judge replays with), gives the broker those tokens
through the environment only, signs a scope contract that allows nothing but
GET on the order endpoint, then lets the kernel, broker, judge and Brains find
and prove any IDOR/BOLA. The tokens are never printed or written anywhere.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from brains.adapter import IdorBrains                       # noqa: E402
from broker.src.kernel_broker import KernelBroker           # noqa: E402
from broker.src.scope import ScopePolicy, ScopeValidator   # noqa: E402
from crapi import seed                                      # noqa: E402
from judge.idor import IdorJudge                            # noqa: E402
from kernel.db import connect_and_init                      # noqa: E402
from kernel.models import Budget, Contract                  # noqa: E402
from kernel.orchestrator import Orchestrator                # noqa: E402

ORIGIN = "http://127.0.0.1:8888"
ORDER_PREFIX = "/workshop/api/shop/orders"
ORDER_TEMPLATE = ORDER_PREFIX + "/{order_id}"
USERS = seed.USERS


def credentials_and_identities(env: dict) -> list[dict]:
    """Log in twice per user. Tokens go into the environment for the broker."""
    identities = []
    for user in USERS:
        role = "victim" if user == USERS[0] else "attacker"
        for label, kind in ((user, "normal"), (user + "_fresh", "fresh")):
            token = seed.login(env[f"{user.upper()}_EMAIL"], env[f"{user.upper()}_PASSWORD"])
            if token is None:
                raise SystemExit(f"could not log in as {user}: run crapi/seed.py first")
            os.environ["BROKER_SECRET_" + label.upper()] = token
            identities.append({"label": label, "role": role, "cred_ref": f"env:{label.upper()}"})
    return identities


def permission_rules(orders: dict) -> list[dict]:
    """crAPI's design: an order is visible only to the user who placed it."""
    rules = []
    for owner, order_id in orders.items():
        path = f"{ORDER_PREFIX}/{order_id}"
        for user in USERS:
            for label in (user, user + "_fresh"):
                rules.append({"identity": label, "method": "GET", "path": path,
                              "decision": "allow" if user == owner else "deny",
                              "source": "crAPI design: an order is private to the user who placed it"})
    return rules


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--llm", action="store_true", help="ask the configured model for hypotheses too")
    args = parser.parse_args()

    env, state = seed.load_env(), (json.loads(seed.STATE_FILE.read_text()) if seed.STATE_FILE.exists() else {})
    orders = state.get("orders", {})
    if not env or set(orders) != set(USERS):
        print("no test accounts yet: run  python crapi/seed.py  first")
        return 1

    identities = credentials_and_identities(env)
    labels = [i["label"] for i in identities]

    contract = Contract(
        run_id=time.strftime("crapi-%Y%m%d-%H%M%S"), target="127.0.0.1", allowed_origins=[ORIGIN],
        allowed_paths=[ORDER_PREFIX + "/*"], allowed_methods=["GET"], identities=labels, stop_conditions=[],
        contract_hash="", permission_rules=permission_rules(orders),
        fresh_identity_map={user: user + "_fresh" for user in USERS},
    )
    contract.contract_hash = contract.compute_hash()

    validator = ScopeValidator(ScopePolicy(
        base_url=ORIGIN, allowed_methods=frozenset({"GET"}), allowed_path_prefixes=(ORDER_PREFIX,),
        allowed_packs=frozenset({"idor-bola"}), allowed_identities=frozenset(labels),
        allowed_cidrs=("127.0.0.0/8",),                       # crAPI runs on this machine
        identity_probe_path="/", identity_probe_marker="crAPI"))

    llm = None
    if args.llm:
        from brains.llm_client import make_llm_client
        llm = make_llm_client()
    brains = IdorBrains(
        [{"method": "GET", "path": ORDER_TEMPLATE, "auth_required": True}],
        {"orders": {user: str(order_id) for user, order_id in orders.items()}},
        llm_client=llm, use_llm=args.llm)

    db_path = HERE / "run.db"
    for suffix in ("", "-wal", "-shm", "-journal"):
        Path(str(db_path) + suffix).unlink(missing_ok=True)
    conn = connect_and_init(db_path)

    print(f"run {contract.run_id}: {ORIGIN}, GET {ORDER_PREFIX}/<id> only, orders {orders}")
    result = Orchestrator(conn).run(
        contract, Budget(max_hunter_calls=20, max_validator_calls=10, max_requests=60),
        KernelBroker(validator), IdorJudge(), brains, identities=identities)

    print(f"\nstatus: {result.status}" + (f"  ({result.reason})" if result.reason else ""))
    print(result.report or "(no report: the run stopped before the report step)")
    print("\nrequests the kernel sent:", dict(conn.execute("SELECT outcome, COUNT(*) FROM dispatches GROUP BY outcome").fetchall()))
    if result.report:
        (HERE / "report.md").write_text(result.report + "\n")
    return 0 if result.status == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
