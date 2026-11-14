"""The judge can't invent evidence or rewrite what the broker recorded."""
import json

from kernel.db import connect_and_init
from kernel.default_hooks import register_default_hooks
from kernel.hooks import HookRegistry
from kernel.models import Budget, RequestPlan
from kernel.orchestrator import Orchestrator
from tests.fakes import IDENTITIES, FakeBrains, FakeBroker, FakeJudge, make_contract


class ScriptedJudge(FakeJudge):
    """FakeJudge that, after a successful replay, does `tamper(trace, replay_entry)`."""

    def __init__(self, tamper):
        super().__init__()
        self.tamper = tamper

    def ground(self, trace, run_id, replay):
        entry = replay(RequestPlan(**trace["plans"][0]))
        trace["cleanup_done"] = True
        trace["severity_hint"] = "high"
        self.tamper(trace, entry)
        return True


def _run(tmp_path, judge, brains=None):
    conn = connect_and_init(tmp_path / "t.db")
    orch = Orchestrator(conn, register_default_hooks(HookRegistry()))
    result = orch.run(make_contract(), Budget(max_hunter_calls=50, max_validator_calls=10),
                      FakeBroker(), judge, brains or FakeBrains(), identities=IDENTITIES)
    return conn, result


def _rejection_notes(conn):
    notes = []
    for r in conn.execute("SELECT rejected_paths FROM threads").fetchall():
        notes.extend(json.loads(r["rejected_paths"]))
    return notes


def test_invented_ledger_id_rejects_the_candidate(tmp_path):
    def invent(trace, entry):
        trace["ledger_ids"] = ["ledg_does_not_exist"]

    conn, result = _run(tmp_path, ScriptedJudge(invent))
    assert result.findings == []
    assert any("never recorded" in n for n in _rejection_notes(conn))


def test_ledger_id_from_another_candidate_is_rejected(tmp_path):
    """A real ledger row, but not one of this candidate's exchanges."""
    other = {}

    def borrow(trace, entry):
        other.setdefault("id", entry.id)          # first candidate's replay id
        if trace["ledger_ids"] != [other["id"]]:
            trace["ledger_ids"] = [other["id"]]

    brains = FakeBrains(objects=[
        {"resource_type": "order", "endpoint": "/api/orders/1001", "method": "GET", "owner_identity": "user_A"},
        {"resource_type": "invoice", "endpoint": "/api/invoices/7", "method": "GET", "owner_identity": "user_A"},
    ])
    conn, result = _run(tmp_path, ScriptedJudge(borrow), brains)
    assert len(result.findings) == 1                 # the first one cites its own replay: fine
    assert any("never recorded" in n for n in _rejection_notes(conn))


def test_empty_evidence_is_rejected(tmp_path):
    conn, result = _run(tmp_path, ScriptedJudge(lambda t, e: t.update(ledger_ids=[])))
    assert result.findings == []
    assert any("no usable evidence" in n for n in _rejection_notes(conn))


def test_judge_cannot_rewrite_recorded_responses(tmp_path):
    """The judge flips the recorded status code and digest; the kernel's copy
    (which the validator reads) is unchanged."""
    def rewrite(trace, entry):
        trace["status_codes"] = [999]
        trace["resp_digests"] = ["forged"]

    conn, result = _run(tmp_path, ScriptedJudge(rewrite))
    saved = json.loads(conn.execute("SELECT trace_json FROM candidates").fetchone()["trace_json"])
    assert saved["status_codes"] == [200]
    assert saved["resp_digests"] != ["forged"]


def test_minimizing_to_the_replay_is_allowed(tmp_path):
    def minimize(trace, entry):
        trace["ledger_ids"] = [entry.id]

    conn, result = _run(tmp_path, ScriptedJudge(minimize))
    assert len(result.findings) == 1
    replay_id = result.findings[0]["evidence_refs"][0]
    assert conn.execute("SELECT 1 FROM ledger WHERE id = ?", (replay_id,)).fetchone()
    linked = conn.execute("SELECT note FROM thread_evidence WHERE ledger_id = ?", (replay_id,)).fetchone()
    assert linked["note"] == "replay"


def test_bad_annotation_types_are_rejected(tmp_path):
    conn, result = _run(tmp_path, ScriptedJudge(lambda t, e: t.update(cleanup_done="yes")))
    assert result.findings == []
    assert any("non-boolean" in n for n in _rejection_notes(conn))
