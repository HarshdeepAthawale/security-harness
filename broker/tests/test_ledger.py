"""The signed, hash-chained ledger. Needs `cryptography`; where it can't be
installed (e.g. Windows on ARM has no wheel) these tests are skipped, not faked."""
import json

import pytest

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from broker.src.ledger import Ledger, LedgerError  # noqa: E402


@pytest.fixture
def key_path(tmp_path):
    path = tmp_path / "ledger.key"
    path.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return path


def test_records_chain_and_survive_a_reopen(tmp_path, key_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key_path)
    first = ledger.append({"state": "pending", "request_hash": "h1"})
    second = ledger.append({"state": "complete", "request_hash": "h1"})
    assert (first["seq"], second["seq"]) == (1, 2)
    assert second["prev_hash"] == first["record_hash"]

    reopened = Ledger(path, key_path)                      # verifies the whole chain on open
    assert reopened.append({"state": "pending", "request_hash": "h2"})["seq"] == 3


def test_editing_a_record_is_detected(tmp_path, key_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key_path)
    ledger.append({"state": "complete", "request_hash": "h1", "response": {"status": 403}})
    record = json.loads(path.read_text())
    record["response"]["status"] = 200
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    with pytest.raises(LedgerError, match="ledger_chain_invalid"):
        Ledger(path, key_path)


def test_removing_a_record_from_the_middle_is_detected(tmp_path, key_path):
    path = tmp_path / "ledger.jsonl"
    ledger = Ledger(path, key_path)
    for n in range(3):
        ledger.append({"state": "pending", "request_hash": f"h{n}"})
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    with pytest.raises(LedgerError, match="ledger_chain_invalid"):
        Ledger(path, key_path)


def test_a_ledger_signed_with_another_key_is_refused(tmp_path, key_path):
    path = tmp_path / "ledger.jsonl"
    Ledger(path, key_path).append({"state": "pending", "request_hash": "h"})
    other = tmp_path / "other.key"
    other.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with pytest.raises(LedgerError):
        Ledger(path, other)


def test_a_bad_key_is_refused(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("not a key")
    with pytest.raises(LedgerError, match="ledger_key_invalid"):
        Ledger(tmp_path / "l.jsonl", bad)


def test_an_oversized_record_is_refused_and_does_not_burn_a_sequence_number(tmp_path, key_path):
    ledger = Ledger(tmp_path / "ledger.jsonl", key_path)
    with pytest.raises(LedgerError, match="ledger_record_too_large"):
        ledger.append({"blob": "x" * (5 * 1024 * 1024)})
    assert ledger.append({"state": "pending"})["seq"] == 1
