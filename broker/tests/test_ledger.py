import asyncio
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

from broker.src.ledger import Ledger, LedgerError


def write_key(path, key=None):
    key = key or Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    return key


@pytest.fixture
def paths(tmp_path):
    write_key(tmp_path / "key.pem")
    return tmp_path / "ledger.jsonl", tmp_path / "key.pem"


@pytest.fixture
def ledger(paths):
    return Ledger(*paths)


def lines(path):
    return path.read_bytes().splitlines()


def test_append_builds_a_chain(ledger):
    a = ledger.append({"state": "pending"})
    b = ledger.append({"state": "complete", "seq_pending": a["seq"]})
    assert (a["seq"], b["seq"]) == (1, 2)
    assert a["prev_hash"] == "0" * 64 and b["prev_hash"] == a["record_hash"]
    assert "signature" in b and "timestamp" in b


def test_reopen_verifies_and_continues(paths):
    l1 = Ledger(*paths); l1.append({"n": 1}); l1.append({"n": 2})
    l2 = Ledger(*paths)
    assert l2.seq == 2
    assert l2.append({"n": 3})["seq"] == 3
    Ledger(*paths)                                    # still valid


def test_file_is_private(paths, ledger):
    ledger.append({"x": 1})
    assert stat.S_IMODE(os.stat(paths[0]).st_mode) == 0o600


def test_tampered_record_detected(paths, ledger):
    ledger.append({"amount": 1}); ledger.append({"amount": 2})
    ls = lines(paths[0])
    rec = json.loads(ls[0]); rec["amount"] = 999
    ls[0] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    paths[0].write_bytes(b"\n".join(ls) + b"\n")
    with pytest.raises(LedgerError):
        Ledger(*paths)


def test_forged_signature_detected(paths, ledger):
    ledger.append({"a": 1})
    rec = json.loads(lines(paths[0])[0])
    rec["signature"] = "00" * 64
    paths[0].write_bytes(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    with pytest.raises(LedgerError):                   # not a raw InvalidSignature
        Ledger(*paths)


def test_deleted_record_detected(paths, ledger):
    for i in range(3): ledger.append({"i": i})
    ls = lines(paths[0]); del ls[1]
    paths[0].write_bytes(b"\n".join(ls) + b"\n")
    with pytest.raises(LedgerError):
        Ledger(*paths)


def test_reordered_records_detected(paths, ledger):
    for i in range(3): ledger.append({"i": i})
    ls = lines(paths[0]); ls[0], ls[1] = ls[1], ls[0]
    paths[0].write_bytes(b"\n".join(ls) + b"\n")
    with pytest.raises(LedgerError):
        Ledger(*paths)


def test_wrong_signing_key_rejected(paths, ledger, tmp_path):
    ledger.append({"a": 1})
    write_key(tmp_path / "other.pem")
    with pytest.raises(LedgerError):
        Ledger(paths[0], tmp_path / "other.pem")


def test_torn_final_line_fails_closed(paths, ledger):
    ledger.append({"a": 1})
    with paths[0].open("ab") as f: f.write(b'{"seq":2,"prev_ha')
    with pytest.raises(LedgerError):
        Ledger(*paths)


@pytest.mark.parametrize("bad_key", ["missing", "garbage", "rsa"])
def test_bad_signing_keys_rejected(tmp_path, bad_key):
    kp = tmp_path / "k.pem"
    if bad_key == "garbage": kp.write_bytes(b"not a key")
    if bad_key == "rsa":
        kp.write_bytes(generate_private_key(65537, 2048).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    with pytest.raises(LedgerError):
        Ledger(tmp_path / "l.jsonl", kp)


def test_oversized_record_rejected_and_chain_unharmed(paths, ledger):
    ledger.append({"a": 1})
    with pytest.raises(LedgerError, match="too_large"):
        ledger.append({"blob": "x" * (5 * 1024 * 1024)})
    assert ledger.append({"b": 2})["seq"] == 2
    Ledger(*paths)


@pytest.mark.parametrize("bad", [{"seq": 5}, {"signature": "x"}, {"record_hash": "x"},
                                 {"prev_hash": "x"}, {"timestamp": "x"}, "string", None])
def test_reserved_keys_and_non_dicts_rejected(ledger, bad):
    with pytest.raises(LedgerError):
        ledger.append(bad)


def test_non_serializable_record_rejected(ledger):
    with pytest.raises(LedgerError):
        ledger.append({"x": object()})
    assert ledger.append({"ok": 1})["seq"] == 1


def test_two_ledger_instances_do_not_fork_the_chain(paths):
    a, b = Ledger(*paths), Ledger(*paths)              # e.g. two processes
    a.append({"from": "a"}); b.append({"from": "b"}); a.append({"from": "a2"})
    c = Ledger(*paths)
    assert c.seq == 3


async def test_append_async_concurrent_calls_stay_ordered(paths, ledger):
    await asyncio.gather(*(ledger.append_async({"i": i}) for i in range(25)))
    assert Ledger(*paths).seq == 25


def test_unfinished_pending_lists_only_incomplete(ledger):
    p1 = ledger.append({"state": "pending", "request_hash": "r1"})
    ledger.append({"state": "complete", "seq_pending": p1["seq"]})
    p2 = ledger.append({"state": "pending", "request_hash": "r2"})
    open_ = ledger.unfinished_pending()
    assert [r["seq"] for r in open_] == [p2["seq"]]
    assert open_[0]["request_hash"] == "r2"
