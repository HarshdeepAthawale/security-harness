"""
ledger.py

Append-only, hash-chained, Ed25519-signed audit log (one JSON object/line).

Guarantees:
  * Each record commits to the previous record's hash (chain) and is signed.
  * Startup verifies the whole chain; any tamper, gap or bad signature
    raises LedgerError (fail closed).
  * append() takes an OS file lock and re-syncs from the file tail, so
    several processes can append without forking the chain.
  * Records are fsync'd before append() returns.
  * A crash between a "pending" and its "complete" record leaves a dangling
    pending entry; unfinished_pending() lists them. Treat them as
    "outcome unknown", never as "not sent".

A torn final line (crash mid-write) makes the ledger fail closed on the next
open. Repair is a deliberate operator action; the ledger never auto-truncates.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .limits import MAX_LEDGER_RECORD_BYTES

try:                       # POSIX only; on Windows the thread lock still applies
    import fcntl
except ImportError:        # pragma: no cover
    fcntl = None

GENESIS = "0" * 64
RESERVED_KEYS = frozenset({"seq", "prev_hash", "timestamp", "record_hash", "signature"})
_VERIFY_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, InvalidSignature)


class LedgerError(RuntimeError):
    pass


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Ledger:

    def __init__(self, path: str | Path, signing_key_path: str | Path):
        self.path, self.key_path = Path(path), Path(signing_key_path)
        try:
            self.key = serialization.load_pem_private_key(
                self.key_path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError) as exc:
            raise LedgerError("ledger_key_invalid") from exc
        if not isinstance(self.key, Ed25519PrivateKey):
            raise LedgerError("ledger_key_invalid")
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.prev = self._head()

    # ------------------------------------------------------------ verification
    def _verify_line(self, line: bytes, expected_seq=None, expected_prev=None) -> dict:
        record = json.loads(line)
        signature = bytes.fromhex(record.pop("signature"))
        digest = record.pop("record_hash")
        if hashlib.sha256(_canonical(record)).hexdigest() != digest:
            raise LedgerError("ledger_chain_invalid")
        if expected_seq is not None and (
            record.get("seq") != expected_seq or record.get("prev_hash") != expected_prev
        ):
            raise LedgerError("ledger_chain_invalid")
        self.key.public_key().verify(signature, bytes.fromhex(digest))
        return {**record, "record_hash": digest}

    def _iter_verified(self):
        """Yield every record after verifying the full chain."""
        if not self.path.exists():
            return
        seq, prev = 0, GENESIS
        try:
            with self.path.open("rb") as f:
                for line in f:
                    record = self._verify_line(line, seq + 1, prev)
                    seq, prev = seq + 1, record["record_hash"]
                    yield record
        except LedgerError:
            raise
        except _VERIFY_ERRORS as exc:
            raise LedgerError("ledger_chain_invalid") from exc

    def _head(self):
        seq, prev = 0, GENESIS
        for record in self._iter_verified():
            seq, prev = record["seq"], record["record_hash"]
        return seq, prev

    def _tail(self):
        """(seq, hash) of the last record, verified. Cheap: reads one line."""
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return 0, GENESIS
        if size == 0:
            return 0, GENESIS
        try:
            with self.path.open("rb") as f:
                pos, buf = size, b""
                while pos > 0:
                    step = min(65536, pos)
                    pos -= step
                    f.seek(pos)
                    buf = f.read(step) + buf
                    stripped = buf.rstrip(b"\n")
                    if b"\n" in stripped:
                        break
            last = buf.rstrip(b"\n").split(b"\n")[-1]
            record = self._verify_line(last)
            return record["seq"], record["record_hash"]
        except LedgerError:
            raise
        except _VERIFY_ERRORS as exc:
            raise LedgerError("ledger_chain_invalid") from exc

    # ------------------------------------------------------------------ append
    def append(self, record: dict) -> dict:
        if not isinstance(record, dict) or RESERVED_KEYS & record.keys():
            raise LedgerError("ledger_record_invalid")

        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                if fcntl is not None:
                    fcntl.flock(fd, fcntl.LOCK_EX)

                seq, prev = self._tail()      # another process may have appended
                item = {
                    **record,
                    "seq": seq + 1,
                    "prev_hash": prev,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    body = _canonical(item)
                except (TypeError, ValueError, OverflowError) as exc:
                    raise LedgerError("ledger_record_invalid") from exc
                if len(body) > MAX_LEDGER_RECORD_BYTES:
                    raise LedgerError("ledger_record_too_large")

                digest = hashlib.sha256(body).hexdigest()
                item["record_hash"] = digest
                item["signature"] = self.key.sign(bytes.fromhex(digest)).hex()
                line = _canonical(item) + b"\n"

                try:
                    with os.fdopen(fd, "ab", closefd=False) as f:
                        f.write(line)
                        f.flush()
                        os.fsync(f.fileno())
                except OSError as exc:
                    raise LedgerError("ledger_write_failed") from exc
            finally:
                os.close(fd)               # also releases the flock

            self.seq, self.prev = seq + 1, digest
            return item

    async def append_async(self, record: dict) -> dict:
        """append() without blocking the event loop (fsync + file lock)."""
        return await asyncio.to_thread(self.append, record)

    # ---------------------------------------------------------------- recovery
    def unfinished_pending(self) -> list[dict]:
        """
        "pending" records with no matching "complete" (crash or cancellation
        mid-request). The request may or may not have been delivered.
        """
        pending: dict[int, dict] = {}
        for record in self._iter_verified():
            state = record.get("state")
            if state == "pending":
                pending[record["seq"]] = record
            elif state == "complete":
                pending.pop(record.get("seq_pending"), None)
        return [pending[k] for k in sorted(pending)]
