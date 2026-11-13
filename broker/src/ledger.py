from __future__ import annotations
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .limits import MAX_LEDGER_RECORD_BYTES


class LedgerError(RuntimeError):
    pass


class Ledger:
    def __init__(self, path: str | Path, signing_key_path: str | Path):
        self.path, self.key_path = Path(path), Path(signing_key_path)
        try:
            keydata = self.key_path.read_bytes()
            self.key = serialization.load_pem_private_key(keydata, password=None)
        except (OSError, ValueError, TypeError) as exc:
            raise LedgerError("ledger_key_invalid") from exc
        if not isinstance(self.key, Ed25519PrivateKey):
            raise LedgerError("ledger_key_invalid")
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.seq, self.prev = self._head()

    def _head(self):
        if not self.path.exists(): return 0, "0" * 64
        seq, prev = 0, "0" * 64
        try:
            with self.path.open("rb") as f:
                for line in f:
                    record = json.loads(line)
                    signature = bytes.fromhex(record.pop("signature"))
                    digest = record.pop("record_hash")
                    body = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
                    if record.get("seq") != seq + 1 or record.get("prev_hash") != prev or hashlib.sha256(body).hexdigest() != digest:
                        raise LedgerError("ledger_chain_invalid")
                    self.key.public_key().verify(signature, bytes.fromhex(digest))
                    seq, prev = seq + 1, digest
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, LedgerError): raise
            raise LedgerError("ledger_chain_invalid") from exc
        return seq, prev

    def append(self, record: dict) -> dict:
        with self._lock:
            self.seq += 1
            item = {**record, "seq": self.seq, "prev_hash": self.prev, "timestamp": datetime.now(timezone.utc).isoformat()}
            body = json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
            if len(body) > MAX_LEDGER_RECORD_BYTES:
                self.seq -= 1
                raise LedgerError("ledger_record_too_large")
            digest = hashlib.sha256(body).hexdigest()
            item["record_hash"] = digest
            item["signature"] = self.key.sign(bytes.fromhex(digest)).hex()
            line = json.dumps(item, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                with os.fdopen(fd, "ab", closefd=True) as f:
                    f.write(line); f.flush(); os.fsync(f.fileno())
            except OSError as exc:
                self.seq -= 1
                raise LedgerError("ledger_write_failed") from exc
            self.prev = digest
            return item