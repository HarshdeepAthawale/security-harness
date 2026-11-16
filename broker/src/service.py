"""
service.py

Orchestrates one request plan end to end. Every security decision is made by
the module that owns it; this file only sequences them and enforces the
invariants that span modules:

    1. plan.py        parse + structural validation
    2. scope.py       authorization -> the canonical URL (the ONLY URL sent)
    3. credentials.py origin-bound auth headers
    4. executor.py    build_request; its URL must equal scope's URL exactly
    5. dns_guard.py   resolve + validate; executor re-validates the result
    6. ledger.py      "pending" record is written BEFORE anything is sent
    7. executor.py    execute against the pinned addresses
    8. redact.py      redact, then write the "complete" record

Invariants:
  * No request is sent unless its pending record is durably in the ledger
    (ledger failure => fail closed, nothing leaves the process).
  * Rejections never reveal internals to the caller: only a short code.
    Exception text is never returned (it can echo plan content).
  * Secrets never reach the ledger or the caller: auth is applied after
    scope, and every response/log passes through a Redactor built from ALL
    configured identities' credentials.
  * A crash or cancellation between "pending" and "complete" leaves a
    dangling pending record. That means "outcome unknown", never "not sent".
    Ledger.unfinished_pending() lists them; main() reports them at startup.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Mapping

from pydantic import ValidationError

from .credentials import Credential, CredentialError, CredentialStore
from .dns_guard import DNSGuard, DNSGuardError, DNSResult
from .executor import (
    ExecutionConfig,
    ExecutionError,
    ExecutionRequest,
    ExecutionResult,
    HTTPExecutor,
)
from .ledger import Ledger, LedgerError
from .limits import MAX_PLAN_BYTES
from .plan import RequestPlan
from .redact import Redactor
from .scope import ScopePolicy, ScopeValidator, ScopeViolation

import httpx

LOG = logging.getLogger("broker")


class ConfigError(Exception):
    """Invalid broker configuration. Messages never contain secret values."""


class Rejected(Exception):
    """Internal: the request was refused before anything was sent."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class _Prepared:
    plan: RequestPlan
    request: ExecutionRequest
    request_hash: str
    body_bytes: int


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ============================================================
# SERVICE
# ============================================================

class BrokerService:

    def __init__(
        self,
        scope: ScopePolicy,
        credentials: Mapping[str, Credential],
        ledger: Ledger,
        executor: HTTPExecutor | None = None,
        guard: DNSGuard | None = None,
    ):
        # Configuration errors must surface as ConfigError, never as a raw
        # ValueError/CredentialError traceback from deep inside a constructor.
        try:
            self.scope = ScopeValidator(scope)
            self.store = CredentialStore(credentials)
        except ValueError as exc:
            raise ConfigError(f"Invalid scope: {exc}") from exc
        except CredentialError as exc:
            raise ConfigError(f"Invalid credentials: {exc}") from exc
        self.ledger = ledger
        self.guard = guard or DNSGuard()

        # A configured identity without credentials would fail on every plan.
        missing = set(scope.allowed_identities) - self.store.identities()
        if missing:
            raise ConfigError(
                f"Identities allowed by scope have no credentials: {sorted(missing)}"
            )

        if executor is None:
            executor = HTTPExecutor(
                ExecutionConfig(
                    allow_insecure_http=self.scope.origin.startswith("http://")
                ),
                address_policy=self.guard,
            )
        self.executor = executor

        # Scrubs every identity's secrets from anything logged or returned.
        self._redactor = Redactor.for_credentials(
            c.render() for c in credentials.values()
        )

    # --------------------------------------------------------
    # Stage 1 (pure, no I/O): plan -> scope -> credentials -> request
    # --------------------------------------------------------

    def _prepare(self, raw: bytes) -> _Prepared:

        if len(raw) > MAX_PLAN_BYTES:
            raise Rejected("invalid_plan")

        try:
            plan = RequestPlan.model_validate_json(raw)
        except ValidationError:
            raise Rejected("invalid_plan") from None

        try:
            url = self.scope.validate(plan)
        except ScopeViolation:
            raise Rejected("scope_violation") from None

        try:
            headers = self.store.apply(plan.identity, url, dict(plan.headers))
        except CredentialError:
            raise Rejected("credential_error") from None

        body: bytes | None = None
        if plan.body is not None:
            if plan.method in {"GET", "HEAD"}:
                raise Rejected("body_not_allowed")
            body = json.dumps(
                plan.body, separators=(",", ":"), allow_nan=False
            ).encode("ascii")
            if not any(k.lower() == "content-type" for k in headers):
                headers["Content-Type"] = "application/json"

        try:
            request = self.executor.build_request(plan.method, url, headers, body)
        except ExecutionError:
            raise Rejected("build_error") from None

        # scope authorized exactly `url`; exactly that is what gets sent.
        if request.url != url:
            raise Rejected("build_error")

        request_hash = hashlib.sha256(
            _canonical({"plan": plan.model_dump(mode="json"), "url": url})
        ).hexdigest()

        return _Prepared(plan, request, request_hash, len(body or b""))

    # --------------------------------------------------------
    # Public entry point
    # --------------------------------------------------------

    async def handle(self, raw: bytes) -> dict:

        raw_hash = hashlib.sha256(raw).hexdigest()

        try:
            prep = self._prepare(raw)
        except Rejected as exc:
            return await self._reject(raw_hash, exc.code)
        except Exception as exc:   # a bug must not become an unlogged request
            LOG.error("prepare_failed type=%s", type(exc).__name__)
            return await self._reject(raw_hash, "internal_error")

        # ---- DNS: resolve + validate; the executor re-validates the result.
        host = httpx.URL(prep.request.url).host
        try:
            dns = await self.guard.resolve(host)
        except DNSGuardError:
            return await self._reject(prep.request_hash, "dns_blocked", prep)
        except Exception as exc:
            LOG.error("dns_failed type=%s", type(exc).__name__)
            return await self._reject(prep.request_hash, "internal_error", prep)

        # ---- Pending record BEFORE sending. Fail closed.
        try:
            pending = await self.ledger.append_async(
                self._pending_record(prep, dns)
            )
        except LedgerError as exc:
            LOG.error("ledger_unavailable code=%s", exc)
            return {
                "outcome": "rejected",
                "code": "ledger_unavailable",
                "request_hash": prep.request_hash,
            }

        # ---- Execute. CancelledError is deliberately not caught: the
        # pending record stays dangling, which means "outcome unknown".
        try:
            result = await self.executor.execute_request(prep.request, dns)
        except ExecutionError:
            # Raised before dispatch (revalidation / closed / address policy).
            return await self._complete_failure(
                pending, prep, "not_sent", "executor_rejected", delivered=False
            )
        except Exception as exc:
            LOG.error("execute_failed type=%s", type(exc).__name__)
            return await self._complete_failure(
                pending, prep, "internal_error", "internal_error", delivered=True
            )

        return await self._complete(pending, prep, result)

    # --------------------------------------------------------
    # Ledger records
    # --------------------------------------------------------

    def _pending_record(self, prep: _Prepared, dns: DNSResult) -> dict:
        r, p = self._redactor, prep.plan
        return {
            "state": "pending",
            "request_hash": prep.request_hash,
            "request": {
                "identity": p.identity,
                "pack": p.pack,
                "method": p.method,
                "url": r.text(prep.request.url),
                "headers": r.headers(p.headers),
                "body": r.value(p.body),
                "body_bytes": prep.body_bytes,
                "expect": p.expect,
            },
            "dns": {"hostname": dns.hostname, "addresses": list(dns.addresses)},
        }

    async def _reject(
        self, request_hash: str, code: str, prep: _Prepared | None = None
    ) -> dict:
        record: dict[str, Any] = {
            "state": "rejected", "request_hash": request_hash, "code": code,
        }
        if prep is not None:
            record["request"] = {
                "identity": prep.plan.identity,
                "pack": prep.plan.pack,
                "method": prep.plan.method,
                "url": self._redactor.text(prep.request.url),
            }
        try:
            await self.ledger.append_async(record)
        except LedgerError as exc:
            LOG.error("ledger_write_failed state=rejected code=%s", exc)
        return {"outcome": "rejected", "code": code, "request_hash": request_hash}

    async def _complete(
        self, pending: dict, prep: _Prepared, result: ExecutionResult
    ) -> dict:

        expected = {int(s) for s in prep.plan.expect.split("/")}
        summary = self._redactor.response_summary(result.body, result.headers)

        if result.error_code is None:
            outcome = "response"
            expectation = "met" if result.status_code in expected else "unmet"
        else:
            # No usable response (network failure, or one refused for
            # encoding/size). Never counts as meeting or missing the expectation.
            outcome, expectation = "error", "inconclusive"

        record = {
            "state": "complete",
            "seq_pending": pending["seq"],
            "request_hash": prep.request_hash,
            "outcome": outcome,
            "status": result.status_code,
            "expect": prep.plan.expect,
            "expectation": expectation,
            "error_code": result.error_code,
            "possibly_delivered": result.request_possibly_delivered,
            "elapsed": round(result.elapsed_time, 4),
            "response": summary,
        }

        response = {
            "outcome": outcome,
            "status": result.status_code,
            "expectation": expectation,
            "error_code": result.error_code,
            "possibly_delivered": result.request_possibly_delivered,
            "request_hash": prep.request_hash,
            "digest": summary["digest"],
            "sample": summary["sample"],
            "sample_truncated": summary["sample_truncated"],
            "headers": summary["headers"],
        }

        try:
            await self.ledger.append_async(record)
        except LedgerError as exc:
            # The request WAS sent and its pending record exists; only the
            # completion is missing. Say so rather than hide it.
            LOG.error("ledger_write_failed state=complete code=%s", exc)
            response["ledger"] = "complete_not_recorded"

        return response

    async def _complete_failure(
        self, pending: dict, prep: _Prepared, outcome: str, code: str,
        *, delivered: bool,
    ) -> dict:
        record = {
            "state": "complete",
            "seq_pending": pending["seq"],
            "request_hash": prep.request_hash,
            "outcome": outcome,
            "status": None,
            "expect": prep.plan.expect,
            "expectation": "inconclusive",
            "error_code": code,
            "possibly_delivered": delivered,
        }
        response = {
            "outcome": outcome,
            "status": None,
            "expectation": "inconclusive",
            "error_code": code,
            "possibly_delivered": delivered,
            "request_hash": prep.request_hash,
        }
        try:
            await self.ledger.append_async(record)
        except LedgerError as exc:
            LOG.error("ledger_write_failed state=complete code=%s", exc)
            response["ledger"] = "complete_not_recorded"
        return response

    # --------------------------------------------------------
    # Line-oriented loop (one JSON plan per line on stdin)
    # --------------------------------------------------------

    async def serve(self, stdin: BinaryIO, stdout: BinaryIO) -> None:
        """Sequential on purpose: ledger order == request order."""
        while True:
            line, oversized = await asyncio.to_thread(
                _read_line, stdin, MAX_PLAN_BYTES
            )
            if line is None:
                break
            if oversized:
                out = await self._reject(
                    hashlib.sha256(b"oversized").hexdigest(), "invalid_plan"
                )
            elif not line.strip():
                continue
            else:
                out = await self.handle(line)
            stdout.write(json.dumps(out, separators=(",", ":")).encode() + b"\n")
            stdout.flush()

    async def close(self) -> None:
        await self.executor.close()


def _read_line(stream: BinaryIO, limit: int) -> tuple[bytes | None, bool]:
    """
    Read one line without ever buffering more than limit+2 bytes.
    Returns (None, False) at EOF, (b"", True) for an oversized line (the rest
    of which is drained), else (line_without_newline, False).
    """
    chunk = stream.readline(limit + 2)
    if not chunk:
        return None, False

    complete = chunk.endswith(b"\n")
    content = chunk.rstrip(b"\r\n")

    if len(content) > limit:
        while not complete:
            more = stream.readline(65536)
            if not more:
                break
            complete = more.endswith(b"\n")
        return b"", True

    return content, False


# ============================================================
# CONFIGURATION LOADING
# ============================================================

def _load_json_object(path: str | Path, what: str) -> dict:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"Cannot read {what} file") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{what} file must contain a JSON object")
    return data


def _str_list(data: dict, key: str) -> list[str]:
    value = data.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
    ):
        raise ConfigError(f"scope.{key} must be a non-empty list of strings")
    return value


def load_scope(path: str | Path) -> ScopePolicy:
    data = _load_json_object(path, "scope")
    allowed = {
        "base_url", "allowed_methods", "allowed_path_prefixes",
        "allowed_packs", "allowed_identities",
    }
    if set(data) != allowed:
        raise ConfigError(
            f"scope keys must be exactly {sorted(allowed)}"
        )
    if not isinstance(data["base_url"], str):
        raise ConfigError("scope.base_url must be a string")
    policy = ScopePolicy(
        base_url=data["base_url"],
        allowed_methods=frozenset(_str_list(data, "allowed_methods")),
        allowed_path_prefixes=tuple(_str_list(data, "allowed_path_prefixes")),
        allowed_packs=frozenset(_str_list(data, "allowed_packs")),
        allowed_identities=frozenset(_str_list(data, "allowed_identities")),
    )
    try:
        ScopeValidator(policy)      # ScopePolicy does not validate itself
    except ValueError as exc:
        raise ConfigError(f"Invalid scope: {exc}") from exc
    return policy


def load_credentials(
    path: str | Path,
    *,
    default_origin: str,
    allow_loose_permissions: bool = False,
) -> dict[str, Credential]:
    """
    {"user_A": {"type": "bearer", "token": "..."},
     "user_B": {"type": "cookie", "cookies": {"sid": "..."}},
     "svc":    {"type": "custom", "headers": {"X-API-Key": "..."}, "cookies": {}},
     "anon":   {"type": "anonymous"}}

    Each entry may add "origins": [...]; the default is the scope's origin.
    """
    p = Path(path)
    try:
        mode = p.stat().st_mode
    except OSError as exc:
        raise ConfigError("Cannot read credentials file") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO) and not allow_loose_permissions:
        raise ConfigError(
            "Credentials file is readable by group/others; run chmod 600 "
            "(on WSL /mnt/c use --allow-loose-file-perms, or keep the file "
            "inside the Linux filesystem)"
        )

    data = _load_json_object(p, "credentials")
    out: dict[str, Credential] = {}

    for identity, spec in data.items():
        if not isinstance(spec, dict) or "type" not in spec:
            raise ConfigError(f"Credential '{identity}' needs a 'type'")
        spec = dict(spec)
        kind = spec.pop("type")
        origins = spec.pop("origins", [default_origin])
        insecure = any(
            isinstance(o, str) and o.startswith("http://") for o in origins
        ) if isinstance(origins, list) else False
        try:
            if kind == "anonymous" and not spec:
                out[identity] = Credential.anonymous()
            elif kind == "bearer" and set(spec) == {"token"}:
                out[identity] = Credential.bearer(
                    spec["token"], origins, allow_insecure=insecure)
            elif kind == "cookie" and set(spec) == {"cookies"}:
                out[identity] = Credential.cookie(
                    spec["cookies"], origins, allow_insecure=insecure)
            elif kind == "custom" and set(spec) <= {"headers", "cookies"} and "headers" in spec:
                out[identity] = Credential.custom(
                    spec["headers"], origins, spec.get("cookies"),
                    allow_insecure=insecure)
            else:
                raise ConfigError(f"Credential '{identity}' has an invalid shape")
        except CredentialError as exc:
            raise ConfigError(f"Credential '{identity}' is invalid: {exc}") from exc

    if not out:
        raise ConfigError("Credentials file is empty")
    return out


# ============================================================
# CLI
# ============================================================

async def _run(args: argparse.Namespace) -> None:
    scope = load_scope(args.scope)
    credentials = load_credentials(
        args.credentials,
        default_origin=scope.base_url,
        allow_loose_permissions=args.allow_loose_file_perms,
    )
    ledger = Ledger(args.ledger, args.signing_key)
    guard = DNSGuard(
        allow_private=args.allow_private,
        allow_loopback=args.allow_loopback,
    )
    service = BrokerService(scope, credentials, ledger, guard=guard)

    for entry in ledger.unfinished_pending():
        LOG.warning(
            "unfinished_pending seq=%s request_hash=%s outcome=unknown",
            entry["seq"], entry["request_hash"],
        )

    try:
        await service.serve(sys.stdin.buffer, sys.stdout.buffer)
    finally:
        await service.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="broker")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--signing-key", default="/etc/broker/keys/ledger_signing.key")
    parser.add_argument("--allow-loopback", action="store_true",
                        help="permit 127.0.0.0/8 targets (lab use)")
    parser.add_argument("--allow-private", action="store_true",
                        help="permit RFC1918 targets (lab use)")
    parser.add_argument("--allow-loose-file-perms", action="store_true",
                        help="skip the credentials-file permission check (WSL /mnt/c)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    try:
        asyncio.run(_run(args))
    except (ConfigError, LedgerError) as exc:
        print(f"startup error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
