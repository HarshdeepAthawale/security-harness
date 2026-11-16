"""
KernelBroker: synchronous kernel interface to the asynchronous BrokerService.

Security boundaries:
    1. Kernel Contract: per-run authorization.
    2. Broker ScopePolicy: static authorization.
    3. CredentialStore: origin-bound authentication.
    4. DNSGuard: destination validation.
    5. HTTPExecutor: pinned-address execution.
    6. Signed broker ledger: execution audit trail.
    7. Kernel LedgerEntry: assessment record.

The broker service is the only component that sends HTTP requests.
"""

from __future__ import annotations

import asyncio
import fnmatch
import json
import re
import threading

from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from broker.src.errors import BrokerError
from broker.src.plan import RequestPlan as BrokerPlan
from broker.src.scope import ScopeViolation
from broker.src.service import BrokerService

from kernel.models import Contract, LedgerEntry, RequestPlan


# ============================================================
# HELPERS
# ============================================================

def expected_statuses(text: str) -> str:
    """
    Convert human-readable expectations into the numeric format
    required by BrokerService.

    Examples:
        attack: 403 or 404             -> 403/404
        baseline: 200 with user data   -> 200
        no codes here                  -> 200
    """

    if not isinstance(text, str):
        return "200"

    codes = re.findall(
        r"(?<!\d)([1-5]\d\d)(?!\d)",
        text,
    )

    if not codes:
        return "200"

    return "/".join(dict.fromkeys(codes))


def challenge_flags(result: dict) -> list[str]:
    """
    Identify strong bot-protection signals.

    Ordinary mentions of CAPTCHA or HTTP 403 are not sufficient.
    """

    if not isinstance(result, dict):
        return []

    status = result.get("status", result.get("status_code"))
    sample = result.get("sample", "")

    if not isinstance(sample, str):
        sample = ""

    headers = result.get("headers", {})

    if isinstance(headers, list):
        normalized_headers = {
            str(key).lower(): str(value).lower()
            for key, value in headers
        }
    elif isinstance(headers, dict):
        normalized_headers = {
            str(key).lower(): str(value).lower()
            for key, value in headers.items()
        }
    else:
        normalized_headers={}

    if normalized_headers.get("cf-mitigated") == "challenge":
        return ["bot_challenge"]

    lowered = sample.lower()

    challenge_markers = (
        "<title>just a moment",
        "checking your browser",
        "please complete the captcha",
        "verify you are human",
    )

    if any(marker in lowered for marker in challenge_markers):
        return ["bot_challenge"]

    if status in {403, 503} and (
        "captcha" in lowered
        or "challenge-platform" in lowered
        or "cloudflare" in lowered
    ):
        return ["bot_challenge"]

    return []


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class IdentityProbe:
    """
    Explicit application identity verification configuration.

    The identity must have an anonymous credential configured.
    The probe path and pack must be authorized by Broker ScopePolicy.
    """

    identity: str
    path: str
    pack: str
    marker: str
    expected_status: int = 200

    def __post_init__(self):
        if not self.identity:
            raise ValueError("Probe identity is required")

        if not self.path.startswith("/"):
            raise ValueError("Probe path must be absolute")

        if not self.pack or not self.marker:
            raise ValueError("Probe pack and marker are required")

        if not 100 <= self.expected_status <= 599:
            raise ValueError("Invalid expected status")


# ============================================================
# BROKER
# ============================================================

class KernelBroker:
    """
    Synchronous implementation of the kernel Broker protocol.

    BrokerService is constructed and used exclusively on a dedicated
    asyncio event-loop thread.

    service_factory must construct a fresh BrokerService and all
    its dependencies when called.
    """

    def __init__(
        self,
        service_factory: Callable[[], BrokerService],
        *,
        identity_probe: IdentityProbe | None = None,
        operation_timeout: float = 60.0,
    ):

        if not callable(service_factory):
            raise TypeError("service_factory must be callable")

        if operation_timeout <= 0:
            raise ValueError("operation_timeout must be positive")

        self._factory = service_factory
        self._identity_probe = identity_probe
        self._timeout = operation_timeout

        self._loop = None
        self._service = None
        self._origin = None

        self._ready = threading.Event()
        self._startup_error = None

        self._closed = False
        self._lock = threading.RLock()

        self._thread = threading.Thread(
            target=self._thread_main,
            name="kernel-broker-loop",
            daemon=True,
        )

        self._thread.start()

        if not self._ready.wait(timeout=self._timeout):
            raise BrokerError("broker_startup_timeout")

        if self._startup_error is not None:
            raise BrokerError("broker_startup_failed") from self._startup_error

        future = asyncio.run_coroutine_threadsafe(
            self._initialize(),
            self._loop,
        )

        try:
            future.result(timeout=self._timeout)

        except Exception as exc:
            self.close()
            raise BrokerError("broker_initialization_failed") from exc

    # --------------------------------------------------------
    # EVENT LOOP
    # --------------------------------------------------------

    def _thread_main(self):

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        self._loop = loop
        self._ready.set()

        try:
            loop.run_forever()

        finally:
            pending = asyncio.all_tasks(loop)

            for task in pending:
                task.cancel()

            if pending:
                loop.run_until_complete(
                    asyncio.gather(
                        *pending,
                        return_exceptions=True,
                    )
                )

            loop.close()

    async def _initialize(self):

        # Construction occurs inside the event-loop thread.
        self._service = self._factory()

        if not isinstance(self._service, BrokerService):
            raise TypeError(
                "Factory must return a BrokerService instance"
            )

        self._origin = self._normalize_origin(
            self._service.scope.origin
        )

    @staticmethod
    def _normalize_origin(origin: str) -> str:

        parsed = urlsplit(origin)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise BrokerError("invalid_broker_origin")

        if not parsed.hostname:
            raise BrokerError("invalid_broker_origin")

        if parsed.username or parsed.password:
            raise BrokerError("invalid_broker_origin")

        if parsed.path not in {"", "/"}:
            raise BrokerError("invalid_broker_origin")

        if parsed.query or parsed.fragment:
            raise BrokerError("invalid_broker_origin")

        try:
            port = parsed.port
        except ValueError as exc:
            raise BrokerError("invalid_broker_origin") from exc

        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower()

        if ":" in host:
            host = f"[{host}]"

        if port is None:
            port = 443 if scheme == "https" else 80

        return f"{scheme}://{host}:{port}"

    # --------------------------------------------------------
    # ASYNC BRIDGE
    # --------------------------------------------------------

    def _submit(self, coroutine):

        with self._lock:

            if self._closed:
                coroutine.close()
                raise BrokerError("broker_closed")

            future = asyncio.run_coroutine_threadsafe(
                coroutine,
                self._loop,
            )

            try:
                return future.result(timeout=self._timeout)
            except FutureTimeout as exc:
                raise BrokerError(
                    "broker_outcome_unknown"
                ) from exc

    async def _handle(self, raw: bytes):
        return await self._service.handle(raw)

    # --------------------------------------------------------
    # CONTRACT VALIDATION
    # --------------------------------------------------------

    def _check_contract(
        self,
        plan: RequestPlan,
        contract: Contract,
    ):

        if contract.compute_hash() != contract.contract_hash:
            raise BrokerError("contract_integrity_failure")

        allowed_origins = {
            self._normalize_origin(origin)
            for origin in contract.allowed_origins
        }

        if self._origin not in allowed_origins:
            raise BrokerError("contract_origin_violation")

        parsed = urlsplit(self._origin)

        if parsed.hostname.lower() != contract.target.lower():
            raise BrokerError("contract_target_mismatch")

        if plan.method.upper() not in {
            method.upper()
            for method in contract.allowed_methods
        }:
            raise BrokerError("contract_method_violation")

        if plan.identity not in contract.identities:
            raise BrokerError("contract_identity_violation")

        if not any(
            fnmatch.fnmatchcase(plan.path, pattern)
            for pattern in contract.allowed_paths
        ):
            raise BrokerError("contract_path_violation")

    # --------------------------------------------------------
    # PLAN TRANSLATION
    # --------------------------------------------------------

    @staticmethod
    def _serialize_plan(plan: RequestPlan) -> bytes:

        payload = {
            "identity": plan.identity,
            "method": plan.method.upper(),
            "path": plan.path,
            "headers": dict(plan.headers),
            "query": dict(plan.query),
            "body": plan.body,
            "pack": plan.pack,
            "expect": expected_statuses(plan.expect),
        }

        return json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _prepare_and_validate(
        self,
        plan: RequestPlan,
        contract: Contract,
    ):

        self._check_contract(plan, contract)

        raw = self._serialize_plan(plan)

        # Validate using the broker's own Pydantic model.
        broker_plan = BrokerPlan.model_validate_json(raw)

        # Independently run the actual broker ScopeValidator.
        # No HTTP request has been sent at this point.
        canonical_url = self._service.scope.validate(broker_plan)

        return raw, canonical_url

    # --------------------------------------------------------
    # RESPONSE MAPPING
    # --------------------------------------------------------

    @staticmethod
    def _make_entry(
        plan: RequestPlan,
        contract: Contract,
        canonical_url: str,
        result: dict,
    ) -> LedgerEntry:

        if not isinstance(result, dict):
            raise BrokerError("invalid_broker_response")

        outcome = result.get("outcome")

        if outcome == "rejected":
            # The broker refused the request before execution.
            raise BrokerError(
                str(result.get("code", "broker_rejected"))
            )

        status = result.get("status")

        if status is not None:
            if not isinstance(status, int) or isinstance(status, bool):
                raise BrokerError("invalid_broker_status")

        request_hash = result.get("request_hash")

        if not isinstance(request_hash, str) or not request_hash:
            raise BrokerError("missing_request_hash")

        digest = result.get("digest")

        if digest is not None:
            if not isinstance(digest, str) or len(digest) != 64:
                raise BrokerError("invalid_response_digest")

        flags = challenge_flags(result)

        if outcome != "response":
            flags.append(f"broker_outcome:{outcome}")

        if result.get("possibly_delivered"):
            flags.append("possibly_delivered")

        if result.get("ledger") == "complete_not_recorded":
            flags.append("broker_ledger_incomplete")

        return LedgerEntry(
            run_id=contract.run_id,
            request_hash=request_hash,
            method=plan.method.upper(),
            url=canonical_url,
            status_code=status,
            resp_digest=digest,
            identity_id=plan.identity,
            flags=flags,
        )

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    def send(
        self,
        plan: RequestPlan,
        contract: Contract,
    ) -> LedgerEntry:

        raw, canonical_url = self._prepare_and_validate(
            plan,
            contract,
        )

        result = self._submit(
            self._handle(raw)
        )

        return self._make_entry(
            plan,
            contract,
            canonical_url,
            result,
        )

    # --------------------------------------------------------
    # IDENTITY VERIFICATION
    # --------------------------------------------------------

    def check_identity(self, contract: Contract) -> bool:

        probe = self._identity_probe

        if probe is None:
            return False

        # A missing or unauthorized probe must never trigger traffic.
        if probe.identity not in contract.identities:
            return False

        probe_plan = RequestPlan(
            unit_id="identity-probe",
            identity=probe.identity,
            method="GET",
            path=probe.path,
            headers={},
            query={},
            body=None,
            pack=probe.pack,
            expect=str(probe.expected_status),
        )

        try:
            raw, canonical_url = self._prepare_and_validate(
                probe_plan,
                contract,
            )

        except ScopeViolation:
            return False

        result = self._submit(
            self._handle(raw)
        )

        if not isinstance(result, dict):
            raise BrokerError("invalid_identity_probe_response")

        if result.get("outcome") != "response":
            return False

        if result.get("status") != probe.expected_status:
            return False

        sample = result.get("sample")

        if not isinstance(sample, str):
            return False

        return probe.marker in sample

    # --------------------------------------------------------
    # SHUTDOWN
    # --------------------------------------------------------

    def close(self):

        with self._lock:

            if self._closed:
                return

            self._closed = True

            if self._service is not None and self._loop.is_running():

                async def shutdown():
                    await self._service.close()

                future = asyncio.run_coroutine_threadsafe(
                    shutdown(),
                    self._loop,
                )

                try:
                    future.result(timeout=self._timeout)

                finally:
                    self._loop.call_soon_threadsafe(
                        self._loop.stop
                    )

            elif self._loop is not None and self._loop.is_running():

                self._loop.call_soon_threadsafe(
                    self._loop.stop
                )

        if self._thread.is_alive():
            self._thread.join(timeout=self._timeout)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()