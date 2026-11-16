"""
executor.py

Constructs and executes HTTP requests under broker-controlled limits,
connecting only to DNS-validated, pinned IP addresses.

Responsibilities:
    - Validate executor-level request properties (canonical form).
    - Re-validate the DNS result's addresses against the address policy.
    - Enforce a total execution deadline (including queueing).
    - Bound request and response sizes; never decode or follow redirects.
    - Report whether a request may have reached the server.

Contract:
    * Expected network failures RETURN an ExecutionResult.
    * Invalid requests / DNS results and programming errors RAISE.
    * Cancellation is never swallowed.

Other modules: plan.py (structure), scope.py (authorization; must authorize
the exact string in ExecutionRequest.url), credentials.py, redact.py,
ledger.py, dns_guard.py, pinned_transport.py, service.py (orchestration).

SECURITY: also enforce destination-IP restrictions at the network egress
boundary. This process is one layer, not the only one.

Requires Python >= 3.11 (asyncio.timeout).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import time

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

import httpx

from broker.src.dns_guard import DNSGuard, DNSGuardError, DNSResult
from broker.src.limits import (
    MAX_BODY_BYTES,
    MAX_HEADER_COUNT,
    MAX_HEADER_NAME_LENGTH,
    MAX_HEADER_VALUE_LENGTH,
    MAX_RESPONSE_BYTES,
)
from broker.src.pinned_transport import (
    PinnedHTTPTransport,
    PinnedTransportError,
    normalize_hostname,
)


# ============================================================
# EXCEPTIONS
# ============================================================

class ExecutionError(Exception):
    """Base executor exception."""


class RequestBuildError(ExecutionError):
    """Invalid outgoing request or DNS result."""


class ExecutorClosedError(ExecutionError):
    """Executor has been closed."""


# ============================================================
# CONSTANTS
# ============================================================

HTTP_TOKEN_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Legacy IPv4 spellings (2130706433, 0x7f.1, 017700000001) are parsed
# differently by different components. Reject anything numeric-looking that
# is not a canonical IP literal.
_NUMERIC_LOOKING_HOST = re.compile(r"^[0-9a-fx.]+$", re.IGNORECASE)

ALLOWED_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
)

FORBIDDEN_HEADERS = frozenset({
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "accept-encoding",
})

MAX_URL_LENGTH = 8192


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass(frozen=True)
class ExecutionConfig:
    """Broker-controlled limits. Never agent-controlled."""

    timeout_seconds: float = 15.0
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_request_bytes: int = MAX_BODY_BYTES
    max_concurrent_requests: int = 10
    allow_insecure_http: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not 0 < self.timeout_seconds <= 120
        ):
            raise ValueError("Invalid timeout")

        for name in (
            "max_response_bytes",
            "max_request_bytes",
            "max_concurrent_requests",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"Invalid {name}")

        if type(self.allow_insecure_http) is not bool:
            raise ValueError("allow_insecure_http must be boolean")


# ============================================================
# REQUEST / RESULT MODELS
# ============================================================

@dataclass(frozen=True, repr=False)
class ExecutionRequest:
    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "headers", MappingProxyType(dict(self.headers))
        )

    def __repr__(self) -> str:
        return (
            f"ExecutionRequest(method={self.method!r}, url={self.url!r}, "
            f"headers=<redacted>, body=<redacted>)"
        )


@dataclass(frozen=True, repr=False)
class ExecutionResult:
    """
    Outcome of an execution.

    transport_success: a response was received and nothing went wrong.
    http_success:      transport_success and a 2xx status.

    request_possibly_delivered:
        False -> the request provably never reached the server (pin/DNS
                 policy failure, connect failure, TLS failure, pool/queue
                 timeout, deadline hit while queued). Safe to retry.
        True  -> the server may have received and acted on it (timeouts
                 mid-flight, protocol errors, any response). The ledger
                 must record this as "outcome unknown", never "failed".
    """

    status_code: int | None
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    elapsed_time: float
    error_code: str | None = None
    error_message: str | None = None
    request_possibly_delivered: bool = False

    @property
    def received_response(self) -> bool:
        return self.status_code is not None

    @property
    def transport_success(self) -> bool:
        return self.received_response and self.error_code is None

    @property
    def http_success(self) -> bool:
        return (
            self.transport_success
            and self.status_code is not None
            and 200 <= self.status_code < 300
        )

    def __repr__(self) -> str:
        return (
            f"ExecutionResult(status_code={self.status_code!r}, "
            f"elapsed_time={self.elapsed_time:.4f}, "
            f"error_code={self.error_code!r}, "
            f"possibly_delivered={self.request_possibly_delivered}, "
            f"body=<redacted>)"
        )


# ============================================================
# HELPERS
# ============================================================

def _is_tls_verification_error(exc: BaseException) -> bool:
    """
    True if a certificate-verification failure is in the exception chain.

    Follows __cause__ AND __context__: httpcore attaches the original
    ssl.SSLCertVerificationError as __context__ of its ConnectError, not as
    __cause__ (verified against a real TLS handshake; see
    test_https_untrusted_cert_rejected_by_default). Following only __cause__
    would report every TLS failure as a generic connection error.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        current = current.__cause__ or current.__context__
    return False


def _host_is_ambiguous(host: str) -> bool:
    bare = host.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return False
    except ValueError:
        pass
    return bool(_NUMERIC_LOOKING_HOST.fullmatch(bare))


class _Dispatch:
    """Tracks whether the request was handed to the HTTP client."""

    __slots__ = ("started",)

    def __init__(self) -> None:
        self.started = False


# ============================================================
# EXECUTOR
# ============================================================

class HTTPExecutor:

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        address_policy: DNSGuard | None = None,
    ) -> None:
        """
        address_policy: the DNSGuard whose rules every pinned address must
        satisfy. Defaults to the strict policy (no private, loopback,
        link-local or reserved addresses).
        """
        self.config = config or ExecutionConfig()
        self._address_policy = address_policy or DNSGuard()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        self._closed = False
        self._active_requests = 0
        self._idle_event = asyncio.Event()
        self._idle_event.set()
        self._close_task: asyncio.Task[None] | None = None

    # --------------------------------------------------------
    # Transport factory. Tests override this in a subclass; nothing in the
    # public constructor accepts a transport.
    # --------------------------------------------------------

    def _make_transport(self, dns_result: DNSResult) -> httpx.AsyncBaseTransport:
        return PinnedHTTPTransport(dns_result)

    # --------------------------------------------------------
    # Build / validate
    # --------------------------------------------------------

    def build_request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
    ) -> ExecutionRequest:

        if self._closed:
            raise ExecutorClosedError("Executor is closed")

        # METHOD
        if not isinstance(method, str) or not HTTP_TOKEN_PATTERN.fullmatch(method):
            raise RequestBuildError("Invalid HTTP method")
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise RequestBuildError("HTTP method not permitted")

        # URL
        if (
            not isinstance(url, str)
            or not url
            or url != url.strip()
            or len(url) > MAX_URL_LENGTH
        ):
            raise RequestBuildError("Invalid URL")

        try:
            parsed = httpx.URL(url)
        except (httpx.InvalidURL, ValueError):
            raise RequestBuildError("Invalid URL") from None

        if parsed.scheme not in {"http", "https"}:
            raise RequestBuildError("Unsupported URL scheme")
        if not parsed.host:
            raise RequestBuildError("Missing hostname")
        if _host_is_ambiguous(parsed.host):
            raise RequestBuildError("Ambiguous numeric hostname")
        if parsed.username or parsed.password:
            raise RequestBuildError("URL credentials are forbidden")
        if parsed.fragment:
            raise RequestBuildError("URL fragments are forbidden")
        if parsed.scheme == "http" and not self.config.allow_insecure_http:
            raise RequestBuildError("Plain HTTP is disabled")

        # HEADERS
        if headers is None:
            headers = {}
        if not isinstance(headers, Mapping):
            raise RequestBuildError("Headers must be a mapping")
        if len(headers) > MAX_HEADER_COUNT + 2:  # + Cookie, + one auth header
            raise RequestBuildError("Too many headers")

        clean: dict[str, str] = {}
        seen: set[str] = set()

        for name, value in headers.items():
            if (
                not isinstance(name, str)
                or not name
                or len(name) > MAX_HEADER_NAME_LENGTH
                or not HTTP_TOKEN_PATTERN.fullmatch(name)
            ):
                raise RequestBuildError("Invalid header name")
            if not isinstance(value, str):
                raise RequestBuildError("Header value must be a string")
            if len(value) > MAX_HEADER_VALUE_LENGTH:
                raise RequestBuildError("Header value too long")
            if not value.isascii():
                raise RequestBuildError("Non-ASCII header values are forbidden")
            if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
                raise RequestBuildError("Invalid control character in header")

            lowered = name.lower()
            if lowered in seen:
                raise RequestBuildError("Duplicate header")
            if lowered in FORBIDDEN_HEADERS:
                raise RequestBuildError(f"Forbidden header: {name}")
            seen.add(lowered)
            clean[name] = value

        # BODY
        if body is not None and not isinstance(body, bytes):
            raise RequestBuildError("Body must be bytes or None")
        if body is not None and len(body) > self.config.max_request_bytes:
            raise RequestBuildError("Request body too large")

        return ExecutionRequest(
            method=method, url=str(parsed), headers=clean, body=body
        )

    def _validate_request(self, request: ExecutionRequest) -> ExecutionRequest:
        """Re-run build_request and require an identical result."""

        if not isinstance(request, ExecutionRequest):
            raise RequestBuildError("Invalid request object")

        validated = self.build_request(
            request.method, request.url, request.headers, request.body
        )

        # scope.py authorized exactly request.url / request.method.
        # Revalidation must never silently change what gets sent.
        if (
            validated.method != request.method
            or validated.url != request.url
            or dict(validated.headers) != dict(request.headers)
            or validated.body != request.body
        ):
            raise RequestBuildError("Request is not in canonical form")

        return validated

    def _check_dns_result(
        self, request: ExecutionRequest, dns_result: DNSResult
    ) -> DNSResult:
        """
        The DNSResult must (a) satisfy the address policy and (b) belong to
        this request's host. A hand-built DNSResult is rejected here, so the
        guard cannot be bypassed by forging one.
        """

        if not isinstance(dns_result, DNSResult):
            raise RequestBuildError("A validated DNSResult is required")

        try:
            validated = self._address_policy.validate_result(dns_result)
            same_host = (
                normalize_hostname(dns_result.hostname)
                == normalize_hostname(httpx.URL(request.url).host)
            )
        except DNSGuardError:
            raise RequestBuildError(
                "DNS result violates the address policy"
            ) from None
        except PinnedTransportError:
            raise RequestBuildError("Invalid DNS result hostname") from None

        if not same_host:
            raise RequestBuildError(
                "DNS result hostname does not match request URL"
            )

        return validated

    # --------------------------------------------------------
    # Execute
    # --------------------------------------------------------

    async def execute_request(
        self,
        request: ExecutionRequest,
        dns_result: DNSResult,
    ) -> ExecutionResult:

        if self._closed:
            raise ExecutorClosedError("Executor is closed")

        start = time.monotonic()
        request = self._validate_request(request)
        dns_result = self._check_dns_result(request, dns_result)
        dispatch = _Dispatch()

        # No await between the closed check above and this increment.
        self._active_requests += 1
        self._idle_event.clear()

        try:
            # One deadline covering queueing + connect + send + read.
            async with asyncio.timeout(self.config.timeout_seconds):
                async with self._semaphore:
                    return await self._send_request(
                        request, dns_result, start, dispatch
                    )

        except TimeoutError:
            return self._error(
                "timeout", "Total execution deadline exceeded", start,
                delivered=dispatch.started,
            )
        except PinnedTransportError:
            return self._error(
                "dns_pin_error",
                "Could not safely establish the pinned connection",
                start, delivered=False,
            )
        except httpx.ConnectTimeout:
            return self._error(
                "connect_timeout", "Connection timed out", start, delivered=False
            )
        except httpx.PoolTimeout:
            return self._error(
                "pool_timeout", "Connection pool timeout", start, delivered=False
            )
        except httpx.ReadTimeout:
            return self._error(
                "read_timeout", "Response read timed out", start, delivered=True
            )
        except httpx.WriteTimeout:
            return self._error(
                "write_timeout", "Request write timed out", start, delivered=True
            )
        except httpx.ConnectError as exc:
            if _is_tls_verification_error(exc):
                return self._error(
                    "tls_verification_failed",
                    "TLS certificate verification failed",
                    start, delivered=False,
                )
            return self._error(
                "connection_error", "Could not establish connection",
                start, delivered=False,
            )
        except httpx.RequestError:
            return self._error(
                "request_error", "HTTP request failed", start,
                delivered=dispatch.started,
            )
        finally:
            self._active_requests -= 1
            if self._active_requests == 0:
                self._idle_event.set()

    async def _send_request(
        self,
        request: ExecutionRequest,
        dns_result: DNSResult,
        start: float,
        dispatch: _Dispatch,
    ) -> ExecutionResult:

        # The transport connects only to addresses in the validated result.
        transport = self._make_transport(dns_result)

        # Each request owns its client and transport.
        async with httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            trust_env=False,
            timeout=self.config.timeout_seconds,
            headers={"Accept-Encoding": "identity"},
        ) as client:

            dispatch.started = True

            async with client.stream(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                content=request.body,
                follow_redirects=False,
            ) as response:

                status = response.status_code
                headers = tuple(response.headers.multi_items())

                def result(
                    body: bytes | None,
                    code: str | None = None,
                    message: str | None = None,
                ) -> ExecutionResult:
                    return ExecutionResult(
                        status_code=status,
                        headers=headers,
                        body=body,
                        elapsed_time=time.monotonic() - start,
                        error_code=code,
                        error_message=message,
                        request_possibly_delivered=True,
                    )

                # Never hand compressed bytes downstream: redaction must see
                # readable content.
                encoding = response.headers.get("content-encoding", "identity")
                if encoding.strip().lower() not in {"", "identity"}:
                    return result(
                        None, "unexpected_content_encoding",
                        "Non-identity response encoding is not supported",
                    )

                # No body for these; Content-Length may describe a different
                # representation.
                if request.method == "HEAD" or status in {204, 304}:
                    return result(b"")

                declared = response.headers.get("content-length")
                if declared is not None:
                    try:
                        declared_size = int(declared)
                    except ValueError:
                        return result(
                            None, "invalid_content_length",
                            "Malformed Content-Length header",
                        )
                    if declared_size < 0:
                        return result(
                            None, "invalid_content_length",
                            "Negative Content-Length header",
                        )
                    if declared_size > self.config.max_response_bytes:
                        return result(
                            None, "response_too_large",
                            "Declared response size exceeds limit",
                        )

                # The single production read path: bounded, raw, streamed.
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > self.config.max_response_bytes:
                        return result(
                            None, "response_too_large",
                            "Response exceeded size limit",
                        )
                    body.extend(chunk)

                return result(bytes(body))

    @staticmethod
    def _error(
        code: str, message: str, start: float, *, delivered: bool
    ) -> ExecutionResult:
        return ExecutionResult(
            status_code=None,
            headers=(),
            body=None,
            elapsed_time=time.monotonic() - start,
            error_code=code,
            error_message=message,
            request_possibly_delivered=delivered,
        )

    # --------------------------------------------------------
    # Shutdown
    # --------------------------------------------------------

    async def close(self) -> None:
        """
        Stop accepting requests and wait for in-flight ones (bounded by
        their deadline). Idempotent, safe to call concurrently; a cancelled
        caller does not abort the shutdown.
        """
        self._closed = True
        if self._close_task is None:
            self._close_task = asyncio.ensure_future(self._idle_event.wait())
        await asyncio.shield(self._close_task)

    async def __aenter__(self) -> "HTTPExecutor":
        if self._closed:
            raise ExecutorClosedError("Executor is closed")
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()
