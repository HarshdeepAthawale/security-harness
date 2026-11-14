from __future__ import annotations
import http.client
import socket
import ssl
import threading
from urllib.parse import urlsplit
from . import limits
from .credentials import get_credential
from .dns_guard import resolve_pinned
from .errors import BrokerError
from .redact import response_summary
from .scope import ValidatedRequest


class PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to an address the DNS guard already approved, never to a name."""

    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = str(address)
        # Our own handle on the socket. With "Connection: close", http.client
        # hands the socket to the response and sets self.sock to None, so the
        # deadline watchdog can't rely on self.sock still being there.
        self.raw_sock = None

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)
        self.raw_sock = self.sock


class PinnedHTTPSConnection(PinnedHTTPConnection):
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)
        self.raw_sock = self.sock


def _abort(conn: PinnedHTTPConnection) -> None:
    """Unblock a read stuck on a slow server. shutdown() wakes a blocked recv
    on Windows and Linux; close() from another thread does not on Windows."""
    try:
        if conn.raw_sock is not None:
            conn.raw_sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


def _headers_for(request: ValidatedRequest, netloc: str) -> tuple[dict, str | None]:
    """Plan headers + the ones the broker owns. A plan-supplied Host (only
    possible when the scope allows an override) REPLACES the default Host:
    sending both puts two Host headers on the wire."""
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    override = next((v for k, v in request.headers.items() if k.lower() == "host"), None)
    headers["Host"] = override or netloc
    headers["Connection"] = "close"

    credential = None
    if request.identity is not None:                    # the readiness probe has no identity
        credential = get_credential(request.identity)
        headers["Authorization"] = "Bearer " + credential
    return headers, credential


def execute(request: ValidatedRequest, resolver=socket.getaddrinfo) -> dict:
    """Send one validated request. Raises BrokerError with a stable code on any
    network failure; never returns partial data."""
    if not isinstance(request, ValidatedRequest):
        raise TypeError("ValidatedRequest required")
    request.verify()

    addresses = resolve_pinned(request.target, resolver)
    u = urlsplit(request.url)
    headers, credential = _headers_for(request, u.netloc)

    cls = PinnedHTTPSConnection if u.scheme == "https" else PinnedHTTPConnection
    conn = cls(request.target.host, request.target.port, addresses[0], limits.CONNECT_TIMEOUT_SECONDS)

    timed_out = threading.Event()

    def on_deadline():
        timed_out.set()
        _abort(conn)

    watchdog = threading.Timer(limits.TOTAL_TIMEOUT_SECONDS, on_deadline)
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request(request.method, u.path + (("?" + u.query) if u.query else ""),
                     body=request.body, headers=headers)
        if conn.sock:
            conn.sock.settimeout(limits.READ_TIMEOUT_SECONDS)
        response = conn.getresponse()

        body = b""
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            body += chunk
            if len(body) > limits.MAX_RESPONSE_BYTES:
                raise BrokerError("response_too_large")

        # http.client hands back whatever arrived when a connection is cut,
        # without an error. A half body would get a digest that looks like a
        # real response, so check we got everything the server promised.
        if timed_out.is_set():
            raise BrokerError("upstream_timeout")
        if response.length:
            raise BrokerError("upstream_truncated")

        return {"status": response.status,
                **response_summary(body, dict(response.getheaders()),
                                   secrets=(credential,) if credential else ())}

    except BrokerError:
        raise
    except (TimeoutError, socket.timeout) as exc:
        raise BrokerError("upstream_timeout") from exc
    except ssl.SSLError as exc:
        raise BrokerError("upstream_tls_error") from exc
    except (OSError, http.client.HTTPException) as exc:
        raise BrokerError("upstream_timeout" if timed_out.is_set() else "upstream_error") from exc
    finally:
        watchdog.cancel()
        conn.close()
