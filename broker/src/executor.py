from __future__ import annotations
import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit
from .credentials import get_credential
from .dns_guard import resolve_pinned
from .limits import CONNECT_TIMEOUT_SECONDS, MAX_RESPONSE_BYTES, READ_TIMEOUT_SECONDS
from .plan import ValidatedRequest
from .redact import response_summary


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = str(address)
    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class PinnedHTTPSConnection(PinnedHTTPConnection):
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host)


def execute(request: ValidatedRequest, resolver=socket.getaddrinfo) -> dict:
    if not isinstance(request, ValidatedRequest): raise TypeError("ValidatedRequest required")
    request.verify()
    addresses = resolve_pinned(request._scope, resolver)
    address = addresses[0]
    u = urlsplit(request.url)
    cls = PinnedHTTPSConnection if u.scheme == "https" else PinnedHTTPConnection
    conn = cls(request._scope.host, request._scope.port, address, CONNECT_TIMEOUT_SECONDS)
    headers = dict(request.headers)
    headers["Host"] = u.netloc
    headers["Authorization"] = "Bearer " + get_credential(request.identity)
    headers["Connection"] = "close"
    try:
        conn.request(request.method, u.path + (("?" + u.query) if u.query else ""), body=request.body, headers=headers)
        if conn.sock: conn.sock.settimeout(READ_TIMEOUT_SECONDS)
        response = conn.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES: raise ValueError("response_too_large")
        return {"status": response.status, **response_summary(body, dict(response.getheaders()))}
    finally:
        conn.close()