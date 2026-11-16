from __future__ import annotations

import contextlib
import ipaddress
import ssl
from collections.abc import AsyncIterator

import httpcore
import httpx

from broker.src.dns_guard import DNSResult

# Own httpcore -> httpx exception mapping. httpx's helper lives in a private
# module (httpx._transports.default) that can change between releases.
# Order matters: most specific first.
_EXCEPTION_MAP = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.TimeoutException, httpx.TimeoutException),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.ProtocolError, httpx.ProtocolError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
    (httpcore.ProxyError, httpx.ProxyError),
)


@contextlib.contextmanager
def map_httpcore_exceptions():
    try:
        yield
    except Exception as exc:
        for core_type, httpx_type in _EXCEPTION_MAP:
            if isinstance(exc, core_type):
                raise httpx_type(str(exc)) from exc
        raise


class PinnedTransportError(Exception):
    """Invalid DNS-to-request binding."""


def normalize_hostname(hostname: str) -> str:
    if not isinstance(hostname, str) or not hostname:
        raise PinnedTransportError("Invalid hostname")

    hostname = hostname.rstrip(".").lower()

    try:
        return str(ipaddress.ip_address(hostname))
    except ValueError:
        pass

    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        raise PinnedTransportError("Invalid hostname") from None


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):

    def __init__(self, dns_result: DNSResult):

        if not isinstance(dns_result, DNSResult):
            raise TypeError("Expected DNSResult")

        self.hostname = normalize_hostname(dns_result.hostname)

        if not dns_result.addresses:
            raise PinnedTransportError("No validated IP addresses")

        addresses = []

        for address in dns_result.addresses:

            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                raise PinnedTransportError(
                    "Invalid IP in DNS result"
                ) from None

            if (
                    isinstance(ip, ipaddress.IPv6Address)
                    and ip.scope_id is not None
            ):
                raise PinnedTransportError(
                    "Scoped IPv6 addresses are forbidden"
                )

            canonical = str(ip)

            if canonical not in addresses:
                addresses.append(canonical)

        self.addresses = tuple(addresses)

        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):

        if normalize_hostname(host) != self.hostname:
            raise httpcore.ConnectError(
                "Hostname does not match validated DNS result"
            )

        last_error = None

        for address in self.addresses:

            try:
                return await self.backend.connect_tcp(
                    host=address,
                    port=port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )

            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        raise httpcore.ConnectError(
            "Could not connect to a validated IP"
        ) from last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options=None,
    ):
        raise httpcore.ConnectError(
            "Unix socket connections are forbidden"
        )

    async def sleep(self, seconds: float):
        await self.backend.sleep(seconds)


class PinnedResponseStream(httpx.AsyncByteStream):

    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:

        with map_httpcore_exceptions():
            async for chunk in self.stream:
                yield chunk

    async def aclose(self):

        if hasattr(self.stream, "aclose"):
            await self.stream.aclose()


class PinnedHTTPTransport(httpx.AsyncBaseTransport):

    def __init__(
            self,
            dns_result: DNSResult,
            ssl_context: ssl.SSLContext | None = None
    ):

        self.hostname = normalize_hostname(dns_result.hostname)

        backend = PinnedNetworkBackend(dns_result)

        if ssl_context is None:
            ssl_context = ssl.create_default_context()

        if (
                ssl_context.verify_mode != ssl.CERT_REQUIRED
                or not ssl_context.check_hostname
        ):
            raise PinnedTransportError(
                "TLS certificate and hostname verification must remain enabled"
            )

        self.pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            http1=True,
            http2=False,
            network_backend=backend,
        )

    async def handle_async_request(
        self,
        request: httpx.Request,
    ) -> httpx.Response:

        request_hostname = normalize_hostname(request.url.host)

        if request_hostname != self.hostname:
            raise PinnedTransportError(
                "Request hostname does not match DNS validation"
            )

        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )

        with map_httpcore_exceptions():
            response = await self.pool.handle_async_request(
                core_request
            )

        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=PinnedResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self):
        await self.pool.aclose()