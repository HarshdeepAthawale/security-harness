"""Real sockets, no mocks: proves connections go to the pinned IP, TLS is
verified against the HOSTNAME, and the policy gate cannot be forged.

HTTPS tests need broker/tests/certs/localhost-{cert,key}.pem (a cert whose
SAN is DNS:localhost); they skip if the files are missing."""

import socket
from pathlib import Path
from urllib.parse import urlsplit

import httpcore
import httpx
import pytest
import ssl

from broker.src.dns_guard import DNSGuard, DNSResult
from broker.src.executor import ExecutionConfig, HTTPExecutor, RequestBuildError
from broker.src.pinned_transport import (
    PinnedHTTPTransport,
    PinnedNetworkBackend,
    PinnedTransportError,
)
from broker.tests.local_server import start_server, stop_server

pytestmark = pytest.mark.asyncio

CERT = Path(__file__).parent / "certs" / "localhost-cert.pem"
LOOPBACK_OK = DNSGuard(allow_loopback=True)       # tests are the exception


@pytest.fixture
def http_server():
    server, thread, url = start_server()
    yield url
    stop_server(server, thread)


@pytest.fixture
def https_server():
    if not CERT.exists():
        pytest.skip("test certificate not present")
    server, thread, url = start_server(use_https=True)
    yield url
    stop_server(server, thread)


def pinned(host="localhost", addr="127.0.0.1"):
    return DNSResult(host, (addr,))


class TrustingExecutor(HTTPExecutor):
    """Executor whose transport trusts the test certificate."""

    def _make_transport(self, dns_result):
        return PinnedHTTPTransport(
            dns_result, ssl_context=ssl.create_default_context(cafile=str(CERT)))


def plain_executor(**cfg):
    return HTTPExecutor(ExecutionConfig(allow_insecure_http=True, **cfg), LOOPBACK_OK)


# ------------------------------------------------------------------ HTTP
async def test_real_request_through_pinned_transport(http_server):
    async with plain_executor() as ex:
        r = await ex.execute_request(ex.build_request("GET", http_server), pinned())
    assert r.status_code == 200
    assert r.body == b"Hello from the real TCP server!"
    assert r.error_code is None


async def test_host_header_is_the_original_hostname_not_the_ip(http_server):
    port = urlsplit(http_server).port
    async with plain_executor() as ex:
        r = await ex.execute_request(ex.build_request("GET", f"{http_server}/host"), pinned())
    assert r.body == f"localhost:{port}".encode()


async def test_transport_connects_to_pinned_ip_not_resolver(http_server, monkeypatch):
    backend = PinnedNetworkBackend(pinned())
    connected, real = [], backend.backend.connect_tcp

    async def record(*, host, port, local_address=None, timeout=None, socket_options=None):
        connected.append(host)
        return await real(host=host, port=port, local_address=local_address,
                          timeout=timeout, socket_options=socket_options)

    monkeypatch.setattr(backend.backend, "connect_tcp", record)
    stream = await backend.connect_tcp(host="localhost", port=urlsplit(http_server).port, timeout=5)
    await stream.aclose()
    assert connected == ["127.0.0.1"]


async def test_falls_back_to_next_pinned_address(http_server):
    port = urlsplit(http_server).port
    # 127.0.0.2 is loopback but nothing listens there; 127.0.0.1 does.
    backend = PinnedNetworkBackend(DNSResult("localhost", ("127.0.0.2", "127.0.0.1")))
    stream = await backend.connect_tcp(host="localhost", port=port, timeout=5)
    await stream.aclose()


async def test_all_pinned_addresses_failing_raises_connect_error():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    backend = PinnedNetworkBackend(pinned())
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp(host="localhost", port=port, timeout=2)


async def test_backend_rejects_hostname_mismatch():
    with pytest.raises(httpcore.ConnectError, match="does not match"):
        await PinnedNetworkBackend(pinned()).connect_tcp(host="attacker.example", port=80, timeout=2)


async def test_transport_rejects_request_for_other_host(http_server):
    t = PinnedHTTPTransport(pinned())
    async with httpx.AsyncClient(transport=t, trust_env=False) as c:
        with pytest.raises(PinnedTransportError):
            await c.get(f"http://other.example:{urlsplit(http_server).port}/")


async def test_unix_sockets_forbidden():
    with pytest.raises(httpcore.ConnectError):
        await PinnedNetworkBackend(pinned()).connect_unix_socket("/var/run/docker.sock")


async def test_connection_refused_is_not_delivered():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    async with plain_executor() as ex:
        r = await ex.execute_request(ex.build_request("GET", f"http://localhost:{port}/"), pinned())
    assert r.error_code == "connection_error" and r.request_possibly_delivered is False


# ------------------------------------------------------- policy gate (real)
@pytest.mark.parametrize("addr", ["127.0.0.1", "169.254.169.254", "10.0.0.5"])
async def test_default_policy_rejects_forged_results(http_server, addr):
    async with HTTPExecutor(ExecutionConfig(allow_insecure_http=True)) as ex:   # strict default
        req = ex.build_request("GET", http_server)
        with pytest.raises(RequestBuildError, match="address policy"):
            await ex.execute_request(req, DNSResult("localhost", (addr,)))


async def test_metadata_forged_result_rejected_even_when_loopback_allowed(http_server):
    async with plain_executor() as ex:
        with pytest.raises(RequestBuildError):
            await ex.execute_request(ex.build_request("GET", http_server),
                                     DNSResult("localhost", ("169.254.169.254",)))


# ------------------------------------------------- response handling (real)
async def test_redirect_to_metadata_is_not_followed(http_server):
    async with plain_executor() as ex:
        r = await ex.execute_request(ex.build_request("GET", f"{http_server}/redirect"), pinned())
    assert r.status_code == 302 and r.transport_success
    assert ("location", "http://169.254.169.254/latest/meta-data/") in r.headers


async def test_gzip_response_rejected(http_server):
    async with plain_executor() as ex:
        r = await ex.execute_request(ex.build_request("GET", f"{http_server}/gzip"), pinned())
    assert r.error_code == "unexpected_content_encoding" and r.body is None


async def test_oversized_response_rejected(http_server):
    async with plain_executor(max_response_bytes=1000) as ex:
        r = await ex.execute_request(ex.build_request("GET", f"{http_server}/big"), pinned())
    assert r.error_code == "response_too_large" and r.body is None


# ------------------------------------------------------------------ HTTPS
async def test_https_succeeds_with_trusted_cert_and_matching_name(https_server):
    ex = TrustingExecutor(ExecutionConfig(), LOOPBACK_OK)
    async with ex:
        r = await ex.execute_request(ex.build_request("GET", https_server), pinned())
    assert r.status_code == 200 and r.body == b"Hello from the real TCP server!"


async def test_https_verifies_hostname_not_ip(https_server):
    """Same IP, same server, but the validated NAME differs from the cert."""
    port = urlsplit(https_server).port
    ex = TrustingExecutor(ExecutionConfig(), LOOPBACK_OK)
    async with ex:
        r = await ex.execute_request(
            ex.build_request("GET", f"https://evil.test:{port}/"), pinned("evil.test"))
    assert r.error_code == "tls_verification_failed"
    assert r.request_possibly_delivered is False


async def test_https_untrusted_cert_rejected_by_default(https_server):
    async with HTTPExecutor(ExecutionConfig(), LOOPBACK_OK) as ex:     # system CAs only
        r = await ex.execute_request(ex.build_request("GET", https_server), pinned())
    assert r.error_code == "tls_verification_failed"


async def test_transport_refuses_context_without_hostname_check():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False                       # verify_mode stays CERT_REQUIRED
    with pytest.raises(PinnedTransportError):
        PinnedHTTPTransport(pinned(), ssl_context=ctx)


async def test_transport_refuses_context_with_optional_verification():
    ctx = ssl.create_default_context()
    ctx.verify_mode = ssl.CERT_OPTIONAL              # check_hostname stays True
    with pytest.raises(PinnedTransportError):
        PinnedHTTPTransport(pinned(), ssl_context=ctx)


async def test_transport_refuses_fully_disabled_verification():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with pytest.raises(PinnedTransportError):
        PinnedHTTPTransport(pinned(), ssl_context=ctx)
