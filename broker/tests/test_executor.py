"""Executor unit tests. The transport is injected by overriding
_make_transport in a subclass (the public API accepts no transport), and all
mock bodies use stream= so tests run the same read path as production."""

import asyncio
import inspect
import ssl

import httpx
import pytest

from broker.src.dns_guard import DNSGuard, DNSResult
from broker.src.executor import (
    ExecutionConfig,
    ExecutionRequest,
    ExecutorClosedError,
    HTTPExecutor,
    RequestBuildError,
)

pytestmark = pytest.mark.asyncio


class SlowStream(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0.0):
        self.chunks, self.delay = chunks, delay

    async def __aiter__(self):
        for c in self.chunks:
            await asyncio.sleep(self.delay)
            yield c


def ok(body=b"hello", status=200, headers=None):
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))


class MockExecutor(HTTPExecutor):
    def __init__(self, handler, config=None, address_policy=None):
        self._mock = httpx.MockTransport(handler)
        self.seen = []
        super().__init__(config, address_policy)

    def _make_transport(self, dns_result):
        self.seen.append(dns_result)
        return self._mock


@pytest.fixture
def config():
    return ExecutionConfig(timeout_seconds=1, max_response_bytes=1024,
                           max_request_bytes=1024, max_concurrent_requests=2)


@pytest.fixture
def dns():
    return DNSResult("example.com", ("93.184.216.34",))


async def run(handler, dns, *, method="GET", url="https://example.com/",
              config=None, headers=None, body=None):
    async with MockExecutor(handler, config) as ex:
        return await ex.execute_request(
            ex.build_request(method, url, headers, body), dns)


# ---------------------------------------------------------------- success
async def test_successful_request(dns):
    r = await run(lambda req: ok(), dns)
    assert r.http_success and r.body == b"hello" and r.error_code is None
    assert r.request_possibly_delivered is True


async def test_404_is_transport_success_but_not_http_success(dns):
    r = await run(lambda req: ok(b"no", 404), dns)
    assert r.transport_success and not r.http_success and r.status_code == 404


async def test_duplicate_response_headers_preserved(dns):
    def h(req):
        return httpx.Response(200, headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
                              stream=httpx.ByteStream(b""))
    r = await run(h, dns)
    assert [v for k, v in r.headers if k.lower() == "set-cookie"] == ["a=1", "b=2"]


# ------------------------------------------------- request validation
async def test_direct_construction_with_forbidden_header_rejected(config, dns):
    async with MockExecutor(lambda r: ok(), config) as ex:
        with pytest.raises(RequestBuildError):
            await ex.execute_request(
                ExecutionRequest("GET", "https://example.com/", {"Accept-Encoding": "gzip"}), dns)


async def test_noncanonical_url_rejected(config, dns):
    async with MockExecutor(lambda r: ok(), config) as ex:
        with pytest.raises(RequestBuildError):
            await ex.execute_request(
                ExecutionRequest("GET", "HTTPS://EXAMPLE.com:443/a/../b"), dns)


async def test_noncanonical_headers_or_body_rejected(config, dns):
    async with MockExecutor(lambda r: ok(), config) as ex:
        with pytest.raises(RequestBuildError):
            await ex.execute_request(
                ExecutionRequest("GET", "https://example.com/", {"X": "a\r\nB: c"}), dns)
        with pytest.raises(RequestBuildError):
            await ex.execute_request(
                ExecutionRequest("GET", "https://example.com/", {}, "str-body"), dns)


@pytest.mark.parametrize("headers", [
    {"X": "a\r\nInjected: 1"}, {"X": "caf\u00e9"}, {"X": "a\x00b"}, {"a": "1", "A": "2"},
    {"Host": "evil"}, {"Accept-Encoding": "gzip"}, {"Expect": "100-continue"},
    {"Transfer-Encoding": "chunked"}, {"Connection": "close"},
])
async def test_bad_headers_rejected(headers):
    ex = HTTPExecutor()
    with pytest.raises(RequestBuildError):
        ex.build_request("GET", "https://example.com/", headers)


@pytest.mark.parametrize("method", ["CONNECT", "TRACE", "FOO", "", "get x"])
async def test_forbidden_methods(method):
    with pytest.raises(RequestBuildError):
        HTTPExecutor().build_request(method, "https://example.com/")


@pytest.mark.parametrize("url", [
    "https://user:pw@example.com/", "https://example.com/#frag", "https://example.com/ ",
    "http://example.com/", "ftp://example.com/", "https://2130706433/", "https://0x7f.1/",
    "https://017700000001/", "", "https:///path",
])
async def test_bad_urls_rejected(url):
    with pytest.raises(RequestBuildError):
        HTTPExecutor().build_request("GET", url)


async def test_body_must_be_bytes_and_bounded():
    ex = HTTPExecutor(ExecutionConfig(max_request_bytes=10))
    with pytest.raises(RequestBuildError):
        ex.build_request("POST", "https://example.com/", body="text")
    with pytest.raises(RequestBuildError):
        ex.build_request("POST", "https://example.com/", body=b"x" * 11)


async def test_public_constructor_has_no_transport_parameter():
    assert "transport" not in inspect.signature(HTTPExecutor.__init__).parameters


# ------------------------------------------------- DNS pinning contract
async def test_dns_result_required(config):
    async with MockExecutor(lambda r: ok(), config) as ex:
        req = ex.build_request("GET", "https://example.com/")
        for bad in (None, "example.com", {"hostname": "example.com"}):
            with pytest.raises(RequestBuildError):
                await ex.execute_request(req, bad)


async def test_dns_hostname_must_match_request(config):
    async with MockExecutor(lambda r: ok(), config) as ex:
        req = ex.build_request("GET", "https://example.com/")
        with pytest.raises(RequestBuildError):
            await ex.execute_request(req, DNSResult("other.com", ("93.184.216.34",)))


async def test_hostname_match_is_case_and_dot_insensitive(config):
    async with MockExecutor(lambda r: ok(), config) as ex:
        req = ex.build_request("GET", "https://example.com/")
        r = await ex.execute_request(req, DNSResult("EXAMPLE.com.", ("93.184.216.34",)))
        assert r.http_success


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1",
    "::ffff:127.0.0.1", "0.0.0.0", "fd00:ec2::254",
])
async def test_forged_dns_result_with_internal_address_rejected(config, addr):
    async with MockExecutor(lambda r: pytest.fail("must not connect"), config) as ex:
        req = ex.build_request("GET", "https://example.com/")
        with pytest.raises(RequestBuildError, match="address policy"):
            await ex.execute_request(req, DNSResult("example.com", (addr,)))
        assert ex.seen == []                       # no transport was even created


async def test_one_bad_address_among_good_rejects(config):
    async with MockExecutor(lambda r: ok(), config) as ex:
        req = ex.build_request("GET", "https://example.com/")
        with pytest.raises(RequestBuildError):
            await ex.execute_request(
                req, DNSResult("example.com", ("93.184.216.34", "10.0.0.1")))


async def test_metadata_never_allowed_even_with_permissive_policy(config):
    permissive = DNSGuard(True, True, True, True)
    async with MockExecutor(lambda r: ok(), config, permissive) as ex:
        req = ex.build_request("GET", "https://example.com/")
        with pytest.raises(RequestBuildError):
            await ex.execute_request(req, DNSResult("example.com", ("169.254.169.254",)))


async def test_loopback_allowed_only_when_policy_says_so(config):
    async with MockExecutor(lambda r: ok(), config, DNSGuard(allow_loopback=True)) as ex:
        req = ex.build_request("GET", "https://localhost/")
        r = await ex.execute_request(req, DNSResult("localhost", ("127.0.0.1",)))
        assert r.http_success


async def test_transport_receives_validated_result(config, dns):
    async with MockExecutor(lambda r: ok(), config) as ex:
        await ex.execute_request(ex.build_request("GET", "https://example.com/"), dns)
        assert ex.seen == [dns]


# ------------------------------------------------- response handling
async def test_compressed_response_rejected_headers_kept(dns):
    r = await run(lambda req: ok(b"compressed data", headers={"Content-Encoding": "gzip"}), dns)
    assert r.error_code == "unexpected_content_encoding"
    assert r.status_code == 200 and r.body is None
    assert ("content-encoding", "gzip") in r.headers


async def test_redirect_not_followed(dns):
    r = await run(lambda req: ok(b"", 302, {"Location": "http://169.254.169.254/"}), dns)
    assert r.status_code == 302 and r.transport_success


async def test_no_content_response(dns):
    r = await run(lambda req: httpx.Response(204), dns, method="DELETE")
    assert r.http_success and r.body == b""


async def test_head_with_large_content_length_ok(dns):
    r = await run(lambda req: httpx.Response(200, headers={"Content-Length": "999999999"}),
                  dns, method="HEAD")
    assert r.http_success and r.body == b""


async def test_oversized_declared_length_rejected(config, dns):
    r = await run(lambda req: ok(b"", headers={"Content-Length": "5000"}), dns, config=config)
    assert r.error_code == "response_too_large" and r.body is None


@pytest.mark.parametrize("value", ["abc", "-1"])
async def test_bad_content_length_rejected(dns, value):
    r = await run(lambda req: ok(b"", headers={"Content-Length": value}), dns)
    assert r.error_code == "invalid_content_length"


async def test_oversized_streamed_body_cut_off(config, dns):
    r = await run(lambda req: httpx.Response(200, stream=SlowStream([b"x" * 600, b"x" * 600])),
                  dns, config=config)
    assert r.error_code == "response_too_large" and r.body is None


# ------------------------------------------------- deadline / delivery
async def test_slow_drip_hits_total_deadline(dns):
    cfg = ExecutionConfig(timeout_seconds=0.3)
    r = await run(lambda req: httpx.Response(200, stream=SlowStream([b"a"] * 50, 0.1)),
                  dns, config=cfg)
    assert r.error_code == "timeout" and r.request_possibly_delivered is True


async def test_queue_timeout_is_not_delivered(dns):
    cfg = ExecutionConfig(timeout_seconds=0.3, max_concurrent_requests=1)
    async with MockExecutor(lambda r: ok(), cfg) as ex:
        req = ex.build_request("GET", "https://example.com/")
        await ex._semaphore.acquire()               # saturated pool
        try:
            r = await ex.execute_request(req, dns)
        finally:
            ex._semaphore.release()
    assert r.error_code == "timeout" and r.request_possibly_delivered is False


async def test_tls_failure_vs_refused_and_not_delivered(dns):
    def tls(req):
        raise httpx.ConnectError("x") from ssl.SSLCertVerificationError("bad")

    def refused(req):
        raise httpx.ConnectError("refused")

    a, b = await run(tls, dns), await run(refused, dns)
    assert (a.error_code, b.error_code) == ("tls_verification_failed", "connection_error")
    assert not a.request_possibly_delivered and not b.request_possibly_delivered


async def test_tls_detection_follows_context_like_httpcore(dns):
    # httpcore sets the SSL error as __context__ (not __cause__) on ConnectError.
    def h(req):
        try:
            raise ssl.SSLCertVerificationError("verify failed")
        except ssl.SSLError:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]")

    assert (await run(h, dns)).error_code == "tls_verification_failed"


async def test_read_timeout_is_possibly_delivered(dns):
    def h(req):
        raise httpx.ReadTimeout("slow")
    r = await run(h, dns)
    assert r.error_code == "read_timeout" and r.request_possibly_delivered is True


async def test_connect_timeout_is_not_delivered(dns):
    def h(req):
        raise httpx.ConnectTimeout("slow")
    r = await run(h, dns)
    assert r.error_code == "connect_timeout" and r.request_possibly_delivered is False


# ------------------------------------------------- lifecycle
async def test_rejects_request_after_close(dns):
    ex = MockExecutor(lambda r: ok())
    req = ex.build_request("GET", "https://example.com/")
    await ex.close()
    with pytest.raises(ExecutorClosedError):
        await ex.execute_request(req, dns)
    with pytest.raises(ExecutorClosedError):
        ex.build_request("GET", "https://example.com/")


async def test_close_is_idempotent_and_concurrent():
    ex = MockExecutor(lambda r: ok())
    await asyncio.gather(ex.close(), ex.close(), ex.close())
    await ex.close()


async def test_close_waits_for_inflight_request(dns):
    ex = MockExecutor(lambda r: httpx.Response(200, stream=SlowStream([b"a"], 0.2)),
                      ExecutionConfig(timeout_seconds=2))
    req = ex.build_request("GET", "https://example.com/")
    task = asyncio.create_task(ex.execute_request(req, dns))
    await asyncio.sleep(0.05)
    await ex.close()
    assert task.done() and task.result().http_success


async def test_cancelled_close_does_not_abort_shutdown(dns):
    ex = MockExecutor(lambda r: httpx.Response(200, stream=SlowStream([b"a"], 0.3)),
                      ExecutionConfig(timeout_seconds=2))
    req = ex.build_request("GET", "https://example.com/")
    inflight = asyncio.create_task(ex.execute_request(req, dns))
    await asyncio.sleep(0.05)
    closer = asyncio.create_task(ex.close())
    await asyncio.sleep(0.05)
    closer.cancel()
    await asyncio.gather(closer, return_exceptions=True)
    await inflight
    await ex.close()                                  # completes, not hung


async def test_cancellation_propagates(dns):
    ex = MockExecutor(lambda r: httpx.Response(200, stream=SlowStream([b"a"], 5)),
                      ExecutionConfig(timeout_seconds=10))
    req = ex.build_request("GET", "https://example.com/")
    task = asyncio.create_task(ex.execute_request(req, dns))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await ex.close()                                  # counter was released
