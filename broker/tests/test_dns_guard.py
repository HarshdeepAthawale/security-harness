import asyncio
import socket

import pytest

from broker.src.dns_guard import DNSGuard, DNSGuardError, DNSResult

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _entry(addr: str):
    if ":" in addr:
        return (socket.AF_INET6, socket.SOCK_STREAM, 6, "", (addr, 0, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (addr, 0))


@pytest.fixture
def fake_dns():
    """
    Install a fake resolver on the running loop.

    fake_dns(["8.8.8.8"])                -> same answer every call
    fake_dns([["8.8.8.8"], ["127.0.0.1"]]) with sequence=True
                                          -> successive answers per call
    fake_dns(exc=socket.gaierror(...))   -> raises
    """
    patches = []

    def install(answers=None, *, sequence=False, exc=None, delay=0.0):
        loop = asyncio.get_running_loop()
        calls = {"n": 0}

        async def fake(host, port, **kw):
            i = calls["n"]
            calls["n"] += 1
            if delay:
                await asyncio.sleep(delay)
            if exc is not None:
                raise exc
            batch = answers[min(i, len(answers) - 1)] if sequence else answers
            return [_entry(a) for a in batch]

        original = loop.getaddrinfo
        loop.getaddrinfo = fake
        patches.append((loop, original))
        return calls

    yield install
    for loop, original in patches:
        loop.getaddrinfo = original


async def resolve(fake_dns, addrs, guard=None, host="example.test"):
    fake_dns(addrs)
    return await (guard or DNSGuard()).resolve(host)


# ------------------------------------------------------------
# 1. Default policy: blocked ranges
# ------------------------------------------------------------

BLOCKED = [
    # loopback
    "127.0.0.1", "127.255.255.255", "::1",
    # RFC1918 + boundaries
    "10.0.0.1", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.1.1",
    # link-local / cloud metadata
    "169.254.169.254", "169.254.0.1", "fe80::1",
    # unspecified, multicast, broadcast, reserved
    "0.0.0.0", "::", "224.0.0.1", "ff02::1", "255.255.255.255", "240.0.0.1",
    # CGNAT, documentation, ULA
    "100.64.0.1", "100.127.255.255", "192.0.2.1", "2001:db8::1", "fc00::1", "fd12:3456::1",
    # IPv4-mapped IPv6 (classic bypass)
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
    # zone id
    "fe80::1%eth0",
]


@pytest.mark.parametrize("addr", BLOCKED)
async def test_blocked_by_default(fake_dns, addr):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [addr])


# ------------------------------------------------------------
# 2. Allowed addresses and range boundaries
# ------------------------------------------------------------

ALLOWED = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34",
    "172.15.255.255", "172.32.0.0",      # just outside 172.16/12
    "100.63.255.255", "100.128.0.0",     # just outside 100.64/10
    "11.0.0.1", "9.255.255.255",         # neighbours of 10/8
    "2606:4700:4700::1111",
]


@pytest.mark.parametrize("addr", ALLOWED)
async def test_public_allowed(fake_dns, addr):
    result = await resolve(fake_dns, [addr])
    assert result.addresses == (addr,)


# ------------------------------------------------------------
# 3. Resolution semantics
# ------------------------------------------------------------

async def test_one_bad_address_blocks_whole_hostname(fake_dns):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, ["93.184.216.34", "10.0.0.5"])


async def test_bad_address_blocks_regardless_of_order(fake_dns):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, ["10.0.0.5", "93.184.216.34"])


async def test_mixed_v4_v6_public_ok_deduped_sorted(fake_dns):
    result = await resolve(
        fake_dns, ["8.8.8.8", "2606:4700:4700::1111", "8.8.8.8", "1.1.1.1"]
    )
    assert result.addresses == tuple(sorted(
        {"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"}))


async def test_empty_result_fails_closed(fake_dns):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [])


async def test_gaierror_becomes_guard_error(fake_dns):
    fake_dns(exc=socket.gaierror(socket.EAI_NONAME, "nope"))
    with pytest.raises(DNSGuardError):
        await DNSGuard().resolve("nonexistent.test")


async def test_garbage_address_fails_closed(fake_dns):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, ["not-an-ip"])


async def test_hostname_normalized(fake_dns):
    result = await resolve(fake_dns, ["8.8.8.8"], host="  ExAmple.TEST. ")
    assert result.hostname == "example.test"


@pytest.mark.parametrize("bad", ["", "   ", None, 123, b"example.com"])
async def test_invalid_hostname_input(bad):
    with pytest.raises(DNSGuardError):
        await DNSGuard().resolve(bad)


# ------------------------------------------------------------
# 4. Policy flags
# ------------------------------------------------------------

async def test_allow_loopback_only_allows_loopback(fake_dns):
    g = DNSGuard(allow_loopback=True)
    assert (await resolve(fake_dns, ["127.0.0.1"], g)).addresses == ("127.0.0.1",)
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, ["10.0.0.1"], g)


async def test_allow_private_only_allows_private(fake_dns):
    g = DNSGuard(allow_private=True)
    assert (await resolve(fake_dns, ["10.0.0.1"], g)).addresses == ("10.0.0.1",)
    for bad in ("127.0.0.1", "169.254.169.254", "0.0.0.0", "224.0.0.1"):
        with pytest.raises(DNSGuardError):
            await resolve(fake_dns, [bad], g)


@pytest.mark.parametrize("addr", ["0.0.0.0", "::", "224.0.0.1", "ff02::1"])
async def test_never_allowed_even_with_every_flag(fake_dns, addr):
    g = DNSGuard(True, True, True, True)
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [addr], g)


@pytest.mark.parametrize("addr", [
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0.0.0.0",
])
async def test_mapped_ipv4_judged_by_embedded_address(fake_dns, addr):
    # allow_private must not let mapped loopback/metadata/unspecified through.
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [addr], DNSGuard(allow_private=True))


async def test_cloud_metadata_blocked_even_if_link_local_allowed(fake_dns):
    # allow_link_local=True also permits 169.254.169.254 (credential theft).
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, ["169.254.169.254"], DNSGuard(allow_link_local=True))


# ------------------------------------------------------------
# 5. Embedded-IPv4 transition addresses
# ------------------------------------------------------------

@pytest.mark.parametrize("addr", [
    "64:ff9b::7f00:1",       # NAT64 -> 127.0.0.1
    "64:ff9b::a9fe:a9fe",    # NAT64 -> 169.254.169.254
    "2002:7f00:1::1",        # 6to4  -> 127.0.0.1
    "2002:a9fe:a9fe::1",     # 6to4  -> 169.254.169.254
])
async def test_transition_addresses_with_internal_ipv4_blocked(fake_dns, addr):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [addr])


# ------------------------------------------------------------
# 6. Real resolver path (no network needed)
# ------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "localhost", "127.0.0.1", "2130706433", "0x7f.1", "017700000001",
])
async def test_real_resolver_blocks_loopback_spellings(host):
    with pytest.raises(DNSGuardError):
        await DNSGuard().resolve(host)


@pytest.mark.parametrize("host", [
    "a" * 64 + ".com",
    "bad\x00host.com",
    "x" * 300,
])
async def test_malformed_hostnames_raise_guard_error(host):
    # Must be DNSGuardError, not UnicodeError / ValueError leaking out.
    with pytest.raises(DNSGuardError):
        await DNSGuard().resolve(host)


# ------------------------------------------------------------
# 7. Time-of-check/time-of-use
# ------------------------------------------------------------

async def test_resolution_is_a_point_in_time_snapshot(fake_dns):
    """
    Same name, different answers per lookup. This is DNS rebinding: a client
    that re-resolves after the guard passed can be sent to 127.0.0.1.
    Callers MUST connect to result.addresses and never re-resolve.
    """
    calls = fake_dns([["93.184.216.34"], ["127.0.0.1"]], sequence=True)
    guard = DNSGuard()

    first = await guard.resolve("rebind.test")
    assert first.addresses == ("93.184.216.34",)

    with pytest.raises(DNSGuardError):
        await guard.resolve("rebind.test")

    assert calls["n"] == 2   # each resolve() does a fresh lookup


# ------------------------------------------------------------
# 8. Timeout behaviour
# ------------------------------------------------------------

async def test_hung_resolver_is_bounded(fake_dns):
    fake_dns(["8.8.8.8"], delay=5)
    # A stuck lookup must surface as DNSGuardError at resolve_timeout.
    with pytest.raises(DNSGuardError, match="timed out"):
        await asyncio.wait_for(
            DNSGuard(resolve_timeout=0.2).resolve("slow.test"), timeout=2)


@pytest.mark.parametrize("bad", [0, -1, 61, True, "5", None])
async def test_invalid_resolve_timeout_rejected(bad):
    with pytest.raises(ValueError):
        DNSGuard(resolve_timeout=bad)


# ------------------------------------------------------------
# 9. Metadata endpoints are unconditional; embedded IPv4 is judged
# ------------------------------------------------------------

@pytest.mark.parametrize("addr", [
    "169.254.169.254", "169.254.170.2", "fd00:ec2::254",
    "100.100.100.200", "192.0.0.192",
    "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
])
async def test_metadata_blocked_with_every_flag_on(fake_dns, addr):
    with pytest.raises(DNSGuardError, match="metadata|allowed"):
        await resolve(fake_dns, [addr], DNSGuard(True, True, True, True))


@pytest.mark.parametrize("addr", [
    "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1",
])
async def test_embedded_loopback_blocked_when_only_private_allowed(fake_dns, addr):
    with pytest.raises(DNSGuardError):
        await resolve(fake_dns, [addr], DNSGuard(allow_private=True))


async def test_link_local_non_metadata_still_allowed_when_flagged(fake_dns):
    g = DNSGuard(allow_link_local=True)
    assert (await resolve(fake_dns, ["169.254.1.1"], g)).addresses == ("169.254.1.1",)


async def test_error_message_truncates_long_hostname(fake_dns):
    fake_dns(exc=socket.gaierror(socket.EAI_NONAME, "x"))
    with pytest.raises(DNSGuardError) as e:
        await DNSGuard().resolve("a" * 5000)
    assert len(str(e.value)) < 400

# ------------------------------------------------------------
# 10. validate_result: DNSResult can be forged, so it is re-checked
# ------------------------------------------------------------

async def test_validate_result_accepts_public_and_sorts():
    r = DNSGuard().validate_result(DNSResult("example.com", ("8.8.8.8", "1.1.1.1", "8.8.8.8")))
    assert r.addresses == ("1.1.1.1", "8.8.8.8")


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1", "0.0.0.0",
])
async def test_validate_result_rejects_forged_internal_addresses(addr):
    with pytest.raises(DNSGuardError):
        DNSGuard().validate_result(DNSResult("example.com", (addr,)))


async def test_validate_result_one_bad_address_rejects_all():
    with pytest.raises(DNSGuardError):
        DNSGuard().validate_result(DNSResult("example.com", ("8.8.8.8", "10.0.0.1")))


@pytest.mark.parametrize("bad", [
    DNSResult("example.com", ()),
    DNSResult("", ("8.8.8.8",)),
    DNSResult("example.com", [ "8.8.8.8" ]),     # list, not tuple
    DNSResult("example.com", (2130706433,)),     # int that ipaddress would accept
    "not a result",
    None,
])
async def test_validate_result_rejects_malformed(bad):
    with pytest.raises(DNSGuardError):
        DNSGuard().validate_result(bad)


async def test_validate_result_honours_policy_flags():
    r = DNSGuard(allow_loopback=True).validate_result(DNSResult("localhost", ("127.0.0.1",)))
    assert r.addresses == ("127.0.0.1",)
    with pytest.raises(DNSGuardError):    # metadata stays blocked regardless
        DNSGuard(True, True, True, True).validate_result(
            DNSResult("x", ("169.254.169.254",)))
