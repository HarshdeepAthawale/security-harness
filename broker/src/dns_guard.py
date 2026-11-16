"""
Resolves a hostname and validates every returned IP against policy.

IMPORTANT:
This is a point-in-time check. Callers MUST connect to DNSResult.addresses
and never resolve the hostname again, otherwise DNS rebinding defeats it.

Pair with egress filtering at the network layer.
"""

import asyncio
import ipaddress
import socket

from dataclasses import dataclass


class DNSGuardError(Exception):
    """Raised when DNS resolution or IP validation fails."""


@dataclass(frozen=True)
class DNSResult:
    hostname: str
    addresses: tuple[str, ...]


# Cloud metadata / credential endpoints.
# Blocked unconditionally: no allow_* flag can unlock them.
ALWAYS_BLOCKED = frozenset(
    ipaddress.ip_address(a)
    for a in (
        "169.254.169.254",   # AWS, GCP, Azure, DigitalOcean, OpenStack
        "169.254.170.2",     # AWS ECS task credentials
        "fd00:ec2::254",     # AWS IMDS over IPv6
        "100.100.100.200",   # Alibaba Cloud
        "192.0.0.192",       # Oracle Cloud
    )
)

_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")

_RESOLVER_ERRORS = (
    socket.gaierror,
    UnicodeError,
    ValueError,
    OSError,
)


def _embedded_ipv4(
    ip: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Extract IPv4 carried inside an IPv6 address, if present."""

    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped

    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)

    if ip in _SIX_TO_FOUR:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)

    return None


class DNSGuard:

    def __init__(
        self,
        allow_private: bool = False,
        allow_loopback: bool = False,
        allow_link_local: bool = False,
        allow_reserved: bool = False,
        resolve_timeout: float = 5.0,
    ):

        flags = (
            allow_private,
            allow_loopback,
            allow_link_local,
            allow_reserved,
        )

        if not all(type(flag) is bool for flag in flags):
            raise ValueError("All allow_* options must be booleans")

        if (
            isinstance(resolve_timeout, bool)
            or not isinstance(resolve_timeout, (int, float))
            or not 0 < resolve_timeout <= 60
        ):
            raise ValueError("resolve_timeout must be in (0, 60]")

        self.allow_private = allow_private
        self.allow_loopback = allow_loopback
        self.allow_link_local = allow_link_local
        self.allow_reserved = allow_reserved
        self.resolve_timeout = resolve_timeout

    def _validate_ip(self, address: str) -> str:
        """Validate an IP address and return its canonical form."""

        if not isinstance(address, str):
            raise DNSGuardError("IP address must be a string")

        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise DNSGuardError(
                f"Invalid IP address returned by DNS: {address}"
            ) from exc

        # Scoped IPv6 addresses are not accepted.
        if (
            isinstance(ip, ipaddress.IPv6Address)
            and ip.scope_id is not None
        ):
            raise DNSGuardError(
                "Scoped IPv6 addresses are not allowed"
            )

        # Inspect IPv4 embedded inside IPv6.
        # Prevents bypasses through mapped, NAT64 and 6to4 addresses.
        if isinstance(ip, ipaddress.IPv6Address):
            embedded = _embedded_ipv4(ip)

            if embedded is not None:
                self._validate_ip(str(embedded))

        # Metadata protection takes precedence over all allow flags.
        if ip in ALWAYS_BLOCKED:
            raise DNSGuardError(
                "Cloud metadata addresses are not allowed"
            )

        if ip.is_unspecified:
            raise DNSGuardError(
                "Unspecified IP addresses are not allowed"
            )

        if ip.is_multicast:
            raise DNSGuardError(
                "Multicast IP addresses are not allowed"
            )

        # Loopback and link-local overlap with private classifications.
        # Check them independently before the general private check.
        if ip.is_loopback:
            if not self.allow_loopback:
                raise DNSGuardError(
                    "Loopback IP addresses are not allowed"
                )

            return str(ip)

        if ip.is_link_local:
            if not self.allow_link_local:
                raise DNSGuardError(
                    "Link-local IP addresses are not allowed"
                )

            return str(ip)

        if ip.is_private and not self.allow_private:
            raise DNSGuardError(
                "Private IP addresses are not allowed"
            )

        if ip.is_reserved and not self.allow_reserved:
            raise DNSGuardError(
                "Reserved IP addresses are not allowed"
            )

        if (
            not ip.is_global
            and not (ip.is_private and self.allow_private)
            and not (ip.is_reserved and self.allow_reserved)
        ):
            raise DNSGuardError(
                "Non-global IP addresses are not allowed"
            )

        return str(ip)

    def validate_result(self, result: DNSResult) -> DNSResult:
        """
        Re-validate an existing DNSResult against this policy (no lookup).

        DNSResult is a plain dataclass and can be constructed by hand, so
        anything that connects to result.addresses must call this first.
        """

        if not isinstance(result, DNSResult):
            raise DNSGuardError("Expected a DNSResult")

        if not isinstance(result.hostname, str) or not result.hostname:
            raise DNSGuardError("Invalid hostname in DNS result")

        if (
            not isinstance(result.addresses, tuple)
            or not result.addresses
        ):
            raise DNSGuardError("DNS result has no addresses")

        validated = {self._validate_ip(a) for a in result.addresses}

        return DNSResult(
            hostname=result.hostname,
            addresses=tuple(sorted(validated)),
        )

    async def resolve(self, hostname: str) -> DNSResult:
        """
        Resolve a hostname and validate every returned IP.

        Rejects the entire hostname if even one address violates policy.
        Every expected resolver or validation failure raises DNSGuardError.
        """

        if not isinstance(hostname, str) or not hostname.strip():
            raise DNSGuardError(
                "Hostname must be a non-empty string"
            )

        hostname = hostname.strip().rstrip(".").lower()

        if not hostname or len(hostname) > 253:
            raise DNSGuardError("Invalid hostname length")

        try:
            async with asyncio.timeout(self.resolve_timeout):
                results = await asyncio.get_running_loop().getaddrinfo(
                    hostname,
                    None,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )

        except TimeoutError:
            raise DNSGuardError(
                f"DNS resolution timed out for {hostname!r}"
            ) from None

        except _RESOLVER_ERRORS as exc:
            raise DNSGuardError(
                f"DNS resolution failed for {hostname!r}"
            ) from exc

        if not results:
            raise DNSGuardError(
                f"No IP addresses found for {hostname!r}"
            )

        validated = set()

        try:
            for record in results:

                if (
                    not isinstance(record, tuple)
                    or len(record) != 5
                    or not isinstance(record[4], tuple)
                    or not record[4]
                ):
                    raise DNSGuardError(
                        "Malformed DNS resolver response"
                    )

                address = record[4][0]

                validated.add(self._validate_ip(address))

        except DNSGuardError:
            raise

        except (TypeError, ValueError, IndexError) as exc:
            raise DNSGuardError(
                "Malformed DNS resolver response"
            ) from exc

        if not validated:
            raise DNSGuardError(
                f"No valid IP addresses found for {hostname!r}"
            )

        return DNSResult(
            hostname=hostname,
            addresses=tuple(sorted(validated)),
        )