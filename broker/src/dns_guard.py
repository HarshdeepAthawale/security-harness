from __future__ import annotations
import ipaddress
import socket
from .scope import Scope


class DNSPolicyError(ValueError):
    pass


def resolve_pinned(scope: Scope, resolver=socket.getaddrinfo) -> tuple[ipaddress._BaseAddress, ...]:
    try:
        rows = resolver(scope.host, scope.port, type=socket.SOCK_STREAM)
        addresses = tuple(dict.fromkeys(ipaddress.ip_address(row[4][0].split("%", 1)[0]) for row in rows))
    except (OSError, ValueError, IndexError) as exc:
        raise DNSPolicyError("dns_failed") from exc
    if not addresses:
        raise DNSPolicyError("dns_empty")
    for address in addresses:
        candidate = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped else address
        if not candidate.is_global and not any(candidate.version == net.version and candidate in net for net in scope.allowed_cidrs):
            raise DNSPolicyError("dns_address_denied")
    return addresses
