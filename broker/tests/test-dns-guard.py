import socket
import pytest
from broker.src.dns_guard import DNSPolicyError, resolve_pinned


def test_rejects_private_dns_result(scope):
    fake = lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
    with pytest.raises(DNSPolicyError): resolve_pinned(scope, fake)