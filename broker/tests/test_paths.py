"""Path tricks the broker must refuse on its own, without relying on the kernel's hook."""
import pytest
from pydantic import ValidationError

from broker.src.plan import RequestPlan, path_problem
from broker.src.scope import ScopePolicy, ScopeValidator, ScopeViolation, canonicalize_path

BASE = dict(identity="user_B", method="GET", headers={}, query={}, body=None, pack="idor-bola", expect="403")

BAD = [
    "/api/../admin",
    "/api/./orders",
    "/api/%2e%2e/admin",
    "/api/%252e%252e/admin",       # double-encoded
    "/api/..;/admin",              # Tomcat / Spring path parameter: means '..'
    "/api/.;/orders",
    "/api//admin",                 # servers collapse '//'
    "/api/orders/1%00.json",       # NUL byte, decoded after the check used to run
    "/api/orders/1%0d%0aSet-Cookie:x=1",
    "/api/x%5c..%5cadmin",         # encoded backslash
    "/api/%2fadmin",               # encoded slash
]

GOOD = ["/", "/api", "/api/orders/", "/api/orders/1001", "/api/a%20b", "/api/orders/1;jsessionid=abc"]


@pytest.mark.parametrize("path", BAD)
def test_plan_rejects(path):
    with pytest.raises(ValidationError):
        RequestPlan(path=path, **BASE)


@pytest.mark.parametrize("path", GOOD)
def test_plan_accepts(path):
    RequestPlan(path=path, **BASE)


@pytest.mark.parametrize("path", [p for p in BAD if "%2f" not in p.lower() and "%5c" not in p.lower()])
def test_scope_check_rejects_on_its_own(path):
    """canonicalize_path is what the scope check runs; it must not depend on the plan model."""
    with pytest.raises(ScopeViolation):
        canonicalize_path(path)


def test_end_to_end_a_traversal_never_becomes_a_validated_request():
    validator = ScopeValidator(ScopePolicy(
        base_url="https://t.example.com", allowed_methods=frozenset({"GET"}), allowed_path_prefixes=("/api",),
        allowed_packs=frozenset({"idor-bola"}), allowed_identities=frozenset({"user_B"})))
    with pytest.raises((ValidationError, ScopeViolation)):
        validator.build(RequestPlan(path="/api/..;/admin", **BASE))


def test_path_problem_names_the_reason():
    assert path_problem("/api/..;/x") == "dot segment"
    assert path_problem("/api//x") == "empty segment"
    assert path_problem("/api/x%00") == "control character"
    assert path_problem("/api/orders/") is None
