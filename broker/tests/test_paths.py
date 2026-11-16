"""Path tricks the broker must refuse independently."""

import pytest
from pydantic import ValidationError

from broker.src.plan import RequestPlan, path_problem
from broker.src.scope import (
    ScopePolicy,
    ScopeValidator,
    ScopeViolation,
    canonicalize_path,
)


BASE = dict(
    identity="user_B",
    method="GET",
    headers={},
    query={},
    body=None,
    pack="idor-bola",
    expect="403",
)


BAD = [
    "/api/../admin",
    "/api/./orders",
    "/api/%2e%2e/admin",
    "/api/%252e%252e/admin",
    "/api/..;/admin",
    "/api/.;/orders",
    "/api//admin",
    "/api/orders/1%00.json",
    "/api/orders/1%0d%0aSet-Cookie:x=1",
    "/api/x%5c..%5cadmin",
    "/api/%2fadmin",
]


GOOD = [
    "/",
    "/api",
    "/api/orders/",
    "/api/orders/1001",
    "/api/a%20b",
    "/api/orders/1;jsessionid=abc",
]


@pytest.mark.parametrize("path", BAD)
def test_plan_rejects(path):
    with pytest.raises(ValidationError):
        RequestPlan(path=path, **BASE)


@pytest.mark.parametrize("path", GOOD)
def test_plan_accepts(path):
    RequestPlan(path=path, **BASE)


@pytest.mark.parametrize(
    "path",
    [
        p for p in BAD
        if "%2f" not in p.lower() and "%5c" not in p.lower()
    ],
)
def test_scope_check_rejects_on_its_own(path):
    """Scope canonicalization must independently reject dangerous paths."""
    with pytest.raises(ScopeViolation):
        canonicalize_path(path)


def test_end_to_end_traversal_never_becomes_validated_request():
    validator = ScopeValidator(
        ScopePolicy(
            base_url="https://t.example.com",
            allowed_methods=frozenset({"GET"}),
            allowed_path_prefixes=("/api",),
            allowed_packs=frozenset({"idor-bola"}),
            allowed_identities=frozenset({"user_B"}),
        )
    )

    with pytest.raises((ValidationError, ScopeViolation)):
        plan = RequestPlan(
            path="/api/..;/admin",
            **BASE,
        )
        validator.validate(plan)

@pytest.mark.parametrize(
    "path, expected",
    [
        ("/api/..;/x", "dot segment"),
        ("/api//x", "empty segment"),
        ("/api/x%00", "control character"),
        ("/api/orders/", None),
    ],
)
def test_path_problem_names_the_reason(path, expected):
    assert path_problem(path) == expected