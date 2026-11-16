import pytest

from broker.src.plan import RequestPlan
from broker.src.scope import (
    ScopePolicy,
    ScopeValidator,
    ScopeViolation,
    normalize_hostname,
    normalize_origin,
)


# --------------------------------------------------
# FIXTURES
# --------------------------------------------------

@pytest.fixture
def policy():

    return ScopePolicy(
        base_url="https://target.example.com",

        allowed_methods=frozenset({
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "HEAD",
            "OPTIONS",
        }),

        allowed_path_prefixes=("/",),

        allowed_packs=frozenset({
            "idor-bola",
            "xss",
            "sqli",
            "auth-testing",
        }),

        allowed_identities=frozenset({
            "user_A",
            "user_B",
            "admin",
        }),

    )


@pytest.fixture
def validator(policy):

    return ScopeValidator(policy)


def make_plan(**overrides):

    data = {
        "identity": "user_A",
        "method": "GET",
        "path": "/api/orders/1001",
        "headers": {},
        "query": {},
        "body": None,
        "pack": "idor-bola",
        "expect": "403/404",
    }

    data.update(overrides)

    return RequestPlan(**data)


# --------------------------------------------------
# TARGET URL TESTS
# --------------------------------------------------

def test_normalize_origin():

    assert normalize_origin(
        "HTTPS://Example.com:443"
    ) == "https://example.com"


def test_normalize_origin_removes_default_http_port():

    assert normalize_origin(
        "http://example.com:80"
    ) == "http://example.com"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com",
        "https://example.com/admin",
        "https://example.com?x=1",
        "https://user:password@example.com",
        "https://",
        "",
    ],
)
def test_reject_invalid_target_urls(url):

    with pytest.raises(ValueError):
        normalize_origin(url)


# --------------------------------------------------
# HOSTNAME TESTS
# --------------------------------------------------

def test_normalize_hostname():

    assert normalize_hostname(
        "EXAMPLE.COM."
    ) == "example.com"


def test_normalize_ip():

    assert normalize_hostname(
        "127.0.0.1"
    ) == "127.0.0.1"


@pytest.mark.parametrize(
    "hostname",
    [
        "",
        "bad host",
        "example.com/path",
        "example.com@evil.com",
        "example.com?",
    ],
)
def test_reject_invalid_hostnames(hostname):

    with pytest.raises(ValueError):
        normalize_hostname(hostname)


# --------------------------------------------------
# AUTHORIZED REQUEST TESTS
# --------------------------------------------------

def test_accepts_normal_request(validator):

    plan = make_plan()

    result = validator.validate(plan)

    assert result == (
        "https://target.example.com/api/orders/1001"
    )


def test_accepts_admin_path(validator):

    plan = make_plan(
        path="/admin"
    )

    assert validator.validate(plan) == (
        "https://target.example.com/admin"
    )


def test_accepts_idor_test(validator):

    plan = make_plan(
        identity="user_A",
        path="/api/orders/1002",
        pack="idor-bola",
        expect="403/404",
    )

    validator.validate(plan)


def test_accepts_privilege_escalation_test(validator):

    plan = make_plan(
        path="/admin/users",
        pack="auth-testing",
    )

    validator.validate(plan)


def test_accepts_delete_request(validator):

    plan = make_plan(
        method="DELETE",
        path="/api/orders/1001",
    )

    validator.validate(plan)


# --------------------------------------------------
# METHOD TESTS
# --------------------------------------------------

def test_rejects_unauthorized_method(policy):

    restricted_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=frozenset({"GET"}),
        allowed_path_prefixes=("/",),
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
    )

    validator = ScopeValidator(restricted_policy)

    plan = make_plan(
        method="DELETE"
    )

    with pytest.raises(ScopeViolation):
        validator.validate(plan)


# --------------------------------------------------
# PATH TESTS
# --------------------------------------------------

def test_rejects_path_outside_scope(policy):

    restricted_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=policy.allowed_methods,
        allowed_path_prefixes=("/api/orders",),
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
    )

    validator = ScopeValidator(restricted_policy)

    plan = make_plan(
        path="/admin"
    )

    with pytest.raises(ScopeViolation):
        validator.validate(plan)


def test_path_prefix_boundary_matching(policy):

    restricted_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=policy.allowed_methods,
        allowed_path_prefixes=("/api/orders",),
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
    )

    validator = ScopeValidator(restricted_policy)

    valid_plan = make_plan(
        path="/api/orders/1001"
    )

    invalid_plan = make_plan(
        path="/api/orders-admin"
    )

    validator.validate(valid_plan)

    with pytest.raises(ScopeViolation):
        validator.validate(invalid_plan)


# --------------------------------------------------
# PACK TESTS
# --------------------------------------------------

def test_rejects_unauthorized_pack(validator):

    plan = make_plan(
        pack="unknown-pack"
    )

    with pytest.raises(ScopeViolation):
        validator.validate(plan)


# --------------------------------------------------
# IDENTITY TESTS
# --------------------------------------------------

def test_rejects_unauthorized_identity(validator):

    plan = make_plan(
        identity="unknown-user"
    )

    with pytest.raises(ScopeViolation):
        validator.validate(plan)


# --------------------------------------------------
# HOST HEADER / CANONICAL URL
# --------------------------------------------------

def test_plan_cannot_carry_host_header():
    # Host is reserved in plan.py, so it can never reach scope.
    with pytest.raises(Exception):
        make_plan(headers={"Host": "attacker.example.com"})


def test_scope_rejects_host_header_even_if_plan_validation_bypassed(validator):
    plan = RequestPlan.model_construct(
        identity="user_A", method="GET", path="/api/orders",
        headers={"Host": "attacker.example.com"}, query={}, body=None,
        pack="idor-bola", expect="200",
    )
    with pytest.raises(ScopeViolation):
        validator.validate(plan)


def test_query_is_encoded_into_canonical_url(validator):
    plan = make_plan(query={"q": "a b&c=d", "n": 5, "tags": ["x", "y"]})
    url = validator.validate(plan)
    assert url.startswith("https://target.example.com/api/orders/1001?")
    assert "a%20b%26c%3Dd" in url or "a+b%26c%3Dd" in url
    assert "tags=x&tags=y" in url


def test_empty_query_adds_no_question_mark(validator):
    assert "?" not in validator.validate(make_plan())


def test_non_canonical_path_rejected_even_if_plan_validation_bypassed(validator):
    # httpx would re-encode these, so the authorized URL != the sent URL.
    for path in ("/api/orders/\u00fc", "/api/orders/a b"):
        plan = RequestPlan.model_construct(
            identity="user_A", method="GET", path=path, headers={},
            query={}, body=None, pack="idor-bola", expect="200",
        )
        with pytest.raises(ScopeViolation):
            validator.validate(plan)


def test_destination_always_comes_from_trusted_origin(validator):
    assert validator.validate(make_plan()).startswith("https://target.example.com/")
