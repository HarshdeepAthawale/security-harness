import pytest

from broker.src.plan import RequestPlan
from broker.src.scope import (
    ScopePolicy,
    ScopeValidator,
    ScopeViolation,
    normalize_hostname,
    normalize_origin,
    normalize_host_header,
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

        allow_host_header_override=False,
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
# HOST HEADER TESTS
# --------------------------------------------------

def test_normalize_host_header():

    assert normalize_host_header(
        "EXAMPLE.COM:8080"
    ) == "example.com:8080"


def test_normalize_ipv6_host_header():

    assert normalize_host_header(
        "[::1]:8080"
    ) == "[::1]:8080"


@pytest.mark.parametrize(
    "host",
    [
        "",
        "example.com/path",
        "user@example.com",
        "example.com:abc",
        "example.com:99999",
    ],
)
def test_reject_invalid_host_header(host):

    with pytest.raises(ValueError):
        normalize_host_header(host)


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
# HOST OVERRIDE TESTS
# --------------------------------------------------

def test_rejects_host_override_by_default(validator):

    plan = make_plan(
        headers={
            "Host": "attacker.example.com"
        }
    )

    with pytest.raises(ScopeViolation):
        validator.validate(plan)


def test_allows_host_override_when_enabled(policy):

    enabled_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=policy.allowed_methods,
        allowed_path_prefixes=policy.allowed_path_prefixes,
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
        allow_host_header_override=True,
    )

    validator = ScopeValidator(enabled_policy)

    plan = make_plan(
        headers={
            "Host": "attacker.example.com"
        }
    )

    # The returned destination must still be the trusted target.
    result = validator.validate(plan)

    assert result == (
        "https://target.example.com/api/orders/1001"
    )


def test_host_override_allowlist(policy):

    restricted_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=policy.allowed_methods,
        allowed_path_prefixes=policy.allowed_path_prefixes,
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
        allow_host_header_override=True,
        allowed_host_header_values=frozenset({
            "staging.example.com",
        }),
    )

    validator = ScopeValidator(restricted_policy)

    valid_plan = make_plan(
        headers={
            "Host": "STAGING.EXAMPLE.COM"
        }
    )

    invalid_plan = make_plan(
        headers={
            "Host": "attacker.example.com"
        }
    )

    validator.validate(valid_plan)

    with pytest.raises(ScopeViolation):
        validator.validate(invalid_plan)


def test_host_override_does_not_change_destination(policy):

    enabled_policy = ScopePolicy(
        base_url=policy.base_url,
        allowed_methods=policy.allowed_methods,
        allowed_path_prefixes=policy.allowed_path_prefixes,
        allowed_packs=policy.allowed_packs,
        allowed_identities=policy.allowed_identities,
        allow_host_header_override=True,
    )

    validator = ScopeValidator(enabled_policy)

    plan = make_plan(
        headers={
            "Host": "evil.example.com"
        }
    )

    destination = validator.validate(plan)

    assert destination.startswith(
        "https://target.example.com/"
    )