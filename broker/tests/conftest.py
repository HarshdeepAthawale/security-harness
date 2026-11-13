import pytest

from broker.src.plan import RequestPlan
from broker.src.scope import ScopePolicy, ScopeValidator


# --------------------------------------------------
# SHARED REQUEST DATA
# --------------------------------------------------

@pytest.fixture
def valid_plan_data():

    return {
        "identity": "user_A",
        "method": "GET",
        "path": "/api/orders/1001",
        "headers": {},
        "query": {},
        "body": None,
        "pack": "idor-bola",
        "expect": "403/404",
    }


# --------------------------------------------------
# REQUEST PLAN FIXTURE
# --------------------------------------------------

@pytest.fixture
def valid_plan(valid_plan_data):

    return RequestPlan(**valid_plan_data)


# --------------------------------------------------
# SCOPE POLICY FIXTURE
# --------------------------------------------------

@pytest.fixture
def scope_policy():

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

        # Entire application is in scope.
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


# --------------------------------------------------
# SCOPE VALIDATOR FIXTURE
# --------------------------------------------------

@pytest.fixture
def scope_validator(scope_policy):

    return ScopeValidator(scope_policy)