import pytest

from pydantic import ValidationError
from broker.src.plan import RequestPlan


def test_valid_plan():

    plan = RequestPlan(
        identity="user_B",
        method="POST",
        path="/api/orders/1001/cancel",
        headers={
            "Content-Type": "application/json"
        },
        query={},
        body={
            "reason": "test"
        },
        pack="idor-bola",
        expect="403/404",
    )

    assert plan.identity == "user_B"
    assert plan.method == "POST"
    assert plan.expect == "403/404"


def test_reject_authorization_header():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="GET",
            path="/api/orders",
            headers={
                "Authorization": "Bearer secret"
            },
            pack="idor-bola",
            expect="200",
        )


def test_reject_invalid_method():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="TRACE",
            path="/api/orders",
            pack="idor-bola",
            expect="200",
        )


def test_reject_absolute_url():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="GET",
            path="https://evil.com/api",
            pack="idor-bola",
            expect="200",
        )


def test_reject_path_traversal():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="GET",
            path="/api/../admin",
            pack="idor-bola",
            expect="200",
        )


def test_reject_invalid_expect():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="GET",
            path="/api/orders",
            pack="idor-bola",
            expect="999",
        )


def test_reject_unknown_field():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="user_B",
            method="GET",
            path="/api/orders",
            pack="idor-bola",
            expect="200",
            admin=True,
        )

def test_empty():

    with pytest.raises(ValidationError):

        RequestPlan(
            identity="",
            method="",
            path="",
            pack="idor-bola",
            expect="",
            admin=True,
        )

@pytest.mark.parametrize("identity", [
    "user_A",
    "user_B",
    "admin_123",
    "test-user",
    "USER123",
])
def test_accepts_valid_identity(identity):
    plan = RequestPlan(
        identity=identity,
        method="GET",
        path="/api/orders",
        pack="idor-bola",
        expect="200",
    )

    assert plan.identity == identity


@pytest.mark.parametrize("identity", [
    "",
    "user B",
    "user@123",
    "user/B",
    "../admin",
    "user;DROP",
])
def test_rejects_invalid_identity(identity):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity=identity,
            method="GET",
            path="/api/orders",
            pack="idor-bola",
            expect="200",
        )

@pytest.mark.parametrize("method", [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
])
def test_accepts_valid_methods(method):
    plan = RequestPlan(
        identity="user_A",
        method=method,
        path="/api/orders",
        pack="idor-bola",
        expect="200",
    )

    assert plan.method == method


@pytest.mark.parametrize("method", [
    "TRACE",
    "CONNECT",
    "INVALID",
    "get",
    "",
])
def test_rejects_invalid_methods(method):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method=method,
            path="/api/orders",
            pack="idor-bola",
            expect="200",
        )
@pytest.mark.parametrize("path", [
    "/api/orders",
    "/api/orders/1001",
    "/api/orders/1001/cancel",
    "/api/users/profile",
    "/api/v1/orders",
])
def test_accepts_valid_paths(path):
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path=path,
        pack="idor-bola",
        expect="200",
    )

    assert plan.path == path


@pytest.mark.parametrize("path", [
    "",
    "api/orders",
    "//evil.com/api",
    "https://evil.com/api",
    "/api/orders?admin=true",
    "/api/orders#fragment",
    "/api\\orders",
    "/api/../admin",
    "/api/./admin",
    "/api/%2e%2e/admin",
    "/api/%252e%252e/admin",
])
def test_rejects_invalid_paths(path):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path=path,
            pack="idor-bola",
            expect="200",
        )
@pytest.mark.parametrize("header", [

    # Authentication and session management
    "authorization",
    "proxy-authorization",
    "cookie",

    # Destination control
    "host",

    # HTTP message framing
    "content-length",
    "transfer-encoding",

    # Connection management
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",

])
def test_rejects_forbidden_headers(header):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="POST",
            path="/api/orders",
            headers={
                header: header,
            },
            pack="idor-bola",
            expect="200",
        )


def test_accepts_normal_headers():
    plan = RequestPlan(
        identity="user_A",
        method="POST",
        path="/api/orders",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Request-ID": "12345",
        },
        pack="idor-bola",
        expect="200",
    )

    assert len(plan.headers) == 3


@pytest.mark.parametrize("header_name", [
    "Invalid Header",
    "Header:Value",
    "Header\nName",
    "Header(Name)",
])
def test_rejects_invalid_header_names(header_name):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            headers={
                header_name: "value"
            },
            pack="idor-bola",
            expect="200",
        )


@pytest.mark.parametrize("header_value", [
    "hello\r\nAuthorization: Bearer secret",
    "hello\nInjected-Header: malicious",
])
def test_rejects_header_injection(header_value):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            headers={
                "X-Test": header_value
            },
            pack="idor-bola",
            expect="200",
        )


def test_rejects_too_many_headers():
    headers = {
        f"X-Header-{i}": f"value-{i}"
        for i in range(31)
    }

    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            headers=headers,
            pack="idor-bola",
            expect="200",
        )
def test_accepts_query_parameters():
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path="/api/orders",
        query={
            "page": 1,
            "limit": 10,
            "status": "pending",
        },
        pack="idor-bola",
        expect="200",
    )

    assert plan.query["page"] == 1


def test_accepts_empty_query():
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path="/api/orders",
        query={},
        pack="idor-bola",
        expect="200",
    )

    assert plan.query == {}


def test_rejects_too_many_query_parameters():
    query = {
        f"param_{i}": i
        for i in range(51)
    }

    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            query=query,
            pack="idor-bola",
            expect="200",
        )


def test_rejects_non_json_query_values():
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            query={
                "value": float("nan")
            },
            pack="idor-bola",
            expect="200",
        )
def test_accepts_valid_body():
    body = {
        "reason": "test",
        "order_id": 1001,
    }

    plan = RequestPlan(
        identity="user_A",
        method="POST",
        path="/api/orders/1001/cancel",
        body=body,
        pack="idor-bola",
        expect="403/404",
    )

    assert plan.body == body


def test_accepts_null_body():
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path="/api/orders",
        body=None,
        pack="idor-bola",
        expect="200",
    )

    assert plan.body is None


def test_rejects_non_serializable_body():
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="POST",
            path="/api/orders",
            body={
                "invalid": {1, 2, 3}
            },
            pack="idor-bola",
            expect="200",
        )


def test_rejects_nan_in_body():
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="POST",
            path="/api/orders",
            body={
                "price": float("nan")
            },
            pack="idor-bola",
            expect="200",
        )


def test_rejects_oversized_body():
    large_body = {
        "data": "x" * 1_000_000
    }

    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="POST",
            path="/api/orders",
            body=large_body,
            pack="idor-bola",
            expect="200",
        )
@pytest.mark.parametrize("pack", [
    "idor-bola",
    "sql-injection",
    "xss",
    "ssrf",
    "auth-testing",
])
def test_accepts_valid_pack(pack):
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path="/api/orders",
        pack=pack,
        expect="200",
    )

    assert plan.pack == pack


@pytest.mark.parametrize("pack", [
    "",
    "idor bola",
    "idor/bola",
    "pack@123",
    "pack;drop",
])
def test_rejects_invalid_pack(pack):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            pack=pack,
            expect="200",
        )
@pytest.mark.parametrize("expect", [
    "200",
    "403",
    "404",
    "403/404",
    "200/201/204",
    "400/401/403/404",
])
def test_accepts_valid_expected_status(expect):
    plan = RequestPlan(
        identity="user_A",
        method="GET",
        path="/api/orders",
        pack="idor-bola",
        expect=expect,
    )

    assert plan.expect == expect


@pytest.mark.parametrize("expect", [
    "",
    "abc",
    "999",
    "99",
    "600",
    "200/999",
    "200/abc",
    "200/",
    "/403",
])
def test_rejects_invalid_expected_status(expect):
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            pack="idor-bola",
            expect=expect,
        )
def test_rejects_unexpected_fields():
    with pytest.raises(ValidationError):
        RequestPlan(
            identity="user_A",
            method="GET",
            path="/api/orders",
            pack="idor-bola",
            expect="200",
            is_admin=True,
        )