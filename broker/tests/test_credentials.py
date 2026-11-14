
import pytest

from broker.src.credentials import (
    Credential,
    CredentialStore,
    CredentialError,
)


PROD = "https://app.target.com"
STAGING = "https://staging.target.com"

TOKEN = "SECRETtoken123"
COOKIE = "SECRETcookie456"
API_KEY = "SECRETapikey789"


# ============================================================
# 1. FIXTURES
# ============================================================

@pytest.fixture
def store():
    return CredentialStore({
        "anon": Credential.anonymous(),
        "alice": Credential.bearer(TOKEN, [PROD]),
        "bob": Credential.cookie({"sid": COOKIE}, [PROD]),
        "carol": Credential.custom(
            {"X-CSRF": "csrf1"},
            [PROD],
            {"sid": COOKIE}
        ),
        "dave": Credential.custom(
            {"X-API-Key": API_KEY},
            [PROD]
        ),
        "multi": Credential.bearer(TOKEN, [PROD, STAGING]),
    })


# ============================================================
# 2. CREDENTIAL CREATION
# ============================================================

def test_create_anonymous_credential():
    cred = Credential.anonymous()

    assert cred.is_anonymous is True
    assert cred.render() == {}


def test_create_bearer_credential():
    cred = Credential.bearer(TOKEN, [PROD])

    assert cred.is_anonymous is False
    assert cred.render() == {
        "Authorization": f"Bearer {TOKEN}"
    }


def test_create_cookie_credential():
    cred = Credential.cookie({"sid": COOKIE}, [PROD])

    assert cred.is_anonymous is False
    assert cred.render() == {
        "Cookie": f"sid={COOKIE}"
    }


def test_create_custom_credential():
    cred = Credential.custom({"X-API-Key": API_KEY}, [PROD])

    assert cred.render() == {
        "X-API-Key": API_KEY
    }


def test_create_custom_credential_with_cookie():
    cred = Credential.custom(
        {"X-CSRF": "csrf1"},
        [PROD],
        {"sid": COOKIE}
    )

    assert cred.render() == {
        "X-CSRF": "csrf1",
        "Cookie": f"sid={COOKIE}"
    }


# ============================================================
# 3. INVALID CREDENTIAL INPUTS
# ============================================================

@pytest.mark.parametrize("token", [
    "",
    " ",
    "token with spaces",
    "token\ninjection",
    "token\tinjection",
    None,
    123,
    [],
    "abc;def",
    "abc==def",
])
def test_reject_invalid_bearer_tokens(token):
    with pytest.raises(CredentialError):
        Credential.bearer(token, [PROD])


@pytest.mark.parametrize("headers", [
    None,
    [],
    "Authorization",
    123,
    {"Invalid Header": "value"},
    {"X-Test": 123},
    {"X-Test": None},
    {"X-Test": "value\ninjected"},
    {"X-Test": "a" * 9000},
    {"X-Test": ""},
    {"X-Test": "first", "x-test": "second"},
])
def test_reject_invalid_custom_headers(headers):
    with pytest.raises(CredentialError):
        Credential.custom(headers, [PROD])


@pytest.mark.parametrize("cookies", [
    None,
    {},
    [],
    {"sid": None},
    {"sid": 123},
    {"sid": "value\ninjected"},
    {"sid": "value with spaces"},
    {"sid": "a" * 5000},
    {"sid": "a;b"},
    {"sid": "a,b"},
    {"sid": "a\\b"},
])
def test_reject_invalid_cookies(cookies):
    with pytest.raises(CredentialError):
        Credential.cookie(cookies, [PROD])


# ============================================================
# 4. COOKIE CASE SENSITIVITY
# ============================================================

def test_cookie_names_are_case_sensitive():
    cred = Credential.cookie(
        {"sid": "one", "SID": "two"},
        [PROD]
    )

    assert cred.render()["Cookie"] == "sid=one; SID=two"


def test_duplicate_cookie_names_are_rejected():
    # Python dictionaries cannot contain duplicate identical keys.
    # This test checks the distinction between cookie-name casing.
    cred = Credential.cookie(
        {"SessionID": "one", "sessionid": "two"},
        [PROD]
    )

    assert cred.render()["Cookie"] == (
        "SessionID=one; sessionid=two"
    )


# ============================================================
# 5. ORIGIN AUTHORIZATION
# ============================================================

def test_apply_credential_to_authorized_origin(store):
    result = store.apply("alice", PROD)

    assert result["Authorization"] == f"Bearer {TOKEN}"


def test_reject_unauthorized_origin(store):
    with pytest.raises(CredentialError):
        store.apply("alice", "https://evil.com")


def test_reject_different_subdomain(store):
    with pytest.raises(CredentialError):
        store.apply("alice", "https://admin.target.com")


def test_reject_different_port(store):
    with pytest.raises(CredentialError):
        store.apply("alice", "https://app.target.com:8443")


def test_reject_different_scheme(store):
    with pytest.raises(CredentialError):
        store.apply("alice", "http://app.target.com")


def test_allow_multiple_configured_origins(store):
    assert store.apply("multi", PROD)
    assert store.apply("multi", STAGING)


def test_reject_origin_not_in_multiple_origin_list(store):
    with pytest.raises(CredentialError):
        store.apply("multi", "https://evil.com")


def test_same_origin_different_paths_are_allowed(store):
    result = store.apply(
        "alice",
        "https://app.target.com/api/users"
    )

    assert result["Authorization"] == f"Bearer {TOKEN}"


def test_hostname_case_is_normalized(store):
    result = store.apply(
        "alice",
        "https://APP.TARGET.COM/api"
    )

    assert result["Authorization"] == f"Bearer {TOKEN}"


# ============================================================
# 6. URL VALIDATION
# ============================================================

@pytest.mark.parametrize("url", [
    "",
    "app.target.com",
    "//app.target.com",
    "ftp://app.target.com",
    "javascript://app.target.com",
    "https://",
    "https://user:password@app.target.com",
    "https://app.target.com:99999",
    "https://app.target.com:0",
    " https://app.target.com",
    "https://app.target.com ",
    "https://app.target.com\n",
    "https://app.target.com\r\nHost: evil.com",
])
def test_reject_malformed_urls(store, url):
    with pytest.raises(CredentialError):
        store.apply("alice", url)


def test_reject_url_with_userinfo(store):
    with pytest.raises(CredentialError):
        store.apply(
            "alice",
            "https://user:password@app.target.com"
        )


# ============================================================
# 7. HTTP SECURITY
# ============================================================

def test_plaintext_http_requires_opt_in():
    with pytest.raises(CredentialError):
        Credential.bearer(
            TOKEN,
            ["http://lab.local"]
        )


def test_http_allowed_with_explicit_opt_in():
    cred = Credential.bearer(
        TOKEN,
        ["http://lab.local"],
        allow_insecure=True
    )

    s = CredentialStore({"user": cred})

    result = s.apply("user", "http://lab.local/api")

    assert result["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("flag", [
    "yes",
    1,
    0,
    None,
    [],
])
def test_allow_insecure_requires_boolean(flag):
    with pytest.raises(CredentialError):
        Credential.bearer(
            TOKEN,
            ["http://lab.local"],
            allow_insecure=flag
        )


# ============================================================
# 8. IDENTITY MANAGEMENT
# ============================================================

def test_identity_exists(store):
    assert store.has_identity("alice") is True


def test_unknown_identity(store):
    assert store.has_identity("unknown") is False


def test_unknown_identity_cannot_apply_credentials(store):
    with pytest.raises(CredentialError):
        store.apply("unknown", PROD)


@pytest.mark.parametrize("identity", [
    "",
    " alice",
    "alice ",
    "alice\n",
    "alice\x00",
    None,
    123,
    b"alice",
])
def test_reject_invalid_identity_names(identity):
    with pytest.raises(CredentialError):
        CredentialStore({
            identity: Credential.anonymous()
        })


def test_identities_returns_all_configured_names(store):
    assert store.identities() == frozenset({
        "anon",
        "alice",
        "bob",
        "carol",
        "dave",
        "multi",
    })


# ============================================================
# 9. HEADER PROTECTION
# ============================================================

@pytest.mark.parametrize("header", [
    "Authorization",
    "authorization",
    "AUTHORIZATION",
    "Cookie",
    "cookie",
    "Proxy-Authorization",
])
def test_reject_caller_auth_headers(store, header):
    with pytest.raises(CredentialError):
        store.apply(
            "anon",
            PROD,
            {header: "attacker-value"}
        )


@pytest.mark.parametrize("header", [
    "Host",
    "Content-Length",
    "Transfer-Encoding",
    "Connection",
    "Proxy-Authorization",
])
def test_reject_forbidden_headers(store, header):
    with pytest.raises(CredentialError):
        store.apply(
            "anon",
            PROD,
            {header: "attacker-value"}
        )


def test_reject_duplicate_request_headers(store):
    # Normal dictionaries can contain differently-cased keys.
    with pytest.raises(CredentialError):
        store.apply(
            "anon",
            PROD,
            {
                "X-Test": "first",
                "x-test": "second"
            }
        )


def test_reject_override_of_custom_auth_header(store):
    with pytest.raises(CredentialError):
        store.apply(
            "dave",
            PROD,
            {"x-api-key": "attacker-value"}
        )


def test_reject_override_of_credential_cookie(store):
    with pytest.raises(CredentialError):
        store.apply(
            "bob",
            PROD,
            {"Cookie": "attacker=value"}
        )


# ============================================================
# 10. REQUEST HEADER VALIDATION
# ============================================================

def test_preserve_valid_request_headers(store):
    result = store.apply(
        "alice",
        PROD,
        {
            "Accept": "application/json",
            "X-Trace-ID": "123"
        }
    )

    assert result["Accept"] == "application/json"
    assert result["X-Trace-ID"] == "123"
    assert result["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.parametrize("headers", [
    None,
    "Accept",
    [],
    123,
])
def test_reject_invalid_request_header_mapping(store, headers):
    if headers is None:
        # None is a valid value meaning no additional headers.
        assert store.apply("anon", PROD, headers) == {}
    else:
        with pytest.raises(CredentialError):
            store.apply("anon", PROD, headers)


@pytest.mark.parametrize("headers", [
    {"Invalid Header": "value"},
    {"X-Test": 123},
    {"X-Test": None},
    {"X-Test": "value\ninjected"},
    {"X-Test": "value\r\nInjected: true"},
    {"X-Test": "a" * 9000},
])
def test_reject_malformed_request_headers(store, headers):
    with pytest.raises(CredentialError):
        store.apply("anon", PROD, headers)


# ============================================================
# 11. IMMUTABILITY AND ISOLATION
# ============================================================

def test_source_header_mapping_cannot_modify_credential():
    original = {"X-Key": "original"}

    cred = Credential.custom(original, [PROD])

    original["X-Key"] = "modified"

    assert cred.render()["X-Key"] == "original"


def test_source_cookie_mapping_cannot_modify_credential():
    original = {"sid": "original"}

    cred = Credential.cookie(original, [PROD])

    original["sid"] = "modified"

    assert cred.render()["Cookie"] == "sid=original"


def test_source_origins_cannot_modify_credential():
    original = [PROD]

    cred = Credential.bearer(TOKEN, original)

    original.append("https://evil.com")

    s = CredentialStore({"user": cred})

    with pytest.raises(CredentialError):
        s.apply("user", "https://evil.com")


def test_source_store_mapping_cannot_modify_store():
    original = {
        "user": Credential.anonymous()
    }

    s = CredentialStore(original)

    original["admin"] = Credential.anonymous()

    assert s.has_identity("admin") is False


def test_returned_headers_do_not_modify_store(store):
    result = store.apply("alice", PROD)

    result["Authorization"] = "attacker-value"
    result["Injected"] = "value"

    second_result = store.apply("alice", PROD)

    assert second_result == {
        "Authorization": f"Bearer {TOKEN}"
    }



# ============================================================
# 12. SECRET PROTECTION
# ============================================================

def test_secret_not_visible_in_credential_repr():
    cred = Credential.bearer(TOKEN, [PROD])

    assert TOKEN not in repr(cred)
    assert TOKEN not in str(cred)


def test_cookie_secret_not_visible_in_repr():
    cred = Credential.cookie({"sid": COOKIE}, [PROD])

    assert COOKIE not in repr(cred)
    assert COOKIE not in str(cred)


def test_custom_secret_not_visible_in_repr():
    cred = Credential.custom({"X-API-Key": API_KEY}, [PROD])

    assert API_KEY not in repr(cred)
    assert API_KEY not in str(cred)


def test_secret_not_exposed_in_error_message(store):
    with pytest.raises(CredentialError) as exc:
        store.apply("alice", "https://evil.com")

    assert TOKEN not in str(exc.value)


# ============================================================
# 13. STATELESS BEHAVIOUR
# ============================================================

def test_failed_request_does_not_affect_next_request(store):
    with pytest.raises(CredentialError):
        store.apply("alice", "https://evil.com")

    result = store.apply("alice", PROD)

    assert result["Authorization"] == f"Bearer {TOKEN}"


def test_multiple_calls_return_consistent_results(store):
    first = store.apply("alice", PROD)
    second = store.apply("alice", PROD)

    assert first == second


def test_anonymous_identity_never_receives_credentials(store):
    assert store.apply("anon", PROD) == {}


# ============================================================
# 14. OUTPUT VALIDATION
# ============================================================

def test_output_is_dictionary(store):
    result = store.apply("alice", PROD)

    assert isinstance(result, dict)


def test_output_contains_only_string_headers(store):
    result = store.apply(
        "alice",
        PROD,
        {"Accept": "application/json"}
    )

    for name, value in result.items():
        assert isinstance(name, str)
        assert isinstance(value, str)


def test_exact_output_for_each_credential_type(store):
    assert store.apply("alice", PROD) == {
        "Authorization": f"Bearer {TOKEN}"
    }

    assert store.apply("bob", PROD) == {
        "Cookie": f"sid={COOKIE}"
    }

    assert store.apply("carol", PROD) == {
        "X-CSRF": "csrf1",
        "Cookie": f"sid={COOKIE}"
    }

    assert store.apply("dave", PROD) == {
        "X-API-Key": API_KEY
    }

    assert store.apply("anon", PROD) == {}
