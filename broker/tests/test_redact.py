"""Secrets must never survive into the audit sample or returned headers."""

import hashlib
import json

import pytest

from broker.src.limits import MAX_SAMPLE_BYTES
from broker.src.redact import Redactor, response_summary


JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJ1c2VyX0EifQ."
    "signature-part"
)


def _big_json(extra):
    return json.dumps(
        {
            **extra,
            "items": ["x" * 60] * 200,
        }
    ).encode()


@pytest.mark.parametrize(
    "name, body",
    [
        (
            "small json",
            json.dumps({"id": 1, "access_token": JWT}).encode(),
        ),
        (
            "json over 4 KB",
            _big_json({"access_token": JWT}),
        ),
        (
            "json secret at the end",
            json.dumps(
                {
                    "items": ["x" * 60] * 200,
                    "refresh_token": JWT,
                }
            ).encode(),
        ),
        (
            "nested",
            json.dumps(
                {"user": {"auth": {"api_key": JWT}}}
            ).encode(),
        ),
        (
            "html",
            f"<script>var t='{JWT}'</script>".encode(),
        ),
        (
            "plain text",
            f"Authorization: Bearer {JWT}".encode(),
        ),
        (
            "key=value text",
            f"session_id={JWT}&x=1".encode(),
        ),
        (
            "truncated json",
            (
                '{"data":"'
                + "y" * 5000
                + f'","token":"{JWT}"'
            ).encode(),
        ),
        (
            "jwt under innocent key",
            json.dumps({"note": JWT}).encode(),
        ),
    ],
)
def test_secret_never_reaches_sample(name, body):
    summary = response_summary(body)

    assert JWT not in summary["sample"]
    assert JWT not in json.dumps(summary)


def test_credential_echo_is_removed():
    secret = "my-opaque-credential-1234"

    redactor = Redactor([secret])

    body = json.dumps(
        {"you_sent": secret}
    ).encode()

    summary = redactor.response_summary(body)

    assert secret not in summary["sample"]


def test_sample_is_capped_after_redaction():
    sample = response_summary(
        _big_json({"id": 7})
    )["sample"]

    assert len(sample.encode()) <= MAX_SAMPLE_BYTES


def test_digest_is_of_raw_body():
    body = json.dumps(
        {"access_token": JWT}
    ).encode()

    summary = response_summary(body)

    assert summary["digest"] == hashlib.sha256(body).hexdigest()


def test_normal_data_is_preserved():
    body = json.dumps(
        {
            "id": 1001,
            "total": 42.5,
            "residence": "Pune",
        }
    ).encode()

    sample = response_summary(body)["sample"]

    assert '"id":1001' in sample
    assert '"total":42.5' in sample
    assert "Pune" in sample


def test_sensitive_response_headers_are_redacted():
    summary = response_summary(
        b"",
        [
            ["Set-Cookie", "sid=abc123"],
            ["X-Request-Id", "r-1"],
            ["Authorization", "Bearer xyz"],
        ],
    )

    headers = {
        name: value
        for name, value in summary["headers"]
    }

    assert headers["Set-Cookie"] == "[REDACTED]"
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["X-Request-Id"] == "r-1"


def test_duplicate_headers_are_preserved():
    summary = response_summary(
        b"",
        [
            ["Set-Cookie", "a=1"],
            ["Set-Cookie", "b=2"],
        ],
    )

    assert len(summary["headers"]) == 2
    assert all(
        name == "Set-Cookie"
        for name, value in summary["headers"]
    )


def test_redaction_is_idempotent():
    redactor = Redactor()

    original = f'{{"token": "{JWT}"}}'

    once = redactor.text(original)

    assert redactor.text(once) == once


def test_redactor_removes_all_configured_identity_secrets():
    redactor = Redactor.for_credentials(
        [
            {"Authorization": "Bearer user-A-secret-123"},
            {"Cookie": "sid=user-B-secret-456"},
        ]
    )

    body = (
        "user-A-secret-123 "
        "user-B-secret-456"
    )

    result = redactor.text(body)

    assert "user-A-secret-123" not in result
    assert "user-B-secret-456" not in result


def test_header_redaction_preserves_duplicate_names():
    redactor = Redactor()

    headers = redactor.headers(
        [
            ("X-Test", "first"),
            ("X-Test", "second"),
            ("Authorization", "Bearer secret"),
        ]
    )

    assert headers == [
        ["X-Test", "first"],
        ["X-Test", "second"],
        ["Authorization", "[REDACTED]"],
    ]