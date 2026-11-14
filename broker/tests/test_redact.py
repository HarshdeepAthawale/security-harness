"""Secrets must not survive into the stored sample (the signed ledger) or the
returned headers, whatever shape the response has."""
import hashlib
import json

import pytest

from broker.src.limits import MAX_SAMPLE_BYTES
from broker.src.redact import redact_text, redacted_sample, response_summary

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyX0EifQ.signature-part"


def _big_json(extra):
    """A JSON document well over the sample size, secret first."""
    return json.dumps({**extra, "items": ["x" * 60] * 200}).encode()


@pytest.mark.parametrize("name, body", [
    ("small json", json.dumps({"id": 1, "access_token": JWT}).encode()),
    ("json over 4 KB", _big_json({"access_token": JWT})),
    ("json, secret at the end", json.dumps({"items": ["x" * 60] * 200, "refresh_token": JWT}).encode()),
    ("nested", json.dumps({"user": {"auth": {"api_key": JWT}}}).encode()),
    ("html", f"<script>var t='{JWT}'</script>".encode()),
    ("plain text", f"Authorization: Bearer {JWT}".encode()),
    ("key=value text", f"session_id={JWT}&x=1".encode()),
    ("truncated json", ('{"data":"' + "y" * 5000 + f'","token":"{JWT}"').encode()),
    ("jwt under an innocent key", json.dumps({"note": JWT}).encode()),
])
def test_secret_never_reaches_the_sample(name, body):
    assert JWT not in redacted_sample(body)
    assert JWT not in json.dumps(response_summary(body, {}))


def test_the_credential_the_broker_sent_is_removed_even_if_echoed():
    body = json.dumps({"you_sent": "my-opaque-credential-1234"}).encode()
    assert "my-opaque-credential-1234" not in redacted_sample(body, secrets=("my-opaque-credential-1234",))


def test_sample_is_capped_after_redaction():
    sample = redacted_sample(_big_json({"id": 7}))
    assert len(sample.encode()) <= MAX_SAMPLE_BYTES


def test_digest_is_of_the_raw_body_not_the_redacted_one():
    body = json.dumps({"access_token": JWT}).encode()
    assert response_summary(body, {})["digest"] == hashlib.sha256(body).hexdigest()


def test_normal_data_is_kept():
    sample = redacted_sample(json.dumps({"id": 1001, "total": 42.5, "residence": "Pune"}).encode())
    assert '"id":1001' in sample and '"total":42.5' in sample
    assert "Pune" in sample                       # 'residence' must not be mistaken for 'sid'


def test_sensitive_response_headers_are_redacted():
    out = response_summary(b"", {"Set-Cookie": "sid=abc123", "X-Request-Id": "r-1", "Authorization": "Bearer xyz"})
    assert out["headers"]["Set-Cookie"] == "[REDACTED]"
    assert out["headers"]["Authorization"] == "[REDACTED]"
    assert out["headers"]["X-Request-Id"] == "r-1"


def test_redaction_is_idempotent():
    once = redact_text(f'{{"token": "{JWT}"}}')
    assert redact_text(once) == once
