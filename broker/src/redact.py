from __future__ import annotations
import hashlib
import json
import re
from .limits import MAX_SAMPLE_BYTES

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}

# JSON keys whose value is never stored. Word-bounded for the short ones so a
# key like "residence" isn't mistaken for "sid".
TOKEN_KEY = re.compile(
    r"(?i)token|secret|passw(or)?d|credential|authorization|api[_-]?key|session|cookie"
    r"|(^|[^a-z])(sid|otp|jwt|pin)($|[^a-z])"
)

# Secrets that show up in free text (HTML, logs, truncated JSON, JS) where there
# is no key to go by.
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_KEY_VALUE = re.compile(
    r"(?i)\b(access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|passw(?:or)?d|"
    r"api[_-]?key|authorization|jwt|session(?:[_-]?id)?|sid|cookie)\b"
    r"(\W{0,6}?[:=]\s*)([\"']?)(?:\[REDACTED\]|[^\s\"',;&<>}\]]+)"
)


def redact_headers(headers) -> dict[str, str]:
    return {str(k): ("[REDACTED]" if str(k).lower() in SENSITIVE_HEADERS else str(v)) for k, v in headers.items()}


def _clean_json(value):
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if TOKEN_KEY.search(str(k)) else _clean_json(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_json(v) for v in value]
    return value


def redact_text(text: str, secrets=()) -> str:
    """Remove anything token-shaped from free text. Safe to call on text that
    is already redacted (it is idempotent)."""
    for secret in secrets:
        if secret and len(secret) >= 4:
            text = text.replace(secret, "[REDACTED]")
    text = _JWT.sub("[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _KEY_VALUE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED]", text)


def redacted_sample(body: bytes, secrets=()) -> str:
    """What gets stored and returned in place of the body.

    The WHOLE body is redacted first and only then cut down to
    MAX_SAMPLE_BYTES. Cutting first would leave a half-parsed JSON document
    that can't be redacted by key, which is how a token in a large response
    used to end up in the ledger.
    """
    text = body.decode("utf-8", "replace")

    try:
        text = json.dumps(_clean_json(json.loads(text)), separators=(",", ":"), ensure_ascii=True)
    except (ValueError, RecursionError):
        pass

    text = redact_text(text, secrets)
    return text.encode("utf-8")[:MAX_SAMPLE_BYTES].decode("utf-8", "ignore")


def response_summary(body: bytes, headers, secrets=()) -> dict:
    """digest is of the raw body (the judge compares it); the sample and the
    headers are redacted. `secrets` are credentials the broker itself sent,
    removed from the sample even if a server echoes them back."""
    return {
        "digest": hashlib.sha256(body).hexdigest(),
        "sample": redacted_sample(body, secrets),
        "headers": {k: redact_text(v, secrets) for k, v in redact_headers(headers).items()},
    }
