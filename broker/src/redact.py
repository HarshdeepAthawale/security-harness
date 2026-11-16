"""
redact.py

Redaction for everything that reaches the audit ledger.

Design rules:
  1. Redact BEFORE truncating. Truncating first leaves half-JSON that no
     parser can redact, and can cut a secret in half at the sample edge.
  2. Key-name matching is not enough: servers echo secrets back inside HTML,
     error text, URLs and form bodies. A Redactor built from the identity's
     credential headers scrubs those literal values (and their encoded
     variants) from every string, whatever the content type.
  3. Structured JSON is redacted by key (whole value, any type, any depth);
     everything else (including truncated or invalid JSON) by pattern.
  4. Never raise on hostile input; bound all work.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote

from .limits import MAX_REDACT_INPUT_BYTES, MAX_SAMPLE_BYTES

REDACTED = "[REDACTED]"
MIN_SECRET_LENGTH = 4   # shorter literals would mangle ordinary text
MAX_DEPTH = 64

_KEYWORDS = (
    r"token|secret|passw(?:or)?d|pwd|credential|authorization|"
    r"api[_-]?key|session|cookie|bearer|private[_-]?key|jwt|csrf|xsrf"
)

SENSITIVE_KEY = re.compile(_KEYWORDS, re.IGNORECASE)

SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
})

# "key": "value" / "key": 123 / "key": {..}  (also truncated strings)
_JSON_PAIR = re.compile(
    r'("[^"\\\n]{0,80}?(?:%s)[^"\\\n]{0,80}?"\s*:\s*)'
    r'("(?:[^"\\]|\\.)*(?:"|\Z)|[^\s,}\]]+)' % _KEYWORDS,
    re.IGNORECASE,
)

# key=value, key: value (forms, query strings, headers, env-style text)
_KV_PAIR = re.compile(
    r'(?<![\w])((?:[\w.\-]{0,40})(?:%s)(?:[\w.\-]{0,40})\s*[=:]\s*)'
    r'("[^"\n]*"|\'[^\'\n]*\'|[^\s&;,"\'<>]+)' % _KEYWORDS,
    re.IGNORECASE,
)

_BEARER = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]{4,}=*")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def _variants(secret: str) -> Iterable[str]:
    yield secret
    yield quote(secret, safe="")
    yield json.dumps(secret)[1:-1]


class Redactor:
    """Redacts headers, structures and response bodies."""

    def __init__(self, secrets: Iterable[str] = ()):
        literals: set[str] = set()
        for secret in secrets:
            if isinstance(secret, str) and len(secret) >= MIN_SECRET_LENGTH:
                for v in _variants(secret):
                    if len(v) >= MIN_SECRET_LENGTH:
                        literals.add(v)
        self._literal = (
            re.compile("|".join(
                re.escape(v) for v in sorted(literals, key=len, reverse=True)
            ))
            if literals else None
        )

    @staticmethod
    def _secrets_from(rendered: Mapping[str, str]) -> list[str]:
        secrets: list[str] = []
        for name, value in rendered.items():
            if not isinstance(value, str):
                continue
            secrets.append(value)
            m = re.match(r"(?i)\s*(?:bearer|basic|token)\s+(.+)", value)
            if m:
                secrets.append(m.group(1).strip())
            if name.lower() == "cookie":
                for part in value.split(";"):
                    _, _, v = part.strip().partition("=")
                    secrets.append(v)
        return secrets

    @classmethod
    def for_credential_headers(cls, rendered: Mapping[str, str]) -> "Redactor":
        """
        Build from one credential's rendered headers (Credential.render()).
        Every value is a secret by definition; also split out the token part
        of "Bearer x" / "Basic x" and each cookie value.
        """
        return cls(cls._secrets_from(rendered))

    @classmethod
    def for_credentials(cls, rendered: Iterable[Mapping[str, str]]) -> "Redactor":
        """
        Build from EVERY identity's rendered headers. A response to user_A's
        request can echo user_B's token (exactly what BOLA tests provoke),
        so the audit log must scrub all configured secrets, not just the
        requesting identity's.
        """
        secrets: list[str] = []
        for r in rendered:
            secrets.extend(cls._secrets_from(r))
        return cls(secrets)

    # ---------------------------------------------------------------- text
    def text(self, value: str) -> str:
        if self._literal is not None:
            value = self._literal.sub(REDACTED, value)
        value = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", value)
        value = _JWT.sub(REDACTED, value)
        value = _JSON_PAIR.sub(lambda m: m.group(1) + f'"{REDACTED}"', value)
        value = _KV_PAIR.sub(lambda m: m.group(1) + REDACTED, value)
        return value

    # ------------------------------------------------------------- structures
    def value(self, obj: Any, _depth: int = 0) -> Any:
        """Redact a JSON-like structure (query, body, parsed response)."""
        if _depth > MAX_DEPTH:
            return "[TRUNCATED]"
        if isinstance(obj, Mapping):
            return {
                str(k): (REDACTED if SENSITIVE_KEY.search(str(k))
                         else self.value(v, _depth + 1))
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [self.value(v, _depth + 1) for v in obj]
        if isinstance(obj, str):
            return self.text(obj)
        return obj

    # ---------------------------------------------------------------- headers
    def headers(self, headers) -> list[list[str]]:
        """
        Accepts a Mapping or an iterable of (name, value) pairs (e.g.
        ExecutionResult.headers). Returns [[name, value], ...] so duplicate
        headers survive. Never raises on odd input.
        """
        if headers is None:
            return []
        pairs = headers.items() if isinstance(headers, Mapping) else headers
        out: list[list[str]] = []
        for pair in pairs:
            try:
                name, val = pair
            except (TypeError, ValueError):
                continue
            name, val = str(name), str(val)
            if name.lower() in SENSITIVE_HEADERS or SENSITIVE_KEY.search(name):
                val = REDACTED
            else:
                val = self.text(val)
            out.append([name, val])
        return out

    # --------------------------------------------------------------- response
    def response_summary(self, body: bytes | None, headers=()) -> dict:
        body = body or b""
        raw = body[:MAX_REDACT_INPUT_BYTES]
        input_truncated = len(body) > len(raw)

        if b"\x00" in raw[:1024]:
            sample, sample_truncated = f"[binary {len(body)} bytes]", False
        else:
            text = raw.decode("utf-8", "replace")
            redacted = self._redact_body_text(text, parse=not input_truncated)
            encoded = redacted.encode("utf-8")
            sample_truncated = input_truncated or len(encoded) > MAX_SAMPLE_BYTES
            sample = encoded[:MAX_SAMPLE_BYTES].decode("utf-8", "ignore")

        return {
            "digest": hashlib.sha256(body).hexdigest(),   # of the FULL body
            "body_bytes": len(body),
            "sample": sample,
            "sample_truncated": sample_truncated,
            "headers": self.headers(headers),
        }

    def _redact_body_text(self, text: str, *, parse: bool) -> str:
        if parse:
            try:
                parsed = json.loads(text)
            except (ValueError, RecursionError):
                parsed = None
            else:
                if isinstance(parsed, (dict, list)):
                    return json.dumps(
                        self.value(parsed), separators=(",", ":"),
                        ensure_ascii=True,
                    )
        return self.text(text)


# Convenience functions (no credential context).
_DEFAULT = Redactor()


def redact_headers(headers) -> list[list[str]]:
    return _DEFAULT.headers(headers)


def response_summary(body, headers=(), redactor: Redactor | None = None) -> dict:
    return (redactor or _DEFAULT).response_summary(body, headers)
