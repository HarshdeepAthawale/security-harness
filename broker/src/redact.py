from __future__ import annotations
import hashlib
import json
import re
from .limits import MAX_SAMPLE_BYTES

SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "set-cookie"}
TOKEN_KEY = re.compile(r"(?i)(token|secret|password|credential|authorization|api[_-]?key)")


def redact_headers(headers) -> dict[str, str]:
    return {str(k): ("[REDACTED]" if str(k).lower() in SENSITIVE_HEADERS else str(v)) for k, v in headers.items()}


def response_summary(body: bytes, headers) -> dict:
    sample = body[:MAX_SAMPLE_BYTES]
    try:
        parsed = json.loads(sample.decode("utf-8"))
        def clean(value):
            if isinstance(value, dict): return {k: ("[REDACTED]" if TOKEN_KEY.search(k) else clean(v)) for k, v in value.items()}
            if isinstance(value, list): return [clean(v) for v in value]
            return value
        sample = json.dumps(clean(parsed), separators=(",", ":"), ensure_ascii=True).encode()[:MAX_SAMPLE_BYTES]
    except (UnicodeError, json.JSONDecodeError):
        pass
    return {"digest": hashlib.sha256(body).hexdigest(), "sample": sample.decode("utf-8", "replace"), "headers": redact_headers(headers)}