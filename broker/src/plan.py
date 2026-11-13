import json
import re
from typing import Any, Literal
from urllib.parse import unquote

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
)


# --------------------------------------------------
# CONSTANTS
# --------------------------------------------------

MAX_HEADERS = 30
MAX_QUERY_PARAMS = 50

MAX_BODY_SIZE = 1_000_000
MAX_QUERY_SIZE = 100_000

# These headers are controlled by the Broker or HTTP client.
# Host is intentionally NOT included here.
BROKER_RESERVED_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
}

HEADER_NAME_PATTERN = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9a-zA-Z]+$"
)

IDENTIFIER_PATTERN = re.compile(
    r"^[a-zA-Z0-9_-]+$"
)


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def check_json_serializable(value: Any) -> bytes:
    """
    Convert a Python object into JSON bytes.

    Reject:
    - Non-JSON-serializable objects
    - NaN
    - Infinity
    """

    try:
        serialized = json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")

        return serialized

    except (TypeError, ValueError, OverflowError):
        raise ValueError("Value must be valid JSON")


def has_traversal(path: str) -> bool:
    """
    Detect literal and repeatedly encoded traversal segments.
    """

    current = path

    for _ in range(6):

        segments = current.split("/")

        if any(segment in {".", ".."} for segment in segments):
            return True

        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    return False


# --------------------------------------------------
# REQUEST PLAN
# --------------------------------------------------

class RequestPlan(BaseModel):

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    identity: StrictStr

    method: Literal[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
    ]

    path: StrictStr

    headers: dict[StrictStr, StrictStr] = Field(
        default_factory=dict
    )

    query: dict[str, Any] = Field(
        default_factory=dict
    )

    body: Any = None

    pack: StrictStr

    expect: StrictStr

    # --------------------------------------------------
    # IDENTITY
    # --------------------------------------------------

    @field_validator("identity")
    @classmethod
    def validate_identity(cls, value):

        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("Invalid identity format")

        return value

    # --------------------------------------------------
    # PATH
    # --------------------------------------------------

    @field_validator("path")
    @classmethod
    def validate_path(cls, value):

        if not value:
            raise ValueError("Path cannot be empty")

        if not value.startswith("/"):
            raise ValueError("Path must start with '/'")

        if value.startswith("//"):
            raise ValueError("Protocol-relative paths are not allowed")

        if "\\" in value:
            raise ValueError("Backslashes are not allowed")

        if "?" in value or "#" in value:
            raise ValueError(
                "Query strings and fragments must be separate"
            )

        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Control characters are not allowed")

        # Reject malformed percent escapes.
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            raise ValueError("Malformed URL encoding")

        # Encoded separators can cause parser discrepancies.
        if re.search(r"%(?:2f|5c)", value, re.IGNORECASE):
            raise ValueError("Encoded path separators are not allowed")

        if has_traversal(value):
            raise ValueError("Path traversal detected")

        return value

    # --------------------------------------------------
    # HEADERS
    # --------------------------------------------------

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, headers):

        if len(headers) > MAX_HEADERS:
            raise ValueError("Too many headers")

        for name, value in headers.items():

            normalized_name = name.lower()

            if not HEADER_NAME_PATTERN.fullmatch(name):
                raise ValueError(f"Invalid header name: {name}")

            if normalized_name in BROKER_RESERVED_HEADERS:
                raise ValueError(
                    f"Header is controlled by Broker: {name}"
                )

            # Prevent CRLF/header injection.
            if "\r" in value or "\n" in value:
                raise ValueError("CRLF injection detected")

            if "\x00" in value:
                raise ValueError("Null byte in header value")

            if any(
                ord(char) < 32 and char != "\t"
                for char in value
            ):
                raise ValueError("Control character in header value")

        return headers

    # --------------------------------------------------
    # HOST HEADER
    # --------------------------------------------------

    # Host is deliberately not rejected here.
    # ScopeValidator performs its separate authorization check.
    #
    # This validator checks only whether its syntax is valid.

    @field_validator("headers")
    @classmethod
    def validate_host_header_syntax(cls, headers):

        host_value = next(
            (
                value
                for name, value in headers.items()
                if name.lower() == "host"
            ),
            None,
        )

        if host_value is None:
            return headers

        from urllib.parse import urlsplit
        import ipaddress

        try:
            parsed = urlsplit("//" + host_value)

            if (
                not parsed.hostname
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("Invalid Host header")

            hostname = parsed.hostname

            try:
                ipaddress.ip_address(hostname)
            except ValueError:

                hostname = hostname.encode("idna").decode("ascii")

                if len(hostname) > 253:
                    raise ValueError("Hostname too long")

                labels = hostname.rstrip(".").split(".")

                for label in labels:

                    if not re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
                        label,
                    ):
                        raise ValueError("Invalid hostname")

            port = parsed.port

            if port is not None and not 1 <= port <= 65535:
                raise ValueError("Invalid Host port")

        except (ValueError, UnicodeError):
            raise ValueError("Malformed Host header")

        return headers

    # --------------------------------------------------
    # QUERY
    # --------------------------------------------------

    @field_validator("query")
    @classmethod
    def validate_query(cls, query):

        if len(query) > MAX_QUERY_PARAMS:
            raise ValueError("Too many query parameters")

        serialized = check_json_serializable(query)

        if len(serialized) > MAX_QUERY_SIZE:
            raise ValueError("Query parameters too large")

        return query

    # --------------------------------------------------
    # BODY
    # --------------------------------------------------

    @field_validator("body")
    @classmethod
    def validate_body(cls, body):

        if body is None:
            return body

        serialized = check_json_serializable(body)

        if len(serialized) > MAX_BODY_SIZE:
            raise ValueError("Request body too large")

        return body

    # --------------------------------------------------
    # PACK
    # --------------------------------------------------

    @field_validator("pack")
    @classmethod
    def validate_pack(cls, value):

        if not IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("Invalid pack name")

        return value

    # --------------------------------------------------
    # EXPECT
    # --------------------------------------------------

    @field_validator("expect")
    @classmethod
    def validate_expect(cls, value):

        statuses = value.split("/")

        if not statuses:
            raise ValueError("Expected status cannot be empty")

        for status in statuses:

            if not status.isdigit():
                raise ValueError("Invalid expected HTTP status")

            code = int(status)

            if not 100 <= code <= 599:
                raise ValueError("HTTP status must be between 100 and 599")

        if len(statuses) != len(set(statuses)):
            raise ValueError("Duplicate expected status codes")

        return value