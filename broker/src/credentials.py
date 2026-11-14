
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


class CredentialError(Exception):
    pass


# --------------------------------------------------------------------------
# Syntax rules
# --------------------------------------------------------------------------
_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")          # RFC 7230 token
_BEARER_TOKEN = re.compile(r"[A-Za-z0-9\-._~+/]+=*")           # RFC 6750 b64token
_COOKIE_VALUE = re.compile(r"[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+")  # RFC 6265
_DNS_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?")  # '_' allowed: docker/internal names

_DEFAULT_PORT = {"http": 80, "https": 443}

# Caller-supplied request headers may never carry these (identity owns auth).
ALWAYS_PROTECTED = frozenset({"authorization", "proxy-authorization", "cookie"})

# Headers a credential may never set (they alter framing/routing, not identity).
FORBIDDEN_CREDENTIAL_HEADERS = frozenset(
    {"cookie", "proxy-authorization", "host", "content-length",
     "transfer-encoding", "connection"}
)

MAX_HEADER_VALUE = 8192
MAX_COOKIE_VALUE = 4096


# --------------------------------------------------------------------------
# Origin handling: ONE canonicalizer used for config AND runtime URLs
# --------------------------------------------------------------------------
def _canonicalize(url: str, *, origin_only: bool) -> str:
    if not isinstance(url, str) or not url or url != url.strip():
        raise CredentialError("Invalid URL")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise CredentialError("Invalid URL") from exc

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORT or not host:
        raise CredentialError("Invalid URL")
    if parts.username is not None or parts.password is not None:
        raise CredentialError("Userinfo in URL not allowed")
    if origin_only and (parts.path not in ("", "/") or parts.query or parts.fragment):
        raise CredentialError("Expected an origin, not a full URL")
    if port == 0:
        raise CredentialError("Invalid port")

    host = host.rstrip(".").lower()
    if not host:
        raise CredentialError("Invalid hostname")

    try:
        addr = ipaddress.ip_address(host)
        host = f"[{addr.compressed}]" if addr.version == 6 else addr.compressed
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise CredentialError("Invalid hostname") from exc
        if len(host) > 253 or not all(
            len(lbl) <= 63 and _DNS_LABEL.fullmatch(lbl) for lbl in host.split(".")
        ):
            raise CredentialError("Invalid hostname")

    return f"{scheme}://{host}:{port or _DEFAULT_PORT[scheme]}"


def normalize_origin(origin: str) -> str:
    """Canonicalize a CONFIGURED origin (no path/query/fragment allowed)."""
    return _canonicalize(origin, origin_only=True)


def origin_of(url: str) -> str:
    """Canonical origin of a full request URL."""
    return _canonicalize(url, origin_only=False)


def _normalize_origins(origins) -> frozenset[str]:
    if isinstance(origins, (str, bytes)):
        raise CredentialError("Origins must be a collection, not a string")
    try:
        return frozenset(normalize_origin(o) for o in origins)
    except TypeError as exc:
        raise CredentialError("Invalid origins") from exc


# --------------------------------------------------------------------------
# Field validation
# --------------------------------------------------------------------------
def _validate_header_name(name) -> None:
    if not isinstance(name, str) or not _TOKEN.fullmatch(name):
        raise CredentialError("Invalid header name")


def _validate_header_value(value, *, allow_empty: bool) -> None:
    if not isinstance(value, str):
        raise CredentialError("Header value must be a string")
    if not value and not allow_empty:
        raise CredentialError("Empty header value")
    if len(value) > MAX_HEADER_VALUE or not value.isascii():
        raise CredentialError("Invalid header value")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise CredentialError("Control character in header value")


def _validate_pairs(pairs, kind: str) -> tuple:
    """Return an immutable tuple of validated (name, value) tuples."""
    if not isinstance(pairs, (list, tuple)):
        raise CredentialError("Pairs must be a list or tuple")
    out, seen = [], set()
    for pair in pairs:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise CredentialError("Each pair must have exactly two elements")
        name, value = pair
        _validate_header_name(name)  # cookie names use the same token rule
        if kind == "header":
            _validate_header_value(value, allow_empty=False)
            if name.lower() in FORBIDDEN_CREDENTIAL_HEADERS:
                raise CredentialError("Forbidden credential header")
            key = name.lower()            # header names: case-insensitive
        else:
            if (not isinstance(value, str) or len(value) > MAX_COOKIE_VALUE
                    or not _COOKIE_VALUE.fullmatch(value)):
                raise CredentialError("Invalid cookie value")
            key = name                    # cookie names: case-sensitive
        if key in seen:
            raise CredentialError("Duplicate name")
        seen.add(key)
        out.append((name, value))         # fresh tuple: later list mutation can't leak in
    return tuple(out)


# --------------------------------------------------------------------------
# Credential
# --------------------------------------------------------------------------
@dataclass(frozen=True, repr=False)
class Credential:
    headers: tuple = field(default_factory=tuple)
    cookies: tuple = field(default_factory=tuple)
    origins: frozenset = field(default_factory=frozenset)
    allow_insecure: bool = False

    def __post_init__(self):
        headers = _validate_pairs(self.headers, "header")
        cookies = _validate_pairs(self.cookies, "cookie")
        if not isinstance(self.origins, (set, frozenset, list, tuple)):
            raise CredentialError("Origins must be a collection")
        origins = _normalize_origins(self.origins)
        if not isinstance(self.allow_insecure, bool):
            raise CredentialError("allow_insecure must be a bool")

        if headers or cookies:
            if not origins:
                raise CredentialError("Authenticated credentials require allowed origins")
            if not self.allow_insecure and any(o.startswith("http://") for o in origins):
                raise CredentialError(
                    "Plaintext http origin requires allow_insecure=True"
                )

        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "cookies", cookies)
        object.__setattr__(self, "origins", origins)

    # -- constructors ------------------------------------------------------
    @classmethod
    def anonymous(cls) -> "Credential":
        return cls()

    @classmethod
    def bearer(cls, token, origins, *, allow_insecure: bool = False) -> "Credential":
        if not isinstance(token, str) or not _BEARER_TOKEN.fullmatch(token):
            raise CredentialError("Invalid bearer token")
        return cls(headers=(("Authorization", f"Bearer {token}"),),
                   origins=_normalize_origins(origins), allow_insecure=allow_insecure)

    @classmethod
    def cookie(cls, cookies: Mapping, origins, *, allow_insecure: bool = False) -> "Credential":
        if not isinstance(cookies, Mapping) or not cookies:
            raise CredentialError("Invalid cookies")
        return cls(cookies=tuple(cookies.items()),
                   origins=_normalize_origins(origins), allow_insecure=allow_insecure)

    @classmethod
    def custom(cls, headers: Mapping, origins, cookies: Mapping | None = None,
               *, allow_insecure: bool = False) -> "Credential":
        """API keys, opaque tokens, session cookie + CSRF header, Basic auth..."""
        if not isinstance(headers, Mapping):
            raise CredentialError("Invalid headers")
        if cookies is not None and not isinstance(cookies, Mapping):
            raise CredentialError("Invalid cookies")
        return cls(headers=tuple(headers.items()),
                   cookies=tuple((cookies or {}).items()),
                   origins=_normalize_origins(origins), allow_insecure=allow_insecure)

    # -- behaviour ---------------------------------------------------------
    @property
    def is_anonymous(self) -> bool:
        return not self.headers and not self.cookies

    def render(self) -> dict[str, str]:
        out = dict(self.headers)
        if self.cookies:
            out["Cookie"] = "; ".join(f"{n}={v}" for n, v in self.cookies)
        return out

    def __repr__(self) -> str:
        kind = "anonymous" if self.is_anonymous else "authenticated"
        return f"Credential({kind}, secrets=<redacted>, origins={sorted(self.origins)})"


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------
class CredentialStore:
    def __init__(self, credentials: Mapping[str, Credential]):
        if not isinstance(credentials, Mapping) or not credentials:
            raise CredentialError("Credentials cannot be empty")
        copied = {}
        for identity, cred in credentials.items():
            if (not isinstance(identity, str) or not identity or not identity.isascii()
                    or any(ord(c) < 33 or ord(c) == 127 for c in identity)):
                raise CredentialError("Invalid identity")
            if not isinstance(cred, Credential):
                raise CredentialError("Invalid credential object")
            copied[identity] = cred
        self._credentials = MappingProxyType(copied)

    def identities(self) -> frozenset:
        return frozenset(self._credentials)

    def has_identity(self, identity) -> bool:
        return isinstance(identity, str) and identity in self._credentials

    def apply(self, identity: str, url: str,
              request_headers: Mapping[str, str] | None = None) -> dict[str, str]:
        """
        Return request_headers + this identity's auth for exactly this URL.

        Raises if the credential is not bound to the URL's origin, or if the
        caller's headers collide with auth headers (any casing).
        """
        cred = self._credentials.get(identity) if isinstance(identity, str) else None
        if cred is None:
            raise CredentialError("Unknown credential identity")

        origin = origin_of(url)          # same canonicalizer as the config side
        if not cred.is_anonymous and origin not in cred.origins:
            raise CredentialError("Credential is not authorized for this origin")

        if request_headers is None:
            request_headers = {}
        if not isinstance(request_headers, Mapping):
            raise CredentialError("Request headers must be a mapping")

        auth = cred.render()
        protected = ALWAYS_PROTECTED | {n.lower() for n in auth}

        result, seen = {}, set()
        for name, value in request_headers.items():
            _validate_header_name(name)
            _validate_header_value(value, allow_empty=True)
            lower = name.lower()
            if lower in seen:
                raise CredentialError("Duplicate request header")
            seen.add(lower)
            if lower in protected or lower in FORBIDDEN_CREDENTIAL_HEADERS:
                raise CredentialError(f"Protected or forbidden header: {name}")
            result[name] = value

        result.update(auth)
        return result