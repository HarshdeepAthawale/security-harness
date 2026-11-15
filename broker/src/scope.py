import hashlib
import ipaddress
import json
import re

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode, urlsplit, unquote

from .errors import PlanError
from .plan import RequestPlan, path_problem


# --------------------------------------------------
# EXCEPTIONS
# --------------------------------------------------

class ScopeViolation(Exception):
    """Request violates the authorized engagement scope."""
    pass


# --------------------------------------------------
# HOST NORMALIZATION
# --------------------------------------------------

def normalize_hostname(host: str) -> str:
    """
    Normalize a hostname for consistent comparison.
    """

    if not isinstance(host, str) or not host:
        raise ValueError("Hostname cannot be empty")

    host = host.rstrip(".")

    if not host:
        raise ValueError("Invalid hostname")

    if any(char.isspace() for char in host):
        raise ValueError("Whitespace in hostname")

    if any(char in host for char in "/\\@?#"):
        raise ValueError("Invalid hostname characters")

    # IP address.
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass

    try:
        hostname = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("Invalid hostname")

    if len(hostname) > 253:
        raise ValueError("Hostname too long")

    labels = hostname.split(".")

    for label in labels:

        if not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
            label,
        ):
            raise ValueError("Invalid hostname label")

    return hostname


# --------------------------------------------------
# HOST HEADER NORMALIZATION
# --------------------------------------------------

def normalize_host_header(value: str) -> str:
    """
    Normalize a Host header value.

    Examples:
        Example.com       -> example.com
        Example.com:443   -> example.com:443
        [::1]:8080        -> [::1]:8080
    """

    if not isinstance(value, str) or not value:
        raise ValueError("Host header cannot be empty")

    try:
        parsed = urlsplit("//" + value)

        if (
            not parsed.hostname
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("Invalid Host header")

        hostname = normalize_hostname(parsed.hostname)

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid port")

        # IPv6 requires square brackets in Host syntax.
        if ":" in hostname:
            hostname = f"[{hostname}]"

        if port is not None:
            return f"{hostname}:{port}"

        return hostname

    except (ValueError, UnicodeError):
        raise ValueError("Malformed Host header")


# --------------------------------------------------
# TARGET ORIGIN VALIDATION
# --------------------------------------------------

def normalize_origin(base_url: str) -> str:
    """
    Validate and normalize the trusted engagement target.

    Only an origin is accepted:
        https://example.com

    Paths, queries and fragments are not accepted here.
    """

    if not isinstance(base_url, str) or not base_url:
        raise ValueError("Target URL cannot be empty")

    try:
        parsed = urlsplit(base_url)

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS are supported")

        if not parsed.hostname:
            raise ValueError("Target hostname is missing")

        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials in target URL are not allowed")

        if parsed.path not in {"", "/"}:
            raise ValueError("base_url must contain only an origin")

        if parsed.query or parsed.fragment:
            raise ValueError("Query and fragment are not allowed")

        hostname = normalize_hostname(parsed.hostname)

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Invalid target port")

        if port == 80 and scheme == "http":
            port = None

        if port == 443 and scheme == "https":
            port = None

        if ":" in hostname:
            hostname = f"[{hostname}]"

        if port is not None:
            return f"{scheme}://{hostname}:{port}"

        return f"{scheme}://{hostname}"

    except ValueError:
        raise

    except Exception as exc:
        raise ValueError("Invalid target URL") from exc


# --------------------------------------------------
# PATH HELPERS
# --------------------------------------------------

def canonicalize_path(path: str) -> str:
    """
    Decode the path for scope comparison.

    The original request path is still sent to the target.
    This canonical form is only used to check authorization.
    """

    # Same rules as the plan model (traversal incl. '..;', '//', control
    # characters incl. decoded %00, backslashes, nested encoding).
    problem = path_problem(path)

    if problem == "backslash":
        raise ScopeViolation("Backslashes are not allowed")

    if problem == "dot segment":
        raise ScopeViolation("Path traversal detected")

    if problem == "too many encoding layers":
        raise ScopeViolation("Excessively encoded path")

    if problem:
        raise ScopeViolation(f"Unsafe path: {problem}")

    current = path

    for _ in range(6):

        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    return current


def path_matches_prefix(path: str, prefix: str) -> bool:
    """
    Boundary-aware matching.

    /api/orders matches:
        /api/orders
        /api/orders/123

    It does not match:
        /api/orders-admin
    """

    prefix = prefix.rstrip("/") or "/"

    if prefix == "/":
        return path.startswith("/")

    return path == prefix or path.startswith(prefix + "/")


# --------------------------------------------------
# TRUSTED ENGAGEMENT POLICY
# --------------------------------------------------

@dataclass(frozen=True)
class ScopePolicy:

    # Trusted target origin.
    base_url: str

    # Authorized HTTP methods.
    allowed_methods: frozenset[str]

    # Authorized path prefixes.
    # Use ("/",) for the entire application.
    allowed_path_prefixes: tuple[str, ...]

    # Authorized security testing packs.
    allowed_packs: frozenset[str]

    # Authorized test identities.
    allowed_identities: frozenset[str]

    # Host-header testing requires explicit authorization.
    allow_host_header_override: bool = False

    # Optional Host header allowlist.
    allowed_host_header_values: frozenset[str] = frozenset()

    # Private / loopback networks the target is allowed to resolve to, e.g.
    # ("127.0.0.0/8",) for a local crAPI. Public addresses never need listing;
    # without this, a target on a private address is refused (SSRF guard).
    allowed_cidrs: tuple[str, ...] = ()

    # Target-identity fingerprint (PROJECT.md 7.1): a GET to this path must
    # answer `identity_probe_status` with `identity_probe_marker` in the body,
    # or the run doesn't start. Unset = the broker can't prove it is talking
    # to the intended app, so check_identity() fails closed.
    identity_probe_path: str | None = None
    identity_probe_status: int = 200
    identity_probe_marker: str = ""


# --------------------------------------------------
# RESOLVED TARGET + VALIDATED REQUEST
# --------------------------------------------------

@dataclass(frozen=True)
class Scope:
    """The one place requests may go. Everything here comes from the trusted
    policy, never from a plan."""

    scheme: str
    host: str
    port: int
    allowed_cidrs: tuple = ()


_MINT = object()          # only this module can build a ValidatedRequest


def _request_hash(method: str, url: str, headers: dict, body: bytes | None, identity: str | None) -> str:
    material = json.dumps(
        {
            "method": method,
            "url": url,
            "headers": sorted((k.lower(), v) for k, v in headers.items()),
            "body": body.hex() if body is not None else None,
            "identity": identity,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode()).hexdigest()


@dataclass(frozen=True)
class ValidatedRequest:
    """A request that passed the scope check. The executor only accepts this
    type, so a plan can't reach the network without going through
    ScopeValidator.build(). `identity` is None only for the readiness probe,
    which is sent without a credential."""

    method: str
    url: str
    path: str
    query: dict
    headers: dict
    body: bytes | None
    identity: str | None
    pack: str
    replay_safe: bool
    request_hash: str
    target: Scope
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self):
        if self._token is not _MINT:
            raise TypeError("ValidatedRequest can only be created by ScopeValidator")

    def verify(self) -> None:
        """Refuse a request whose fields no longer match what was validated,
        or whose URL points anywhere but the scope's target."""
        parts = urlsplit(self.url)
        if parts.scheme != self.target.scheme or parts.hostname is None:
            raise ValueError("request_tampered")
        if parts.path != self.path:
            raise ValueError("request_tampered")
        expected = _request_hash(self.method, self.url, self.headers, self.body, self.identity)
        if expected != self.request_hash:
            raise ValueError("request_tampered")


# --------------------------------------------------
# SCOPE VALIDATOR
# --------------------------------------------------

class ScopeValidator:

    def __init__(self, policy: ScopePolicy):

        self.policy = policy

        # Validate trusted target configuration.
        self.origin = normalize_origin(policy.base_url)

        if not policy.allowed_methods:
            raise ValueError("At least one HTTP method is required")

        if not policy.allowed_path_prefixes:
            raise ValueError("At least one path prefix is required")

        if not policy.allowed_packs:
            raise ValueError("At least one testing pack is required")

        if not policy.allowed_identities:
            raise ValueError("At least one identity is required")

        # Validate configured path prefixes.
        for prefix in policy.allowed_path_prefixes:

            if not isinstance(prefix, str) or not prefix.startswith("/"):
                raise ValueError("Invalid path prefix")

            if prefix.startswith("//"):
                raise ValueError("Invalid path prefix")

            if "\\" in prefix or "?" in prefix or "#" in prefix:
                raise ValueError("Invalid path prefix")

            canonicalize_path(prefix)

        # Normalize Host allowlist once.
        normalized_hosts = set()

        for host in policy.allowed_host_header_values:

            normalized_hosts.add(
                normalize_host_header(host)
            )

        self.allowed_hosts = frozenset(normalized_hosts)

        # The resolved target the DNS guard and executor connect to.
        parts = urlsplit(self.origin)
        host = parts.hostname

        try:
            cidrs = tuple(ipaddress.ip_network(c, strict=False) for c in policy.allowed_cidrs)
        except ValueError as exc:
            raise ValueError("Invalid allowed_cidrs entry") from exc

        self.target = Scope(
            scheme=parts.scheme,
            host=host,
            port=parts.port or (443 if parts.scheme == "https" else 80),
            allowed_cidrs=cidrs,
        )

        if policy.identity_probe_path is not None:
            canonicalize_path(policy.identity_probe_path)

            if not policy.identity_probe_path.startswith("/") or "?" in policy.identity_probe_path:
                raise ValueError("Invalid identity probe path")

            if not policy.identity_probe_marker:
                raise ValueError("identity_probe_marker is required with identity_probe_path")

    # --------------------------------------------------
    # METHOD CHECK
    # --------------------------------------------------

    def _check_method(self, plan: RequestPlan):

        if plan.method not in self.policy.allowed_methods:
            raise ScopeViolation(
                "HTTP method is outside authorized scope"
            )

    # --------------------------------------------------
    # PACK CHECK
    # --------------------------------------------------

    def _check_pack(self, plan: RequestPlan):

        if plan.pack not in self.policy.allowed_packs:
            raise ScopeViolation(
                "Testing pack is not authorized"
            )

    # --------------------------------------------------
    # IDENTITY CHECK
    # --------------------------------------------------

    def _check_identity(self, plan: RequestPlan):

        if plan.identity not in self.policy.allowed_identities:
            raise ScopeViolation(
                "Identity is not authorized"
            )

    # --------------------------------------------------
    # PATH CHECK
    # --------------------------------------------------

    def _check_path(self, plan: RequestPlan):

        self._check_path_value(plan.path)

    def _check_path_value(self, raw_path: str):

        path = canonicalize_path(raw_path)

        for prefix in self.policy.allowed_path_prefixes:

            canonical_prefix = canonicalize_path(prefix)

            if path_matches_prefix(path, canonical_prefix):
                return

        raise ScopeViolation(
            "Path is outside authorized scope"
        )

    # --------------------------------------------------
    # HOST HEADER CHECK
    # --------------------------------------------------

    def _check_host_header(self, plan: RequestPlan):

        host_value = next(
            (
                value
                for name, value in plan.headers.items()
                if name.lower() == "host"
            ),
            None,
        )

        # No override requested.
        if host_value is None:
            return

        if not self.policy.allow_host_header_override:
            raise ScopeViolation(
                "Host header override is not authorized"
            )

        normalized_host = normalize_host_header(host_value)

        # If an allowlist exists, enforce it.
        if self.allowed_hosts:

            if normalized_host not in self.allowed_hosts:
                raise ScopeViolation(
                    "Host header value is not authorized"
                )

    # --------------------------------------------------
    # MAIN VALIDATION
    # --------------------------------------------------

    def validate(self, plan: RequestPlan) -> str:

        self._check_method(plan)

        self._check_pack(plan)

        self._check_identity(plan)

        self._check_path(plan)

        self._check_host_header(plan)

        # Destination comes exclusively from trusted configuration.
        # The Kernel never supplies the hostname.
        return self.origin + plan.path

    # --------------------------------------------------
    # BUILD A SENDABLE REQUEST
    # --------------------------------------------------

    def build(self, plan: RequestPlan) -> ValidatedRequest:
        """Validate a plan and turn it into the only thing the executor will
        send. Raises ScopeViolation if anything is out of scope."""

        url = self.validate(plan)

        query = {
            key: ([_query_value(v) for v in value] if isinstance(value, list) else _query_value(value))
            for key, value in plan.query.items()
        }
        query_string = urlencode(query, doseq=True)

        body = None
        headers = dict(plan.headers)

        if plan.body is not None:
            body = json.dumps(plan.body, allow_nan=False, separators=(",", ":")).encode("utf-8")

            if not any(name.lower() == "content-type" for name in headers):
                headers["Content-Type"] = "application/json"

        if query_string:
            url = url + "?" + query_string

        return self._mint(
            method=plan.method, url=url, path=plan.path, query=query, headers=headers,
            body=body, identity=plan.identity, pack=plan.pack,
        )

    def build_probe(self) -> ValidatedRequest | None:
        """The readiness request (PROJECT.md 7.1), or None if the policy has
        no identity fingerprint. Sent WITHOUT a credential."""

        path = self.policy.identity_probe_path

        if path is None:
            return None

        if "GET" not in self.policy.allowed_methods:
            raise ScopeViolation("HTTP method is outside authorized scope")

        # The probe path is chosen by whoever wrote the scope file (it is policy,
        # not agent input), so it need not sit inside allowed_path_prefixes: a
        # target's only unauthenticated page is often "/", and listing "/" as a
        # prefix would open the whole site to plans. It still has to be a safe path.
        canonicalize_path(path)

        return self._mint(
            method="GET", url=self.origin + path, path=path, query={}, headers={},
            body=None, identity=None, pack="identity-probe",
        )

    def _mint(self, *, method, url, path, query, headers, body, identity, pack) -> ValidatedRequest:
        return ValidatedRequest(
            method=method,
            url=url,
            path=path,
            query=query,
            headers=headers,
            body=body,
            identity=identity,
            pack=pack,
            replay_safe=method in {"GET", "HEAD", "OPTIONS"},
            request_hash=_request_hash(method, url, headers, body, identity),
            target=self.target,
            _token=_MINT,
        )


def _query_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


# --------------------------------------------------
# PARSING + LOADING
# --------------------------------------------------

def parse_plan(raw: bytes, validator: ScopeValidator) -> ValidatedRequest:
    """JSON bytes -> RequestPlan -> ValidatedRequest. Any failure is a
    PlanError (bad JSON / bad shape) or ScopeViolation (valid but not allowed)."""

    try:
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise PlanError("invalid_plan") from exc

    if not isinstance(data, dict):
        raise PlanError("invalid_plan")

    return validator.build(RequestPlan(**data))


def load_scope(path: str | Path) -> ScopeValidator:
    """Build a validator from a scope file (JSON). Example:

        {
          "base_url": "http://127.0.0.1:8888",
          "allowed_methods": ["GET"],
          "allowed_path_prefixes": ["/api"],
          "allowed_packs": ["idor-bola"],
          "allowed_identities": ["user_A", "user_B"],
          "allowed_cidrs": ["127.0.0.0/8"],
          "identity_probe": {"path": "/api/health", "status": 200, "marker": "my-app"}
        }
    """

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    probe = data.get("identity_probe") or {}

    return ScopeValidator(ScopePolicy(
        base_url=data["base_url"],
        allowed_methods=frozenset(m.upper() for m in data["allowed_methods"]),
        allowed_path_prefixes=tuple(data["allowed_path_prefixes"]),
        allowed_packs=frozenset(data["allowed_packs"]),
        allowed_identities=frozenset(data["allowed_identities"]),
        allow_host_header_override=bool(data.get("allow_host_header_override", False)),
        allowed_host_header_values=frozenset(data.get("allowed_host_header_values", [])),
        allowed_cidrs=tuple(data.get("allowed_cidrs", [])),
        identity_probe_path=probe.get("path"),
        identity_probe_status=int(probe.get("status", 200)),
        identity_probe_marker=probe.get("marker", ""),
    ))
