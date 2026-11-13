import ipaddress
import re

from dataclasses import dataclass
from urllib.parse import urlsplit, unquote

from broker.src.plan import RequestPlan


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

    current = path

    for _ in range(6):

        if "\\" in current:
            raise ScopeViolation("Backslashes are not allowed")

        segments = current.split("/")

        if any(segment in {".", ".."} for segment in segments):
            raise ScopeViolation("Path traversal detected")

        decoded = unquote(current)

        if decoded == current:
            break

        current = decoded

    else:
        # Too many nested encoding layers.
        raise ScopeViolation("Excessively encoded path")

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

        path = canonicalize_path(plan.path)

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