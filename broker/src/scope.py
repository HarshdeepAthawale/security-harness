import ipaddress
import re

import httpx

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
    """Normalize a hostname for consistent comparison."""

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
    except UnicodeError as exc:
        raise ValueError("Invalid hostname") from exc

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
# TARGET ORIGIN VALIDATION
# --------------------------------------------------

def normalize_origin(base_url: str) -> str:
    """
    Validate and normalize the trusted engagement target.

    Only an origin is accepted:
        https://example.com

    Paths, queries and fragments are not accepted.
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

        if parsed.netloc.endswith(":"):
            raise ValueError("Empty target port")

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
    The canonical form is only used for authorization.
    """

    if not isinstance(path, str) or not path.startswith("/"):
        raise ScopeViolation("Invalid request path")

    if path.startswith("//"):
        raise ScopeViolation("Protocol-relative paths are not allowed")

    if "?" in path or "#" in path:
        raise ScopeViolation("Query and fragments are not allowed in path")

    current = path

    for _ in range(7):

        if "\\" in current:
            raise ScopeViolation("Backslashes are not allowed")

        if any(ord(char) < 32 or ord(char) == 127 for char in current):
            raise ScopeViolation("Control characters in path")

        if re.search(r"%(?![0-9a-fA-F]{2})", current):
            raise ScopeViolation("Malformed URL encoding")

        segments = current.split("/")

        for index, segment in enumerate(segments):

            # Allow only leading and trailing empty segments.
            if not segment:
                if index not in (0, len(segments) - 1):
                    raise ScopeViolation("Empty path segment")
                continue

            # Account for path parameters such as ..; and .;
            segment_without_params = segment.split(";", 1)[0]

            if segment_without_params in {".", ".."}:
                raise ScopeViolation("Path traversal detected")

        decoded = unquote(current)

        if decoded == current:
            return current

        current = decoded

    # If decoding still changes the path after seven passes,
    # reject it rather than authorize an ambiguous representation.
    if unquote(current) != current:
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
    # MAIN VALIDATION
    # --------------------------------------------------

    def validate(self, plan: RequestPlan) -> str:
        """
        Validate the complete request against engagement scope.

        Returns the canonical destination URL (trusted origin + validated
        path + encoded query). This exact string must be what the executor
        sends; the service must compare it to ExecutionRequest.url.

        Host headers are not caller-controllable (plan.py reserves them), so
        the destination and Host always come from the trusted origin.
        """

        self._check_method(plan)
        self._check_pack(plan)
        self._check_identity(plan)
        self._check_path(plan)

        if any(name.lower() == "host" for name in plan.headers):
            raise ScopeViolation("Host header override is not supported")

        return self._canonical_url(plan)

    def _canonical_url(self, plan: RequestPlan) -> str:

        try:
            url = httpx.URL(self.origin + plan.path, params=plan.query or None)
        except (httpx.InvalidURL, ValueError, TypeError) as exc:
            raise ScopeViolation("Request URL cannot be constructed") from exc

        canonical = str(url)

        # The path/host the client will send must be exactly what was
        # authorized: no re-encoding, no host change.
        if canonical.split("?", 1)[0] != self.origin + plan.path:
            raise ScopeViolation("Request URL is not in canonical form")

        return canonical
