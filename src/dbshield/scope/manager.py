"""Target scope management and boundary enforcement.

Validates that targets and redirect destinations strictly adhere to authorized
schemes, ports, exact hostnames, and permitted subdomain policies.
"""

from urllib.parse import urljoin, urlparse

from dbshield.exceptions import ScopeViolationError, URLValidationError
from dbshield.models.target import Target


class ScopeManager:
    """Enforces boundary scope rules on target URLs, hosts, and HTTP redirects."""

    def __init__(
        self,
        allowed_hosts: list[str] | None = None,
        allow_subdomains: bool = False,
        allowed_schemes: set[str] | None = None,
        allowed_ports: set[int] | None = None,
        strict_mode: bool = True,
    ) -> None:
        """Initialize ScopeManager.

        Args:
            allowed_hosts: Explicit list of authorized hostnames/domains.
            allow_subdomains: If True, *.domain.com is authorized when domain.com is allowed.
            allowed_schemes: Set of permitted schemes (defaults to {'http', 'https'}).
            allowed_ports: Optional set of permitted TCP ports.
            strict_mode: If True and allowed_hosts is empty, rejects all hosts as out-of-scope.
        """
        self.allowed_hosts: set[str] = set()
        if allowed_hosts:
            for h in allowed_hosts:
                self.add_allowed_host(h)

        self.allow_subdomains = allow_subdomains
        self.allowed_schemes = allowed_schemes or {"http", "https"}
        self.allowed_ports = allowed_ports
        self.strict_mode = strict_mode

    @classmethod
    def normalize_host(cls, host: str) -> str:
        """Normalize hostname to lowercase and strip whitespace, trailing dots, and ports."""
        if not host:
            return ""
        stripped = host.strip().lower().rstrip(".")
        # Strip scheme if present
        if "://" in stripped:
            stripped = stripped.split("://", 1)[1]
        # Strip path
        if "/" in stripped:
            stripped = stripped.split("/", 1)[0]
        # Strip port (handle IPv6 vs IPv4)
        if stripped.startswith("[") and "]" in stripped:
            # IPv6 literal
            stripped = stripped.split("]", 1)[0] + "]"
        elif ":" in stripped:
            stripped = stripped.split(":", 1)[0]
        return stripped

    def add_allowed_host(self, host: str) -> None:
        """Add an authorized hostname to scope."""
        norm = self.normalize_host(host)
        if norm:
            self.allowed_hosts.add(norm)

    def is_host_in_scope(self, host: str) -> bool:
        """Check if a hostname is authorized under current scope rules."""
        norm_host = self.normalize_host(host)
        if not norm_host:
            return False

        if not self.allowed_hosts:
            # If allowed_hosts is empty and strict_mode is True, nothing is allowed
            return not self.strict_mode

        # 1. Exact match check
        if norm_host in self.allowed_hosts:
            return True

        # 2. Subdomain check (only if explicitly enabled)
        if self.allow_subdomains:
            for allowed in self.allowed_hosts:
                # Must end with '.allowed' to prevent 'evil-example.com' or 'example.com.attacker.com'
                if norm_host.endswith(f".{allowed}"):
                    return True

        return False

    def is_url_in_scope(self, url: str | Target) -> bool:
        """Check whether a target URL is within authorized scope."""
        try:
            target = url if isinstance(url, Target) else Target.from_url(url)
        except URLValidationError:
            return False

        # Validate scheme
        if target.scheme not in self.allowed_schemes:
            return False

        # Validate port if restricted
        if self.allowed_ports is not None and target.port not in self.allowed_ports:
            return False

        # Validate host
        return self.is_host_in_scope(target.host)

    def assert_in_scope(self, url: str | Target) -> Target:
        """Assert that a target URL is in scope, raising ScopeViolationError if not.

        Returns:
            Validated Target instance.

        Raises:
            ScopeViolationError: If target URL or host falls outside authorized scope.
            URLValidationError: If URL cannot be parsed.
        """
        target = url if isinstance(url, Target) else Target.from_url(url)

        if target.scheme not in self.allowed_schemes:
            raise ScopeViolationError(
                message=f"Target scheme '{target.scheme}' is not authorized.",
                cause=f"Scheme '{target.scheme}' is outside permitted schemes {self.allowed_schemes}.",
                remedy=f"Use one of authorized schemes: {', '.join(sorted(self.allowed_schemes))}.",
                context={"scheme": target.scheme, "url": target.raw_url},
            )

        if self.allowed_ports is not None and target.port not in self.allowed_ports:
            raise ScopeViolationError(
                message=f"Target port '{target.port}' is not authorized.",
                cause=f"Port {target.port} is not in the allowed ports list.",
                remedy=f"Configure scope to allow port {target.port} or target standard ports.",
                context={"port": target.port, "url": target.raw_url},
            )

        if not self.is_host_in_scope(target.host):
            subdomain_hint = (
                " (subdomains are currently disabled)" if not self.allow_subdomains else ""
            )
            raise ScopeViolationError(
                message=f"Target host '{target.host}' is out of authorized scope.",
                cause=f"Host '{target.host}' does not match allowed hosts {sorted(self.allowed_hosts)}{subdomain_hint}.",
                remedy=f"Authorize '{target.host}' in configuration (DBSHIELD_ALLOWED_HOSTS) before testing.",
                context={"host": target.host, "allowed_hosts": list(self.allowed_hosts)},
            )

        return target

    def validate_redirect(self, original_url: str | Target, redirect_url_str: str) -> Target:
        """Validate an HTTP redirect destination before following it.

        Supports resolving relative redirects against the original target URL.

        Raises:
            ScopeViolationError: If the redirect destination attempts to leave scope.
        """
        orig_base = original_url.full_url if isinstance(original_url, Target) else original_url

        # Resolve relative redirect if needed
        resolved_url = urljoin(orig_base, redirect_url_str.strip())
        parsed = urlparse(resolved_url)

        if not parsed.scheme or not parsed.hostname:
            raise ScopeViolationError(
                message=f"Redirect destination '{redirect_url_str}' is malformed.",
                cause="Could not parse valid scheme and host from redirect target.",
                remedy="Inspect server response for invalid Location header.",
            )

        try:
            target = Target.from_url(resolved_url)
            self.assert_in_scope(target)
            return target
        except (ScopeViolationError, URLValidationError) as exc:
            raise ScopeViolationError(
                message=f"Redirect to '{resolved_url}' is prohibited by scope policy.",
                cause=f"Redirect destination host or scheme is out-of-scope: {exc}",
                remedy="Ensure the target application does not redirect outside authorized test scope.",
                context={"original": orig_base, "redirect": resolved_url},
            ) from exc
