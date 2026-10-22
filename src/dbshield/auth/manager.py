"""Session and authentication state manager for DBShield Phase 3.

Provides target-bound session isolation, cookie persistence across requests,
credential injection without leakage across origins, and explainable
authentication lifecycle tracking.
"""

import logging
from http.cookies import SimpleCookie
from urllib.parse import urlparse

from dbshield.exceptions import AuthenticationError
from dbshield.models.auth import AuthConfig, AuthState, AuthType
from dbshield.models.http import HTTPResponse
from dbshield.models.target import Target

logger = logging.getLogger("dbshield.auth")


class SessionManager:
    """Manages authentication headers, cookies, and state for an assessment session."""

    def __init__(
        self,
        auth_config: AuthConfig | None = None,
        target_origin: str | None = None,
    ) -> None:
        """Initialize SessionManager.

        Args:
            auth_config: Authentication configuration profile.
            target_origin: Optional origin string (e.g. 'https://example.com:443') to bind session to.
        """
        self.auth_config = auth_config or AuthConfig(auth_type=AuthType.NONE)
        self.target_origin: str | None = (
            self._normalize_origin(target_origin) if target_origin else None
        )

        # Cookie jar: name -> value
        self.cookies: dict[str, str] = dict(self.auth_config.cookies)

        # Initial state determination
        if self.auth_config.auth_type == AuthType.NONE:
            self.state = AuthState.NOT_CONFIGURED
        else:
            self.state = AuthState.CONFIGURED

    @staticmethod
    def _normalize_origin(url_or_origin: str) -> str:
        """Extract and normalize scheme://host:port origin from a URL or origin string."""
        parsed = urlparse(url_or_origin)
        scheme = (parsed.scheme or "http").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        default_port = 443 if scheme == "https" else 80
        if port == default_port:
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def is_origin_compatible(self, url: str | Target) -> bool:
        """Verify whether target URL belongs to the same origin bound to this session."""
        if self.target_origin is None:
            return True
        target_str = url.full_url if isinstance(url, Target) else str(url)
        origin = self._normalize_origin(target_str)
        return origin == self.target_origin

    def bind_target(self, url: str | Target) -> None:
        """Bind session to a target origin if not already bound."""
        if self.target_origin is None:
            target_str = url.full_url if isinstance(url, Target) else str(url)
            self.target_origin = self._normalize_origin(target_str)
            logger.debug("Session bound to target origin: %s", self.target_origin)

    def apply_auth(
        self,
        url: str | Target,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> tuple[dict[str, str], dict[str, str]]:
        """Apply session authentication headers and cookies to an outbound request.

        Enforces origin isolation: refuses to leak credentials or cookies to cross-origin targets.

        Args:
            url: Outbound request target URL.
            headers: Optional existing request headers.
            cookies: Optional existing request cookies.

        Returns:
            Tuple of updated (headers, cookies).

        Raises:
            AuthenticationError: If request attempts to use credentials on an incompatible cross-origin target.
        """
        out_headers = dict(headers or {})
        out_cookies = dict(cookies or {})

        # Bind to origin if first request
        if self.target_origin is None:
            self.bind_target(url)

        # Verify origin isolation
        if not self.is_origin_compatible(url):
            target_str = url.full_url if isinstance(url, Target) else str(url)
            target_origin = self._normalize_origin(target_str)
            raise AuthenticationError(
                message=f"Refused to transmit session credentials to cross-origin destination '{target_origin}'.",
                cause=f"Session is bound to origin '{self.target_origin}'.",
                remedy="Create a separate SessionManager instance for distinct target origins.",
                context={"session_origin": self.target_origin, "target_origin": target_origin},
            )

        # Inject configured authentication headers
        auth_headers = self.auth_config.build_headers()
        out_headers.update(auth_headers)

        # Merge session cookies (caller cookies take precedence over stored session cookies)
        merged_cookies = dict(self.cookies)
        merged_cookies.update(out_cookies)

        return out_headers, merged_cookies

    def record_cookies_from_headers(self, headers: dict[str, str] | list[tuple[str, str]]) -> None:
        """Parse Set-Cookie headers from server response and update session cookie store."""
        cookie_parser = SimpleCookie()

        if isinstance(headers, dict):
            # In dict, Set-Cookie may be single or lowercase
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    try:
                        cookie_parser.load(v)
                    except Exception as exc:
                        logger.warning("Failed to parse Set-Cookie header '%s': %s", v, exc)
        else:
            for k, v in headers:
                if k.lower() == "set-cookie":
                    try:
                        cookie_parser.load(v)
                    except Exception as exc:
                        logger.warning("Failed to parse Set-Cookie header '%s': %s", v, exc)

        for name, morsel in cookie_parser.items():
            self.cookies[name] = morsel.value
            logger.debug("Session cookie recorded: %s", name)

    def update_from_response(self, response: HTTPResponse) -> None:
        """Update session cookies and evaluate authentication state from response.

        Guarantees:
        - 401 Unauthorized transitions state to UNAUTHENTICATED.
        - 403 Forbidden does NOT assume expiration (remains UNKNOWN or unchanged).
        - 200 OK does NOT automatically claim AUTHENTICATED without evidence (transitions CONFIGURED -> UNKNOWN).
        """
        # 1. Ingest any Set-Cookie headers
        self.record_cookies_from_headers(response.headers)

        # 2. State evaluation
        if response.status_code == 401:
            self.state = AuthState.UNAUTHENTICATED
            logger.info(
                "Server returned 401 Unauthorized; session state transitioned to UNAUTHENTICATED."
            )

        elif response.status_code == 403:
            # 403 may mean insufficient permissions on an authenticated endpoint, or IP block, or CSRF fail.
            # Preserving distinction per Section 6 requirements.
            logger.info(
                "Server returned 403 Forbidden; preserving current session state (%s).", self.state
            )

        elif response.status_code == 200:
            if self.state == AuthState.CONFIGURED:
                # Per requirement 5.3: Do NOT claim authenticated solely because 200 was returned.
                self.state = AuthState.UNKNOWN
                logger.debug(
                    "Request succeeded with configured credentials; state is UNKNOWN pending validation."
                )

    def reset(self) -> None:
        """Reset session cookies and restore initial configured state."""
        self.cookies.clear()
        self.cookies.update(self.auth_config.cookies)
        self.state = (
            AuthState.CONFIGURED
            if self.auth_config.auth_type != AuthType.NONE
            else AuthState.NOT_CONFIGURED
        )
        logger.debug("Session state reset.")

    def invalidate(self) -> None:
        """Explicitly invalidate session, clearing cookies and setting state to EXPIRED."""
        self.cookies.clear()
        self.state = AuthState.EXPIRED
        logger.info("Session explicitly invalidated (state=EXPIRED).")
