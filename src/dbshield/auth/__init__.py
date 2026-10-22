"""Authentication and session management package for DBShield.

Provides target-bound session isolation, cookie persistence,
and credential injection.
"""

from dbshield.auth.manager import SessionManager

__all__ = ["SessionManager"]
