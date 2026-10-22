"""Response normalization and dynamic element masking for NoSQL differential analysis.

Provides deterministic cleaning of volatile content (timestamps, CSRF tokens,
session nonces, UUIDs, MongoDB ObjectIds) to allow meaningful differential comparisons
between baseline and test responses.
"""

import difflib
import hashlib
import re

from dbshield.logging_config import SensitiveDataFilter

# Regex patterns for volatile dynamic values
RE_TIMESTAMP_ISO = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
RE_TIMESTAMP_RFC = re.compile(
    r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:\s+GMT)?\b",
    re.IGNORECASE,
)
RE_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)
RE_UNIX_EPOCH = re.compile(r"\b1[6789]\d{8,11}\b")
RE_CSRF_FIELD = re.compile(
    r'(name=["\'](?:csrf[-_]?token|_token|authenticity_token|nonce)["\']\s+value=["\'])([^"\']+)(["\'])',
    re.IGNORECASE,
)
RE_JSON_CSRF = re.compile(
    r'("(?:csrf[-_]?token|_token|nonce|request_id|trace_id|session_id)":\s*")([^"]+)(")',
    re.IGNORECASE,
)
# MongoDB 24-hex-char ObjectID pattern
RE_MONGO_OBJECTID = re.compile(
    r'\b(?:ObjectId\(["\']([0-9a-f]{24})["\']\)|[0-9a-f]{24})\b', re.IGNORECASE
)
RE_WHITESPACE = re.compile(r"\s+")


class NoSQLResponseNormalizer:
    """Normalizes HTTP response bodies to isolate structural differences for NoSQL testing."""

    @classmethod
    def normalize(cls, body: str, strip_volatile: bool = True) -> str:
        """Normalize response text by removing volatile elements and collapsing whitespace.

        Args:
            body: Raw response body string.
            strip_volatile: Whether to replace timestamps, UUIDs, ObjectIds, and tokens.

        Returns:
            Normalized, reproducible text body.
        """
        if not body:
            return ""

        # First redact any known secret formats
        cleaned = SensitiveDataFilter.redact(body)

        if strip_volatile:
            # Mask UUIDs
            cleaned = RE_UUID.sub("[DYNAMIC_UUID]", cleaned)
            # Mask MongoDB ObjectIDs (both explicit ObjectId("...") and raw 24-hex strings)
            cleaned = RE_MONGO_OBJECTID.sub("[DYNAMIC_OBJECTID]", cleaned)
            # Mask CSRF form tokens
            cleaned = RE_CSRF_FIELD.sub(r"\1[DYNAMIC_CSRF_TOKEN]\3", cleaned)
            # Mask JSON tokens and IDs
            cleaned = RE_JSON_CSRF.sub(r"\1[DYNAMIC_TOKEN]\3", cleaned)
            # Mask ISO-8601 timestamps
            cleaned = RE_TIMESTAMP_ISO.sub("[DYNAMIC_TIMESTAMP]", cleaned)
            # Mask RFC timestamps
            cleaned = RE_TIMESTAMP_RFC.sub("[DYNAMIC_TIMESTAMP]", cleaned)
            # Mask UNIX epoch timestamps
            cleaned = RE_UNIX_EPOCH.sub("[DYNAMIC_EPOCH]", cleaned)

        # Collapse whitespace
        cleaned = RE_WHITESPACE.sub(" ", cleaned).strip()
        return cleaned

    @classmethod
    def compute_hash(cls, normalized_body: str) -> str:
        """Compute SHA-256 hash of normalized response body."""
        return hashlib.sha256(normalized_body.encode("utf-8", errors="replace")).hexdigest()

    @classmethod
    def compute_similarity(cls, text_a: str, text_b: str) -> float:
        """Calculate similarity ratio between two normalized response texts (0.0 to 1.0).

        Uses SequenceMatcher for structural similarity scoring.
        """
        if text_a == text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0

        # Fast path if lengths are vastly different
        len_a, len_b = len(text_a), len(text_b)
        if max(len_a, len_b) > 0 and min(len_a, len_b) / max(len_a, len_b) < 0.2:
            return 0.2 * (min(len_a, len_b) / max(len_a, len_b))

        matcher = difflib.SequenceMatcher(None, text_a, text_b, autojunk=False)
        return round(matcher.ratio(), 4)

    @classmethod
    def extract_volatile_tokens_count(cls, body: str) -> dict[str, int]:
        """Audit the count of volatile tokens found in response text."""
        return {
            "timestamps": len(RE_TIMESTAMP_ISO.findall(body)) + len(RE_TIMESTAMP_RFC.findall(body)),
            "uuids": len(RE_UUID.findall(body)),
            "object_ids": len(RE_MONGO_OBJECTID.findall(body)),
            "epochs": len(RE_UNIX_EPOCH.findall(body)),
            "csrf_tokens": len(RE_CSRF_FIELD.findall(body)) + len(RE_JSON_CSRF.findall(body)),
        }
