"""Unit tests for response normalization and dynamic content masking (Phase 4)."""

from dbshield.sqli.normalization import ResponseNormalizer


def test_normalization_strips_iso_timestamp() -> None:
    body = '{"data": "items", "created_at": "2026-10-22T14:15:30.123456Z"}'
    normalized = ResponseNormalizer.normalize(body)
    assert "2026-10-22T14:15:30.123456Z" not in normalized
    assert "[DYNAMIC_TIMESTAMP]" in normalized


def test_normalization_strips_rfc_timestamp() -> None:
    body = "Page generated at Mon, 22 Oct 2026 14:15:30 GMT for user."
    normalized = ResponseNormalizer.normalize(body)
    assert "Mon, 22 Oct 2026 14:15:30" not in normalized
    assert "[DYNAMIC_TIMESTAMP]" in normalized


def test_normalization_strips_uuid() -> None:
    body = '{"user_uuid": "c9a646d3-9c61-4cc9-bcaf-6e59fa4f5f5e", "status": "ok"}'
    normalized = ResponseNormalizer.normalize(body)
    assert "c9a646d3-9c61-4cc9-bcaf-6e59fa4f5f5e" not in normalized
    assert "[DYNAMIC_UUID]" in normalized


def test_normalization_strips_csrf_token() -> None:
    body = '<form><input type="hidden" name="csrf_token" value="d41d8cd98f00b204e9800998ecf8427e"></form>'
    normalized = ResponseNormalizer.normalize(body)
    assert "d41d8cd98f00b204e9800998ecf8427e" not in normalized
    assert "[DYNAMIC_CSRF_TOKEN]" in normalized


def test_normalization_collapses_whitespace() -> None:
    body = "   <div>\n\n\t   <p>Item    1</p>\n   </div>  "
    normalized = ResponseNormalizer.normalize(body)
    assert normalized == "<div> <p>Item 1</p> </div>"


def test_compute_hash_deterministic() -> None:
    text_1 = "User item catalog version 1"
    text_2 = "User item catalog version 1"
    hash_1 = ResponseNormalizer.compute_hash(text_1)
    hash_2 = ResponseNormalizer.compute_hash(text_2)
    assert hash_1 == hash_2
    assert len(hash_1) == 64  # SHA-256


def test_compute_similarity_identical() -> None:
    text = "Product List: 10 items found"
    assert ResponseNormalizer.compute_similarity(text, text) == 1.0


def test_compute_similarity_distinct() -> None:
    text_a = "User profile: Alice, email: alice@example.com, role: member"
    text_b = "Error: Invalid user id or database query failed"
    sim = ResponseNormalizer.compute_similarity(text_a, text_b)
    assert sim < 0.50


def test_extract_volatile_tokens_count() -> None:
    body = (
        '{"id": "c9a646d3-9c61-4cc9-bcaf-6e59fa4f5f5e", '
        '"time": "2026-10-22T14:15:30Z", '
        '"epoch": 1698000000, '
        '"csrf_token": "token123"}'
    )
    counts = ResponseNormalizer.extract_volatile_tokens_count(body)
    assert counts["uuids"] == 1
    assert counts["timestamps"] >= 1
    assert counts["epochs"] >= 1
    assert counts["csrf_tokens"] >= 1
