"""Unit tests for NoSQL response normalization and volatile token masking."""

from dbshield.nosqli.normalization import NoSQLResponseNormalizer


def test_normalization_strips_mongo_objectids() -> None:
    """Verify MongoDB 24-hex-character ObjectIds are masked."""
    body_with_explicit_id = '{"_id": ObjectId("507f1f77bcf86cd799439011"), "name": "Alice"}'
    normalized_explicit = NoSQLResponseNormalizer.normalize(body_with_explicit_id)
    assert "[DYNAMIC_OBJECTID]" in normalized_explicit
    assert "507f1f77bcf86cd799439011" not in normalized_explicit

    raw_24hex = '{"id": "507f191e810c19729de860ea", "status": "ok"}'
    normalized_raw = NoSQLResponseNormalizer.normalize(raw_24hex)
    assert "[DYNAMIC_OBJECTID]" in normalized_raw
    assert "507f191e810c19729de860ea" not in normalized_raw


def test_normalization_strips_timestamps_and_uuids() -> None:
    """Verify ISO/RFC timestamps and UUIDs are properly masked."""
    body = (
        '{"event_id": "c9a646d3-9c61-4cd9-bc15-0d24490f2095", '
        '"created_at": "2026-10-22T14:30:00Z", '
        '"timestamp": 1729605000}'
    )
    norm = NoSQLResponseNormalizer.normalize(body)
    assert "[DYNAMIC_UUID]" in norm
    assert "[DYNAMIC_TIMESTAMP]" in norm
    assert "[DYNAMIC_EPOCH]" in norm
    assert "c9a646d3" not in norm


def test_normalization_strips_csrf_tokens() -> None:
    """Verify CSRF tokens in HTML and JSON are masked."""
    html = '<input type="hidden" name="csrf_token" value="abc123secretnonce456"/>'
    norm_html = NoSQLResponseNormalizer.normalize(html)
    assert "[DYNAMIC_CSRF_TOKEN]" in norm_html
    assert "abc123secretnonce456" not in norm_html

    json_text = '{"status": "ok", "csrf_token": "secret_csrf_value_xyz"}'
    norm_json = NoSQLResponseNormalizer.normalize(json_text)
    assert "[DYNAMIC_TOKEN]" in norm_json
    assert "secret_csrf_value_xyz" not in norm_json


def test_compute_similarity_metrics() -> None:
    """Verify similarity computation between identical, similar, and divergent responses."""
    text_a = '{"status": "success", "count": 10, "data": []}'
    text_b = '{"status": "success", "count": 10, "data": []}'
    text_c = '{"status": "error", "message": "Not Found"}'

    assert NoSQLResponseNormalizer.compute_similarity(text_a, text_b) == 1.0
    assert NoSQLResponseNormalizer.compute_similarity(text_a, "") == 0.0
    sim_ac = NoSQLResponseNormalizer.compute_similarity(text_a, text_c)
    assert 0.0 <= sim_ac < 0.60


def test_extract_volatile_tokens_count() -> None:
    """Verify volatile tokens audit count."""
    text = (
        "UUID: 12345678-1234-1234-1234-123456789abc "
        'ObjectId("507f1f77bcf86cd799439011") '
        "Time: 2026-10-22T10:00:00Z"
    )
    counts = NoSQLResponseNormalizer.extract_volatile_tokens_count(text)
    assert counts["uuids"] == 1
    assert counts["object_ids"] >= 1
    assert counts["timestamps"] == 1
