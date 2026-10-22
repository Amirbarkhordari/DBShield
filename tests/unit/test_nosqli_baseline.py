"""Unit tests for NoSQL baseline response characterizer."""

from unittest.mock import MagicMock

from dbshield.models.http import HTTPResponse
from dbshield.nosqli.baseline import NoSQLBaselineCharacterizer


def test_stable_baseline_characterization() -> None:
    """Verify stable baseline across multiple probes."""
    mock_client = MagicMock()
    mock_client.request.side_effect = [
        HTTPResponse(
            url="http://example.com/api", status_code=200, body='{"status": "ok", "items": []}'
        ),
        HTTPResponse(
            url="http://example.com/api", status_code=200, body='{"status": "ok", "items": []}'
        ),
    ]

    characterizer = NoSQLBaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, resp = characterizer.characterize(endpoint="http://example.com/api")

    assert profile.is_stable is True
    assert profile.sample_count == 2
    assert profile.status_code == 200
    assert profile.instability_reason is None


def test_baseline_status_variation_marked_unstable() -> None:
    """Verify baseline is marked unstable when probe status codes differ."""
    mock_client = MagicMock()
    mock_client.request.side_effect = [
        HTTPResponse(url="http://example.com/api", status_code=200, body="ok"),
        HTTPResponse(url="http://example.com/api", status_code=500, body="error"),
    ]

    characterizer = NoSQLBaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, _ = characterizer.characterize(endpoint="http://example.com/api")

    assert profile.is_stable is False
    assert "Status code varied" in (profile.instability_reason or "")


def test_baseline_excessive_body_fluctuation_marked_unstable() -> None:
    """Verify baseline is marked unstable when body similarity is below 0.80."""
    mock_client = MagicMock()
    mock_client.request.side_effect = [
        HTTPResponse(url="http://example.com/api", status_code=200, body="A" * 100),
        HTTPResponse(url="http://example.com/api", status_code=200, body="Z" * 100),
    ]

    characterizer = NoSQLBaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, _ = characterizer.characterize(endpoint="http://example.com/api")

    assert profile.is_stable is False
    assert "fluctuated" in (profile.instability_reason or "")


def test_baseline_server_error_probe_marked_unstable() -> None:
    """Verify baseline returning 500 on initial probe is marked unstable."""
    mock_client = MagicMock()
    mock_client.request.return_value = HTTPResponse(
        url="http://example.com/api", status_code=500, body="Server error"
    )

    characterizer = NoSQLBaselineCharacterizer(http_client=mock_client, stability_samples=1)
    profile, _ = characterizer.characterize(endpoint="http://example.com/api")

    assert profile.is_stable is False
    assert "server error" in (profile.instability_reason or "")


def test_captured_response_fixture_baseline() -> None:
    """Verify baseline generation from captured offline response fixture."""
    captured = HTTPResponse(
        url="http://example.com/api",
        status_code=200,
        body='{"data": [1, 2, 3]}',
        elapsed_seconds=0.035,
    )
    profile, resp = NoSQLBaselineCharacterizer.from_captured_response(captured)

    assert profile.is_stable is True
    assert profile.status_code == 200
    assert profile.sample_count == 1
    assert resp == captured
