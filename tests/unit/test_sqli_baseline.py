"""Unit tests for baseline response characterization (Phase 4)."""

from unittest.mock import MagicMock

from dbshield.models.http import CaseInsensitiveDict, HTTPResponse
from dbshield.sqli.baseline import BaselineCharacterizer


def _make_mock_response(
    status_code: int = 200, body: str = "Clean page", elapsed: float = 0.05
) -> HTTPResponse:
    return HTTPResponse(
        url="http://test.local/items?id=1",
        status_code=status_code,
        headers=CaseInsensitiveDict({"content-type": "text/html"}),
        body=body,
        content_bytes=body.encode("utf-8"),
        elapsed_seconds=elapsed,
    )


def test_stable_baseline_characterization() -> None:
    mock_client = MagicMock()
    mock_client.request.return_value = _make_mock_response(200, "Clean page item catalog")

    characterizer = BaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, resp = characterizer.characterize("http://test.local/items?id=1")

    assert profile.status_code == 200
    assert profile.is_stable is True
    assert profile.instability_reason is None
    assert profile.sample_count == 2
    assert profile.body_hash is not None
    assert mock_client.request.call_count == 2


def test_baseline_status_variation_marked_unstable() -> None:
    mock_client = MagicMock()
    # Sample 1 returns 200, Sample 2 returns 503
    mock_client.request.side_effect = [
        _make_mock_response(200, "Clean page"),
        _make_mock_response(503, "Service Unavailable"),
    ]

    characterizer = BaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, _ = characterizer.characterize("http://test.local/items?id=1")

    assert profile.is_stable is False
    assert "Status code varied between baseline samples" in str(profile.instability_reason)


def test_baseline_excessive_body_fluctuation_marked_unstable() -> None:
    mock_client = MagicMock()
    # Sample 1 and 2 return 200 but completely different bodies
    mock_client.request.side_effect = [
        _make_mock_response(200, "User catalog with 50 products rendered successfully"),
        _make_mock_response(200, "Fatal application error occurred: system maintenance"),
    ]

    characterizer = BaselineCharacterizer(http_client=mock_client, stability_samples=2)
    profile, _ = characterizer.characterize("http://test.local/items?id=1")

    assert profile.is_stable is False
    assert "response bodies fluctuated excessively" in str(profile.instability_reason)


def test_baseline_server_error_probe_marked_unstable() -> None:
    mock_client = MagicMock()
    mock_client.request.return_value = _make_mock_response(500, "Internal Server Error")

    characterizer = BaselineCharacterizer(http_client=mock_client, stability_samples=1)
    profile, _ = characterizer.characterize("http://test.local/items?id=1")

    assert profile.is_stable is False
    assert "returned server error HTTP 500" in str(profile.instability_reason)


def test_captured_response_fixture_baseline() -> None:
    captured = _make_mock_response(200, "Offline fixture content")
    profile, resp = BaselineCharacterizer.from_captured_response(captured)

    assert profile.status_code == 200
    assert profile.is_stable is True
    assert resp.body == "Offline fixture content"
