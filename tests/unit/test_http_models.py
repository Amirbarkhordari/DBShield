"""Unit tests for HTTP data models and response abstraction."""

import json

import pytest

from dbshield.models.http import (
    CaseInsensitiveDict,
    HTTPMethod,
    HTTPRequest,
    HTTPResponse,
)


def test_http_method_enum() -> None:
    """Verify supported HTTP methods."""
    assert HTTPMethod.GET == "GET"
    assert HTTPMethod.POST == "POST"
    assert HTTPMethod.PUT == "PUT"
    assert HTTPMethod.PATCH == "PATCH"
    assert HTTPMethod.DELETE == "DELETE"
    assert HTTPMethod.HEAD == "HEAD"
    assert HTTPMethod.OPTIONS == "OPTIONS"


def test_http_request_defaults_and_validation() -> None:
    """Verify HTTPRequest default attributes and boundary constraints."""
    req = HTTPRequest(url="https://example.com/test")
    assert req.url == "https://example.com/test"
    assert req.method == HTTPMethod.GET
    assert req.timeout == 10.0
    assert req.follow_redirects is True
    assert req.max_redirects == 5
    assert req.verify_ssl is True

    # Negative timeout rejection
    with pytest.raises(ValueError):
        HTTPRequest(url="https://example.com", timeout=-1.0)

    # Excessive redirect limit rejection
    with pytest.raises(ValueError):
        HTTPRequest(url="https://example.com", max_redirects=100)


def test_case_insensitive_dict() -> None:
    """Verify CaseInsensitiveDict allows case-insensitive key lookups and preservation."""
    cid = CaseInsensitiveDict({"Content-Type": "application/json", "X-Custom-ID": "42"})
    assert cid["content-type"] == "application/json"
    assert cid["Content-Type"] == "application/json"
    assert cid.get("CONTENT-TYPE") == "application/json"
    assert "x-custom-id" in cid
    assert "X-CUSTOM-ID" in cid

    cid["Authorization"] = "Bearer token"
    assert cid.get("authorization") == "Bearer token"
    assert "authorization" in cid


def test_http_response_properties_and_duck_typing() -> None:
    """Verify HTTPResponse status classifications and httpx-compatible properties."""
    resp = HTTPResponse(
        url="https://example.com/api/data",
        status_code=200,
        headers={"Content-Type": "application/json", "Server": "test"},
        body='{"status": "ok", "items": [1, 2, 3]}',
        content_bytes=b'{"status": "ok", "items": [1, 2, 3]}',
        content_type="application/json",
        content_length=35,
        elapsed_seconds=0.123,
        request_method="GET",
    )

    assert resp.is_success is True
    assert resp.is_redirect is False
    assert resp.is_client_error is False
    assert resp.is_server_error is False

    # Duck-typing matching httpx.Response
    assert resp.text == '{"status": "ok", "items": [1, 2, 3]}'
    assert resp.content == b'{"status": "ok", "items": [1, 2, 3]}'
    parsed = resp.json()
    assert parsed["status"] == "ok"
    assert parsed["items"] == [1, 2, 3]

    # Case-insensitive headers lookup
    assert resp.headers.get("content-type") == "application/json"
    assert resp.get_header("Content-Type") == "application/json"


def test_http_response_status_classification() -> None:
    """Verify HTTP response status code classification ranges."""
    r_redirect = HTTPResponse(url="https://example.com", status_code=302)
    assert r_redirect.is_redirect is True
    assert r_redirect.is_success is False

    r_client_err = HTTPResponse(url="https://example.com", status_code=404)
    assert r_client_err.is_client_error is True

    r_server_err = HTTPResponse(url="https://example.com", status_code=500)
    assert r_server_err.is_server_error is True


def test_http_response_json_failure() -> None:
    """Verify json() raises ValueError on empty or invalid JSON body."""
    r_empty = HTTPResponse(url="https://example.com", status_code=200, body="")
    with pytest.raises(ValueError, match="Response body is empty"):
        r_empty.json()

    r_invalid = HTTPResponse(url="https://example.com", status_code=200, body="not-json")
    with pytest.raises(json.JSONDecodeError):
        r_invalid.json()


def test_http_response_to_safe_dict_snippet_truncation() -> None:
    """Verify to_safe_dict bounds body preview snippet."""
    long_body = "A" * 1000
    resp = HTTPResponse(
        url="https://example.com",
        status_code=200,
        body=long_body,
        content_bytes=long_body.encode(),
    )
    safe_dict = resp.to_safe_dict()
    assert len(safe_dict["body_snippet"]) == 500
    assert safe_dict["url"] == "https://example.com"
