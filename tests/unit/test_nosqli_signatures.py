"""Unit tests for NoSQL signature catalog, matching, deduplication, and generic error rejection."""

from dbshield.nosqli.models import NoSQLProviderFamily
from dbshield.nosqli.signatures import NoSQLSignatureCatalog


def test_signature_catalog_non_empty() -> None:
    """Verify catalog has loaded signatures for supported providers."""
    signatures = NoSQLSignatureCatalog.get_all_signatures()
    assert len(signatures) >= 8

    families = {s.family for s in signatures}
    assert NoSQLProviderFamily.MONGODB in families
    assert NoSQLProviderFamily.COUCHDB in families
    assert NoSQLProviderFamily.GENERIC_NOSQL in families


def test_mongodb_operator_error_matching() -> None:
    """Verify MongoDB unknown operator error is identified."""
    sample = "MongoError: unknown operator: $invalid_op at src/mongo/db/query.cpp"
    matches = NoSQLSignatureCatalog.match_signatures(sample)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == NoSQLProviderFamily.MONGODB
    assert "unknown operator" in snippet


def test_mongodb_where_syntax_error_matching() -> None:
    """Verify MongoDB $where Javascript syntax error is matched."""
    sample = "Error: $where compile error: SyntaxError: Unexpected token ("
    matches = NoSQLSignatureCatalog.match_signatures(sample)
    assert len(matches) >= 1
    assert any(sig.rule_id == "ERR_MONGO_JS_SYNTAX" for sig, _ in matches)


def test_couchdb_error_matching() -> None:
    """Verify CouchDB view compilation and selector error matching."""
    sample = '{"error":"compilation_error","reason":"Expression does not eval to a function"}'
    matches = NoSQLSignatureCatalog.match_signatures(sample)
    assert len(matches) >= 1
    assert matches[0][0].family == NoSQLProviderFamily.COUCHDB


def test_generic_server_errors_rejected() -> None:
    """Verify generic HTTP 500/400 errors without NoSQL signatures are flagged as generic."""
    generic_500 = "<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p></body></html>"
    assert NoSQLSignatureCatalog.is_generic_server_error(generic_500) is True

    generic_400 = '{"error": "Bad Request", "message": "Missing required field"}'
    assert NoSQLSignatureCatalog.is_generic_server_error(generic_400) is True

    # But a response with MongoDB error is NOT flagged as generic server error
    mongo_error = "MongoServerError: unknown operator: $ne at query engine"
    assert NoSQLSignatureCatalog.is_generic_server_error(mongo_error) is False


def test_snippet_redaction() -> None:
    """Verify sensitive tokens in matched error snippets are redacted."""
    sample = (
        "MongoServerError: unknown operator: $invalid_op with auth "
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMCda8Yhe3iZaWbvV5XKSTbuAn0M"
    )
    matches = NoSQLSignatureCatalog.match_signatures(sample)
    assert len(matches) >= 1
    _, snippet = matches[0]
    assert "eyJ" not in snippet
    assert "[REDACTED" in snippet
