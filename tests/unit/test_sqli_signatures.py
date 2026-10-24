"""Unit tests for database error signature catalog and pattern matching (Phase 4)."""

from dbshield.sqli.models import DatabaseFamily
from dbshield.sqli.signatures import SignatureCatalog


def test_signature_catalog_non_empty() -> None:
    assert len(SignatureCatalog.SIGNATURES) >= 10


def test_mysql_syntax_error_matching() -> None:
    text = (
        "Server response: You have an error in your SQL syntax; check the manual that corresponds "
        "to your MySQL server version for the right syntax to use near ''' at line 1"
    )
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == DatabaseFamily.MYSQL
    assert "error in your SQL syntax" in snippet


def test_mariadb_syntax_error_matching() -> None:
    text = (
        "Error: You have an error in your SQL syntax; check the manual that corresponds "
        "to your MariaDB server version"
    )
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, _ = matches[0]
    assert sig.family == DatabaseFamily.MYSQL


def test_postgresql_syntax_error_matching() -> None:
    text = 'Query failed: ERROR: syntax error at or near "\'" at character 42'
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == DatabaseFamily.POSTGRESQL
    assert "syntax error at or near" in snippet


def test_sqlite_syntax_error_matching() -> None:
    text = 'Traceback: sqlite3.OperationalError: near "\'": syntax error'
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == DatabaseFamily.SQLITE
    assert "syntax error" in snippet


def test_mssql_unclosed_quote_matching() -> None:
    text = "Microsoft SQL Server: Unclosed quotation mark after the character string 'test'."
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == DatabaseFamily.MSSQL
    assert "Unclosed quotation mark" in snippet


def test_oracle_ora_code_matching() -> None:
    text = "Database fault: ORA-00933: SQL command not properly ended"
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.family == DatabaseFamily.ORACLE
    assert "ORA-00933:" in snippet


def test_generic_server_errors_rejected() -> None:
    # Generic server error pages must NOT match database signatures
    generic_500 = "<html><body><h1>500 Internal Server Error</h1><p>An unexpected error occurred.</p></body></html>"
    matches = SignatureCatalog.match_signatures(generic_500)
    assert len(matches) == 0
    assert SignatureCatalog.is_generic_server_error(generic_500) is True


def test_generic_400_bad_request_rejected() -> None:
    generic_400 = "HTTP 400 Bad Request: Malformed parameter"
    assert SignatureCatalog.is_generic_server_error(generic_400) is True
    assert len(SignatureCatalog.match_signatures(generic_400)) == 0


def test_snippet_redacts_credentials() -> None:
    text = (
        "Internal DB notice: You have an error in your SQL syntax; check the manual that "
        "corresponds to your MySQL server version near Bearer ghp_999999999999999999999999999999999999"
    )
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    _, snippet = matches[0]
    assert "ghp_" not in snippet
    assert "[REDACTED" in snippet


def test_mysql_syntax_error_no_duplicate_matches() -> None:
    # Overlapping ERR_MYSQL_SYNTAX and ERR_MYSQL_MANUAL must NOT yield duplicate records
    text = (
        "Server response: You have an error in your SQL syntax; check the manual that corresponds "
        "to your MySQL server version for the right syntax to use near ''' at line 1"
    )
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) == 1
    sig, snippet = matches[0]
    assert sig.rule_id == "ERR_MYSQL_SYNTAX"
    assert sig.family == DatabaseFamily.MYSQL


def test_distinct_signatures_remain_detectable() -> None:
    # Multiple distinct non-overlapping database errors in the same response must all be detected
    text = (
        "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server\n"
        "Stack trace:\n"
        "com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException: Unknown column 'id' in 'where clause'"
    )
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) == 2
    rule_ids = {sig.rule_id for sig, _ in matches}
    assert rule_ids == {"ERR_MYSQL_SYNTAX", "ERR_MYSQL_EXCEPTION"}


def test_truncated_mysql_manual_signature_fallback() -> None:
    # If the syntax prefix is omitted/truncated, ERR_MYSQL_MANUAL is still matched
    text = "Database alert: check the manual that corresponds to your MySQL server version for syntax rules"
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) == 1
    assert matches[0][0].rule_id == "ERR_MYSQL_MANUAL"


def test_postgresql_unterminated_quote_matching() -> None:
    # Regression test for Phase 9: PostgreSQL unterminated quoted string syntax error
    text = "Database query failed: ERROR: unterminated quoted string at or near ''' at character 18"
    matches = SignatureCatalog.match_signatures(text)
    assert len(matches) >= 1
    sig, snippet = matches[0]
    assert sig.rule_id == "ERR_PG_SYNTAX"
    assert sig.family == DatabaseFamily.POSTGRESQL
    assert "unterminated quoted string at or near" in snippet
