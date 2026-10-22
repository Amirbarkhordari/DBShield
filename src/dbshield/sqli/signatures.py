"""Database error signature catalog and pattern matching.

Maintains curated, high-precision regular expression signatures for recognizable
database management systems. Strictly differentiates database-specific syntax errors
from generic HTTP 500 or application server failure pages.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from dbshield.logging_config import SensitiveDataFilter
from dbshield.sqli.models import DatabaseFamily


@dataclass(frozen=True)
class DBErrorSignature:
    """Definition of an individual database error pattern."""

    rule_id: str
    family: DatabaseFamily
    pattern: re.Pattern[str]
    description: str


# Generic server errors that must NEVER be treated as database-specific error signatures
GENERIC_HTTP_ERRORS: list[re.Pattern[str]] = [
    re.compile(r"\b500\s+Internal\s+Server\s+Error\b", re.IGNORECASE),
    re.compile(r"\bInternal\s+Server\s+Error\b", re.IGNORECASE),
    re.compile(r"\b400\s+Bad\s+Request\b", re.IGNORECASE),
    re.compile(r"\bBad\s+Request\b", re.IGNORECASE),
    re.compile(r"\b502\s+Bad\s+Gateway\b", re.IGNORECASE),
    re.compile(r"\b503\s+Service\s+Unavailable\b", re.IGNORECASE),
    re.compile(r"\b504\s+Gateway\s+Timeout\b", re.IGNORECASE),
    re.compile(r"\bAn\s+unexpected\s+error\s+occurred\b", re.IGNORECASE),
    re.compile(r"\bServer\s+Error\b", re.IGNORECASE),
]


class SignatureCatalog:
    """Catalog of verified database error signatures."""

    SIGNATURES: ClassVar[list[DBErrorSignature]] = [
        # MySQL & MariaDB
        DBErrorSignature(
            rule_id="ERR_MYSQL_SYNTAX",
            family=DatabaseFamily.MYSQL,
            pattern=re.compile(
                r"You have an error in your SQL syntax; check the manual that corresponds to your (?:MySQL|MariaDB)",
                re.IGNORECASE,
            ),
            description="MySQL / MariaDB standard SQL syntax error notification.",
        ),
        DBErrorSignature(
            rule_id="ERR_MYSQL_MANUAL",
            family=DatabaseFamily.MYSQL,
            pattern=re.compile(
                r"check the manual that corresponds to your (?:MySQL|MariaDB) server version",
                re.IGNORECASE,
            ),
            description="MySQL / MariaDB syntax manual version reference.",
        ),
        DBErrorSignature(
            rule_id="ERR_MYSQL_EXCEPTION",
            family=DatabaseFamily.MYSQL,
            pattern=re.compile(
                r"(?:MySqlException|com\.mysql\.jdbc\.exceptions|org\.mariadb\.jdbc)",
                re.IGNORECASE,
            ),
            description="MySQL / MariaDB connector exception trace.",
        ),
        DBErrorSignature(
            rule_id="ERR_MYSQL_RESULT",
            family=DatabaseFamily.MYSQL,
            pattern=re.compile(r"valid MySQL result", re.IGNORECASE),
            description="PHP MySQL driver result failure message.",
        ),
        # PostgreSQL
        DBErrorSignature(
            rule_id="ERR_PG_SYNTAX",
            family=DatabaseFamily.POSTGRESQL,
            pattern=re.compile(r"ERROR:\s+syntax error at or near\s+", re.IGNORECASE),
            description="PostgreSQL syntax error message.",
        ),
        DBErrorSignature(
            rule_id="ERR_PG_QUERY_FAILED",
            family=DatabaseFamily.POSTGRESQL,
            pattern=re.compile(
                r"(?:PostgreSQL query failed:|pg_query\(\):\s+Query failed:|pg_exec\(\):\s+Query failed:)",
                re.IGNORECASE,
            ),
            description="PostgreSQL driver query execution failure.",
        ),
        DBErrorSignature(
            rule_id="ERR_PG_JDBC_EXCEPTION",
            family=DatabaseFamily.POSTGRESQL,
            pattern=re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
            description="PostgreSQL JDBC driver exception.",
        ),
        # SQLite
        DBErrorSignature(
            rule_id="ERR_SQLITE_SYNTAX",
            family=DatabaseFamily.SQLITE,
            pattern=re.compile(
                r"(?:OperationalError:\s+near\s+[\"'].*?[\"']:\s+syntax error|sqlite3\.OperationalError:\s+near)",
                re.IGNORECASE,
            ),
            description="SQLite operational syntax error message.",
        ),
        DBErrorSignature(
            rule_id="ERR_SQLITE_EXCEPTION",
            family=DatabaseFamily.SQLITE,
            pattern=re.compile(
                r"(?:SQLite3::SQLException|SQLITE_ERROR|unrecognized token:\s+[\"'])",
                re.IGNORECASE,
            ),
            description="SQLite generic driver error or unrecognized token exception.",
        ),
        # Microsoft SQL Server
        DBErrorSignature(
            rule_id="ERR_MSSQL_UNCLOSED_QUOTE",
            family=DatabaseFamily.MSSQL,
            pattern=re.compile(
                r"Unclosed quotation mark after the character string",
                re.IGNORECASE,
            ),
            description="Microsoft SQL Server unclosed quotation mark syntax error.",
        ),
        DBErrorSignature(
            rule_id="ERR_MSSQL_DRIVER",
            family=DatabaseFamily.MSSQL,
            pattern=re.compile(
                r"(?:Driver.*?SQL[-_ ]*Server|OLE DB.*?SQL Server|Microsoft OLE DB Provider for SQL Server|\[SQL Server\])",
                re.IGNORECASE,
            ),
            description="Microsoft SQL Server OLE DB / ODBC driver error message.",
        ),
        DBErrorSignature(
            rule_id="ERR_MSSQL_JDBC",
            family=DatabaseFamily.MSSQL,
            pattern=re.compile(
                r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
                re.IGNORECASE,
            ),
            description="Microsoft SQL Server JDBC exception.",
        ),
        # Oracle
        DBErrorSignature(
            rule_id="ERR_ORACLE_ORA",
            family=DatabaseFamily.ORACLE,
            pattern=re.compile(r"\b(?:ORA|PLS)-\d{5}:", re.IGNORECASE),
            description="Oracle database error code (ORA-XXXXX or PLS-XXXXX).",
        ),
        DBErrorSignature(
            rule_id="ERR_ORACLE_JDBC",
            family=DatabaseFamily.ORACLE,
            pattern=re.compile(
                r"(?:oracle\.jdbc\.driver\.OracleDriver|Oracle error:)",
                re.IGNORECASE,
            ),
            description="Oracle JDBC driver failure notice.",
        ),
        # Generic SQL
        DBErrorSignature(
            rule_id="ERR_GENERIC_SQL_STATE",
            family=DatabaseFamily.GENERIC_SQL,
            pattern=re.compile(r"\bSQLSTATE\[\d+\]", re.IGNORECASE),
            description="Standard ANSI SQLSTATE error code representation.",
        ),
        DBErrorSignature(
            rule_id="ERR_GENERIC_SQL_SYNTAX",
            family=DatabaseFamily.GENERIC_SQL,
            pattern=re.compile(
                r"(?:Syntax error in SQL statement|Dynamic SQL Error|System\.Data\.SqlClient\.SqlException)",
                re.IGNORECASE,
            ),
            description="Generic database management SQL syntax error statement.",
        ),
    ]

    @classmethod
    def match_signatures(cls, text: str) -> list[tuple[DBErrorSignature, str]]:
        """Match text against database signatures and extract safe snippets.

        Deduplicates overlapping signature matches on the same underlying error text,
        preferring the longer and more specific match, while preserving genuinely
        distinct error occurrences.

        Returns:
            List of (DBErrorSignature, snippet) tuples.
        """
        if not text:
            return []

        raw_matches: list[tuple[int, int, DBErrorSignature, str]] = []

        for sig in cls.SIGNATURES:
            match = sig.pattern.search(text)
            if match:
                start_pos = max(0, match.start() - 40)
                end_pos = min(len(text), match.end() + 80)
                raw_snippet = text[start_pos:end_pos].strip().replace("\n", " ")
                # Redact any sensitive credentials or tokens in snippet
                safe_snippet = SensitiveDataFilter.redact(raw_snippet)
                raw_matches.append((match.start(), match.end(), sig, safe_snippet))

        if not raw_matches:
            return []

        # Sort matches by match length descending so longer/more specific signatures take precedence
        raw_matches.sort(key=lambda m: -(m[1] - m[0]))

        accepted: list[tuple[int, int, DBErrorSignature, str]] = []
        for start, end, sig, snippet in raw_matches:
            # Check if this match's span overlaps with an already-accepted longer match
            if any(max(start, a_start) < min(end, a_end) for a_start, a_end, _, _ in accepted):
                continue
            accepted.append((start, end, sig, snippet))

        # Re-sort accepted matches by text occurrence order (start position)
        accepted.sort(key=lambda m: m[0])
        return [(sig, snippet) for _, _, sig, snippet in accepted]

    @classmethod
    def is_generic_server_error(cls, text: str) -> bool:
        """Check if response text only matches generic server errors without DB signatures."""
        has_generic = any(gen.search(text) for gen in GENERIC_HTTP_ERRORS)
        has_db_sig = any(sig.pattern.search(text) for sig in cls.SIGNATURES)
        return has_generic and not has_db_sig
