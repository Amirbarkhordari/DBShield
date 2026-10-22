"""NoSQL database error signature catalog and pattern matching.

Maintains curated, high-precision regular expression signatures for recognizable
NoSQL document databases (MongoDB, CouchDB, Mongoose, PyMongo). Strictly differentiates
NoSQL-specific syntax or operator errors from generic HTTP 500 or application server failure pages.
"""

import re
from dataclasses import dataclass
from typing import ClassVar

from dbshield.logging_config import SensitiveDataFilter
from dbshield.nosqli.models import NoSQLProviderFamily


@dataclass(frozen=True)
class NoSQLErrorSignature:
    """Definition of an individual NoSQL database error pattern."""

    rule_id: str
    family: NoSQLProviderFamily
    pattern: re.Pattern[str]
    description: str


# Generic server errors that must NEVER be treated as database-specific NoSQL error signatures
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


class NoSQLSignatureCatalog:
    """Catalog of verified NoSQL database error signatures."""

    SIGNATURES: ClassVar[list[NoSQLErrorSignature]] = [
        # MongoDB: Operator rejection & BadValue
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_UNKNOWN_OPERATOR",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:unknown operator:\s+\$|unknown top level operator:\s+\$|BadValue:\s+unknown operator)",
                re.IGNORECASE,
            ),
            description="MongoDB unknown query or aggregation operator rejection.",
        ),
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_CANONICALIZE",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"Can't canonicalize query:\s+BadValue",
                re.IGNORECASE,
            ),
            description="MongoDB query canonicalization failure notice.",
        ),
        # MongoDB: JavaScript / $where clause syntax error
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_JS_SYNTAX",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:unterminated string literal|SyntaxError:\s+Unexpected token|ReferenceError:\s+.*?is not defined|JavaScript execution failed:)",
                re.IGNORECASE,
            ),
            description="MongoDB JavaScript $where or mapReduce clause evaluation failure.",
        ),
        # MongoDB: PyMongo & Driver exceptions
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_DRIVER_OPERATION",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:pymongo\.errors\.OperationFailure|MongoError:\s+error processing query|MongoServerError:\s+error processing query)",
                re.IGNORECASE,
            ),
            description="PyMongo or MongoDB native driver query operation failure.",
        ),
        # MongoDB: BSON Serialization / Document syntax error
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_BSON_EXCEPTION",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:BSONException|BSONObj size:\s+\d+\s+is invalid|Invalid BSON document|bson\.errors\.InvalidBSON)",
                re.IGNORECASE,
            ),
            description="MongoDB BSON serialization or malformed document exception.",
        ),
        # Mongoose ORM / CastError
        NoSQLErrorSignature(
            rule_id="ERR_MONGOOSE_CAST",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:Cast to ObjectId failed for value|ValidationError:\s+.*?Cast to|MongooseError:\s+Cast to)",
                re.IGNORECASE,
            ),
            description="Mongoose schema CastError or invalid ObjectId parameter type exception.",
        ),
        # MongoDB: Regular expression evaluation error
        NoSQLErrorSignature(
            rule_id="ERR_MONGO_REGEX_SYNTAX",
            family=NoSQLProviderFamily.MONGODB,
            pattern=re.compile(
                r"(?:regular expression is invalid|bad regex|regex compilation failed|Regular expression error:)",
                re.IGNORECASE,
            ),
            description="MongoDB regular expression compilation or syntax error.",
        ),
        # CouchDB: View compilation & selector errors
        NoSQLErrorSignature(
            rule_id="ERR_COUCHDB_COMPILATION",
            family=NoSQLProviderFamily.COUCHDB,
            pattern=re.compile(
                r"(?:\"error\":\s*\"compilation_error\"|\"reason\":\s*\"Expression does not eval to a function\")",
                re.IGNORECASE,
            ),
            description="CouchDB JavaScript view compilation failure notice.",
        ),
        NoSQLErrorSignature(
            rule_id="ERR_COUCHDB_SELECTOR_PARSE",
            family=NoSQLProviderFamily.COUCHDB,
            pattern=re.compile(
                r"(?:\"error\":\s*\"query_parse_error\"|\"error\":\s*\"bad_request\",\s*\"reason\":\s*\"Selector error|\"error\":\s*\"invalid_selector\")",
                re.IGNORECASE,
            ),
            description="CouchDB Mango query selector syntax or parse error.",
        ),
        # Generic NoSQL Document Store
        NoSQLErrorSignature(
            rule_id="ERR_GENERIC_NOSQL_QUERY",
            family=NoSQLProviderFamily.GENERIC_NOSQL,
            pattern=re.compile(
                r"(?:NoSQLQueryException|DocumentClientException|Invalid NoSQL query expression)",
                re.IGNORECASE,
            ),
            description="Generic NoSQL document database query processing exception.",
        ),
    ]

    @classmethod
    def get_all_signatures(cls) -> list[NoSQLErrorSignature]:
        """Return all registered NoSQL error signatures."""
        return list(cls.SIGNATURES)

    @classmethod
    def match_signatures(cls, text: str) -> list[tuple[NoSQLErrorSignature, str]]:
        """Match text against NoSQL signatures and extract safe snippets.

        Deduplicates overlapping signature matches on the same underlying error text,
        preferring the longer and more specific match, while preserving genuinely
        distinct error occurrences.

        Returns:
            List of (NoSQLErrorSignature, snippet) tuples.
        """
        if not text:
            return []

        raw_matches: list[tuple[int, int, NoSQLErrorSignature, str]] = []

        for sig in cls.SIGNATURES:
            match = sig.pattern.search(text)
            if match:
                start_pos = max(0, match.start() - 40)
                end_pos = min(len(text), match.end() + 80)
                raw_snippet = text[start_pos:end_pos].strip().replace("\n", " ")
                safe_snippet = SensitiveDataFilter.redact(raw_snippet)
                raw_matches.append((match.start(), match.end(), sig, safe_snippet))

        if not raw_matches:
            return []

        # Sort matches by match length descending so longer/more specific signatures take precedence
        raw_matches.sort(key=lambda m: -(m[1] - m[0]))

        accepted: list[tuple[int, int, NoSQLErrorSignature, str]] = []
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
        """Check if response text only matches generic server errors without NoSQL signatures."""
        has_generic = any(gen.search(text) for gen in GENERIC_HTTP_ERRORS)
        has_nosql_sig = any(sig.pattern.search(text) for sig in cls.SIGNATURES)
        return has_generic and not has_nosql_sig
