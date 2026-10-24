"""Standard catalog of deterministic lab validation scenarios for DBShield (Phase 9).

Covers positive, negative, and ambiguous test cases across SQLi, NoSQLi,
execution safety budgets, and verification consistency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dbshield.validation.models import (
    ExpectedClassification,
    ExpectedOutcome,
    LabScenario,
    MockHTTPResponse,
    ScenarioCategory,
)


def load_standard_scenarios() -> list[LabScenario]:
    """Return a curated, deterministic catalog of Phase 9 validation scenarios."""
    scenarios: list[LabScenario] = []

    # =========================================================================
    # 1. SQL Injection Positive Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-MYSQL-ERR",
            name="MySQL Error-Based Injection in Query Parameter",
            description="Target reflects MySQL syntax error when single-quote probe is supplied.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/catalog?item=42",
            parameter_name="item",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/catalog?item=42",
                    status_code=200,
                    body="<html><body><h1>Product 42</h1><p>Clean catalog entry</p></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="http://lab.local/catalog?item=42%27",
                    status_code=500,
                    body=(
                        "<html><body><h1>Database Error</h1>"
                        "<p>You have an error in your SQL syntax; check the manual that corresponds "
                        "to your MySQL server version near ''' at line 1</p></body></html>"
                    ),
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="mysql",
                min_evidence_count=1,
                verification_status="potential_indicator",
            ),
            tags=["sqli", "error", "mysql", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-PGSQL-ERR",
            name="PostgreSQL Error-Based Injection in Form Body",
            description="Target reflects PostgreSQL syntax error on single-quote probe in POST form.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/login",
            http_method="POST",
            parameter_name="user",
            parameter_location="body_urlencoded",
            data="user=admin&role=guest",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/login",
                    status_code=200,
                    body="<html><body><h1>Login Page</h1><p>Please enter credentials</p></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="user=admin%27",
                    status_code=500,
                    body=(
                        "<html><body><h1>Server Error</h1>"
                        "<p>ERROR: unterminated quoted string at or near ''' position 18</p></body></html>"
                    ),
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="postgresql",
                min_evidence_count=1,
            ),
            tags=["sqli", "error", "postgresql", "form", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-SQLITE-ERR",
            name="SQLite Error-Based Injection in JSON Body",
            description="Target reflects SQLite syntax error in JSON field.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/api/search",
            http_method="POST",
            parameter_name="query",
            parameter_location="body_json",
            json_data={"query": "test", "limit": 10},
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/search",
                    status_code=200,
                    body='{"status": "ok", "results": [{"id": 1, "name": "Item 1"}]}',
                ),
                MockHTTPResponse(
                    url_pattern="test'",
                    status_code=500,
                    body='{"error": "sqlite3.OperationalError: unrecognized token: "\'""}',
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="sqlite",
                min_evidence_count=1,
            ),
            tags=["sqli", "error", "sqlite", "json", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-MSSQL-ERR",
            name="MSSQL Error-Based Injection in Query Parameter",
            description="Target reflects Microsoft SQL Server OLE DB / ODBC syntax error.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/view?doc_id=100",
            parameter_name="doc_id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/view?doc_id=100",
                    status_code=200,
                    body="<html><body><h1>Document 100</h1><p>Content</p></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="doc_id=100%27",
                    status_code=500,
                    body=(
                        "<html><body><h2>500 Internal Server Error</h2>"
                        "<p>[Microsoft][ODBC SQL Server Driver][SQL Server]Unclosed quotation mark before the character string '''.</p></body></html>"
                    ),
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="mssql",
                min_evidence_count=1,
            ),
            tags=["sqli", "error", "mssql", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-ORACLE-ERR",
            name="Oracle Error-Based Injection in Query Parameter",
            description="Target reflects Oracle ORA-01756 quoted string error.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/profile?id=50",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/profile?id=50",
                    status_code=200,
                    body="<html><body><h1>User Profile 50</h1></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="id=50%27",
                    status_code=500,
                    body="<html><body><h1>Error</h1><p>ORA-01756: quoted string not properly terminated</p></body></html>",
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="oracle",
                min_evidence_count=1,
            ),
            tags=["sqli", "error", "oracle", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-POS-BOOL-DIFF",
            name="Boolean-Based Differential Response in Query Parameter",
            description="Target returns identical content for TRUE condition and diverged content for FALSE condition.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/account?user_id=12",
            parameter_name="user_id",
            parameter_location="query",
            mock_responses=[
                # Baseline
                MockHTTPResponse(
                    url_pattern="http://lab.local/account?user_id=12",
                    status_code=200,
                    body="<html><body><h1>Account Dashboard</h1><p>Welcome, Alice (Active member)</p></body></html>",
                ),
                # Error probe (no syntax error shown)
                MockHTTPResponse(
                    url_pattern="user_id=12%27",
                    status_code=200,
                    body="<html><body><h1>Account Dashboard</h1><p>Welcome, Alice (Active member)</p></body></html>",
                ),
                # TRUE probe (1=1): matches baseline
                MockHTTPResponse(
                    url_pattern="user_id=12+AND+1%3D1",
                    status_code=200,
                    body="<html><body><h1>Account Dashboard</h1><p>Welcome, Alice (Active member)</p></body></html>",
                ),
                # FALSE probe (1=2): user not found
                MockHTTPResponse(
                    url_pattern="user_id=12+AND+1%3D2",
                    status_code=200,
                    body="<html><body><h1>User Not Found</h1><p>No account records matching query.</p></body></html>",
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="boolean_differential",
                min_evidence_count=1,
            ),
            tags=["sqli", "differential", "boolean", "positive"],
        )
    )

    # =========================================================================
    # 2. SQL Injection Negative Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="SQLI-NEG-CLEAN-QUERY",
            name="Clean Query Parameter Without Injection Signals",
            description="Target returns normal, identical responses across all probes without error or differential.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/catalog?page=1",
            parameter_name="page",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/catalog",
                    status_code=200,
                    body="<html><body><h1>Catalog Page 1</h1><p>10 items listed</p></body></html>",
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["sqli", "negative", "clean"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-NEG-GENERIC-500",
            name="Generic HTTP 500 Server Error Without Database Signatures",
            description="Target returns a generic 500 error lacking any recognized database error patterns.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/reports?id=5",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/reports?id=5",
                    status_code=200,
                    body="<html><body><h1>Report 5</h1><p>Summary data</p></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="http://lab.local/reports",
                    status_code=500,
                    body="<html><body><h1>500 Internal Server Error</h1><p>An unexpected application error occurred.</p></body></html>",
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["sqli", "negative", "generic_500"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-NEG-APP-VALIDATION",
            name="Application Validation Error Without Database Vulnerability",
            description="Target returns normal HTTP 400 with input validation message.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/contact",
            http_method="POST",
            parameter_name="email",
            parameter_location="body_urlencoded",
            data="email=user%40example.com&msg=hello",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/contact",
                    status_code=200,
                    body="<html><body><h1>Contact Form</h1><p>Feedback received</p></body></html>",
                ),
                MockHTTPResponse(
                    url_pattern="email=",
                    status_code=400,
                    body="<html><body><h1>Validation Error</h1><p>Invalid email address format.</p></body></html>",
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["sqli", "negative", "validation"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-NEG-SQL-KEYWORDS",
            name="Benign Page Content Containing Natural SQL Keywords",
            description="Target page naturally contains words 'SELECT', 'FROM', 'ORDER' in text without injection.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/about",
            parameter_name="section",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/about",
                    status_code=200,
                    body=(
                        "<html><body><h1>About Us</h1>"
                        "<p>Please SELECT your options FROM the menu below to ORDER our products.</p></body></html>"
                    ),
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["sqli", "negative", "keywords"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-NEG-PREEXISTING-ERR",
            name="Pre-Existing Database Error Already Present in Baseline",
            description="Baseline response already contains a database error; probe does not introduce new error.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/broken?id=1",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/broken",
                    status_code=500,
                    body=(
                        "<html><body><h1>System Notice</h1>"
                        "<p>You have an error in your SQL syntax; check the manual near 'broken'</p></body></html>"
                    ),
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["sqli", "negative", "preexisting"],
        )
    )

    # =========================================================================
    # 3. SQL Injection Ambiguous / Boundary Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="SQLI-AMB-UNSTABLE-BASE",
            name="Unstable Nondeterministic Baseline Response",
            description="Baseline returns erratic content, preventing reliable differential comparison.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="http://lab.local/random?id=7",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/random",
                    status_code=200,
                    body="<html><body><h1>Dynamic Token:</h1><p>XYZ123456789</p></body></html>",
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.AMBIGUOUS_INCONCLUSIVE,
                status="no_indicator",
            ),
            tags=["sqli", "ambiguous", "unstable"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="SQLI-AMB-SCOPE-BLOCKED",
            name="Out-of-Scope Target Refused by Engine",
            description="Target host not in ScopeManager whitelist; scan blocked immediately.",
            category=ScenarioCategory.SQL_INJECTION,
            target_url="https://unauthorized-external.com/items?id=1",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.BLOCKED_OR_ERROR,
                status="blocked_by_scope",
            ),
            tags=["sqli", "scope", "safety"],
        )
    )

    # =========================================================================
    # 4. NoSQL Injection Positive Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-POS-MONGO-ERR",
            name="MongoDB Unknown Operator Error in Query Parameter",
            description="Target returns MongoServerError when $invalid_nosql_op probe is injected.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/items?id=1",
            parameter_name="id",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/items?id=1",
                    status_code=200,
                    body='{"status": "success", "data": {"id": 1, "name": "Doc A"}}',
                ),
                MockHTTPResponse(
                    url_pattern="id%5B%24invalid_nosql_op%5D=1",
                    status_code=500,
                    body='{"error": "MongoServerError: unknown operator: $invalid_nosql_op", "code": 2}',
                ),
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/items",
                    status_code=200,
                    body='{"status": "success", "data": {"id": 1, "name": "Doc A"}}',
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="mongodb",
                min_evidence_count=1,
            ),
            tags=["nosqli", "error", "mongodb", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-POS-COUCH-ERR",
            name="CouchDB Query Error in JSON Parameter",
            description="Target returns CouchDB compilation or syntax error.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/query",
            http_method="POST",
            parameter_name="filter",
            parameter_location="body_json",
            json_data={"filter": "status"},
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/query",
                    status_code=200,
                    body='{"ok": true, "rows": []}',
                ),
                MockHTTPResponse(
                    url_pattern="$invalid_nosql_op",
                    status_code=500,
                    body='{"error": "query_parse_error", "reason": "CouchDB query compilation error: syntax error"}',
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="error_based",
                family="couchdb",
                min_evidence_count=1,
            ),
            tags=["nosqli", "error", "couchdb", "json", "positive"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-POS-MONGO-DIFF",
            name="MongoDB Boolean Differential ($ne vs $eq)",
            description="Target matches baseline on $ne probe and diverges on $eq probe.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/user?uid=5",
            parameter_name="uid",
            parameter_location="query",
            mock_responses=[
                # Baseline
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/user?uid=5",
                    status_code=200,
                    body='{"user": "alice", "role": "admin", "active": true}',
                ),
                # Error probe returns standard profile
                MockHTTPResponse(
                    url_pattern="uid%5B%24invalid_nosql_op%5D=1",
                    status_code=200,
                    body='{"user": "alice", "role": "admin", "active": true}',
                ),
                # True condition: uid[$ne]=__dbshield_sentinel__ returns alice
                MockHTTPResponse(
                    url_pattern="uid%5B%24ne%5D=__dbshield_sentinel__",
                    status_code=200,
                    body='{"user": "alice", "role": "admin", "active": true}',
                ),
                # False condition: uid[$eq]=__dbshield_sentinel__ returns empty
                MockHTTPResponse(
                    url_pattern="uid%5B%24eq%5D=__dbshield_sentinel__",
                    status_code=200,
                    body='{"user": null, "message": "User not found"}',
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_POSITIVE,
                status="potential_indicator",
                technique="boolean_differential",
                family="mongodb",
                min_evidence_count=1,
            ),
            tags=["nosqli", "differential", "mongodb", "positive"],
        )
    )

    # =========================================================================
    # 5. NoSQL Injection Negative Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-NEG-CLEAN-QUERY",
            name="Clean NoSQL Query Parameter",
            description="Target returns standard catalog without any NoSQL operator errors or variance.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/catalog?category=books",
            parameter_name="category",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/catalog",
                    status_code=200,
                    body='{"status": "ok", "items": [{"id": 1, "name": "Book 1"}]}',
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["nosqli", "negative", "clean"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-NEG-APP-400",
            name="NoSQL Application 400 Bad Request Without Injection",
            description="Target returns standard 400 Bad Request on invalid parameter format without NoSQL error.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/orders?status=active",
            parameter_name="status",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/orders?status=active",
                    status_code=200,
                    body='{"orders": [1, 2, 3]}',
                ),
                MockHTTPResponse(
                    url_pattern="status%5B",
                    status_code=400,
                    body='{"error": "Invalid query parameter structure: string expected."}',
                ),
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["nosqli", "negative", "400"],
        )
    )

    scenarios.append(
        LabScenario(
            scenario_id="NOSQLI-NEG-OPERATOR-STRING",
            name="Natural Appearance of Operator Strings in Text",
            description="Target response naturally contains '$gt' or '$regex' in documentation text without injection.",
            category=ScenarioCategory.NOSQL_INJECTION,
            target_url="http://lab.local/api/docs?page=operators",
            parameter_name="page",
            parameter_location="query",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/docs",
                    status_code=200,
                    body=(
                        '{"doc": "MongoDB supports operators like $gt, $lt, and $regex for querying. '
                        'Use them responsibly."}'
                    ),
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.TRUE_NEGATIVE,
                status="no_indicator",
                min_evidence_count=0,
            ),
            tags=["nosqli", "negative", "operator_string"],
        )
    )

    # =========================================================================
    # 6. Safety & Resource Limit Scenarios
    # =========================================================================
    scenarios.append(
        LabScenario(
            scenario_id="SAFETY-INELIGIBLE-PARAM",
            name="Safety Guard: Ineligible Credential Parameter Skipped",
            description="Sensitive parameters like 'password' or 'token' must be flagged ineligible and never probed.",
            category=ScenarioCategory.SAFETY_BUDGET,
            target_url="http://lab.local/api/auth",
            http_method="POST",
            parameter_name="password",
            parameter_location="body_urlencoded",
            data="user=alice&password=secretPassword123",
            mock_responses=[
                MockHTTPResponse(
                    url_pattern="http://lab.local/api/auth",
                    status_code=200,
                    body="<html><body>Login</body></html>",
                )
            ],
            expected=ExpectedOutcome(
                classification=ExpectedClassification.BLOCKED_OR_ERROR,
                status="ineligible_skipped",
                min_evidence_count=0,
            ),
            tags=["safety", "credential", "zero_leakage"],
        )
    )

    return scenarios


def load_scenarios_from_file(file_path: str | Path) -> list[LabScenario]:
    """Load lab validation scenarios from an external JSON file.

    The file must contain a JSON array of scenario definitions or an object with a 'scenarios' list.
    """
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Scenario file '{file_path}' does not exist.")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    raw_list: list[dict[str, Any]]
    if isinstance(data, list):
        raw_list = data
    elif isinstance(data, dict) and "scenarios" in data and isinstance(data["scenarios"], list):
        raw_list = data["scenarios"]
    else:
        raise ValueError(
            f"Scenario file '{file_path}' must contain a JSON array of scenarios or a 'scenarios' field."
        )

    return [LabScenario.model_validate(item) for item in raw_list]
