"""Login page discovery engine orchestrator for DBShield Phase 2.

Safely retrieves authorized target pages, coordinates tolerant HTML parsing,
applies rule-based heuristic classification, and constructs immutable,
structured DiscoveryResult instances.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from dbshield.discovery.classifier import DiscoveryClassifier
from dbshield.discovery.parser import HTMLFormParser
from dbshield.exceptions import (
    HTTPClientError,
    NetworkError,
    ScopeViolationError,
    URLValidationError,
)
from dbshield.http.client import SafeHTTPClient
from dbshield.models.discovery import (
    DiscoveredForm,
    DiscoveryResult,
    DiscoveryStatus,
    DiscoverySummary,
    FieldClassification,
    InputField,
    PageClassification,
)
from dbshield.models.http import HTTPResponse
from dbshield.models.target import Target
from dbshield.scope.manager import ScopeManager

logger = logging.getLogger("dbshield.discovery.engine")


class DiscoveryEngine:
    """Orchestrates passive login page retrieval and input identification."""

    def __init__(
        self,
        scope_manager: ScopeManager,
        http_client: SafeHTTPClient | None = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
        user_agent: str = "DBShield/0.1.0 (Database Vulnerability Assessment Framework)",
        parser: HTMLFormParser | None = None,
        classifier: DiscoveryClassifier | None = None,
    ) -> None:
        """Initialize the discovery engine.

        Args:
            scope_manager: Authoritative target scope manager.
            http_client: Optional pre-configured SafeHTTPClient instance.
            timeout: Maximum network timeout for page retrieval.
            max_redirects: Maximum number of in-scope redirects allowed.
            user_agent: User-Agent header for HTTP requests.
            parser: Optional HTMLFormParser instance.
            classifier: Optional DiscoveryClassifier instance.
        """
        self.scope_manager = scope_manager
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = SafeHTTPClient(
                scope_manager=self.scope_manager,
                timeout=self.timeout,
                max_redirects=self.max_redirects,
                user_agent=self.user_agent,
            )
            self._owns_client = True

        self.parser = parser or HTMLFormParser()
        self.classifier = classifier or DiscoveryClassifier()

    def close(self) -> None:
        """Release underlying HTTP client resources if owned."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "DiscoveryEngine":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def discover(self, url: str | Target) -> DiscoveryResult:
        """Execute login page discovery against an authorized URL.

        Args:
            url: Target URL string or Target model instance.

        Returns:
            Structured DiscoveryResult with detailed form and field inventories.
        """
        discovery_id = str(uuid.uuid4())
        warnings: list[str] = []
        errors: list[str] = []

        # 1. Target Validation & Normalization
        try:
            target = url if isinstance(url, Target) else Target.from_url(url)
        except URLValidationError as exc:
            errors.append(f"Invalid target URL: {exc.message}")
            return DiscoveryResult(
                discovery_id=discovery_id,
                target_url=str(url),
                status=DiscoveryStatus.FAILED,
                page_classification=PageClassification.PAGE_COULD_NOT_BE_ANALYZED,
                page_evidence=["URL validation failed"],
                warnings=warnings,
                errors=errors,
            )

        # 2. Scope Boundary Check
        try:
            self.scope_manager.assert_in_scope(target)
        except ScopeViolationError as exc:
            errors.append(f"Target '{target.full_url}' is outside authorized scope: {exc.message}")
            return DiscoveryResult(
                discovery_id=discovery_id,
                target_url=target.full_url,
                status=DiscoveryStatus.BLOCKED_BY_SCOPE,
                page_classification=PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED,
                page_evidence=[f"Blocked by scope rules: host '{target.host}' not authorized"],
                warnings=warnings,
                errors=errors,
            )

        # 3. Safe HTTP Page Retrieval
        response: HTTPResponse | None = None
        final_url: str = target.full_url
        try:
            logger.info("Executing safe HTTP retrieval for target: %s", target.full_url)
            response = self._client.get(target)
            final_url = str(response.url)
        except ScopeViolationError as exc:
            errors.append(f"Redirect led to out-of-scope host: {exc.message}")
            return DiscoveryResult(
                discovery_id=discovery_id,
                target_url=target.full_url,
                status=DiscoveryStatus.BLOCKED_BY_SCOPE,
                page_classification=PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED,
                page_evidence=["Redirect to unauthorized destination was blocked"],
                warnings=warnings,
                errors=errors,
            )
        except (NetworkError, HTTPClientError) as exc:
            errors.append(f"Failed to retrieve target page: {exc.message}")
            return DiscoveryResult(
                discovery_id=discovery_id,
                target_url=target.full_url,
                status=DiscoveryStatus.FAILED,
                page_classification=PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED,
                page_evidence=[f"Network/HTTP retrieval error: {exc.message}"],
                warnings=warnings,
                errors=errors,
            )
        except Exception as exc:
            errors.append(f"Unexpected retrieval failure: {exc}")
            return DiscoveryResult(
                discovery_id=discovery_id,
                target_url=target.full_url,
                status=DiscoveryStatus.FAILED,
                page_classification=PageClassification.PAGE_INACCESSIBLE_OR_BLOCKED,
                page_evidence=[f"Unexpected exception during retrieval: {exc}"],
                warnings=warnings,
                errors=errors,
            )

        assert response is not None
        http_status = response.status_code
        content_type = response.headers.get("content-type", "")

        if http_status >= 400:
            warnings.append(f"Target returned non-successful HTTP status code: {http_status}")

        # Check content-type
        is_html = ("text/html" in content_type.lower()) or ("xhtml" in content_type.lower())
        if not is_html and content_type:
            warnings.append(
                f"Response Content-Type '{content_type}' is not text/html. HTML analysis may yield incomplete results."
            )

        # 4. HTML Parsing
        parsed_page = self.parser.parse(response.text, base_url=final_url)
        warnings.extend(parsed_page.warnings)

        # 5. Form & Control Classification with Scope Validation on Actions
        classified_forms: list[DiscoveredForm] = []
        action_in_scope_count = 0
        action_out_of_scope_count = 0

        for raw_form in parsed_page.forms:
            form = self.classifier.classify_form(raw_form, page_url=final_url)

            # Evaluate Form Action Authorization against ScopeManager (WITHOUT contacting action URL)
            is_action_in_scope = self.scope_manager.is_url_in_scope(form.resolved_action)
            if not is_action_in_scope:
                action_out_of_scope_count += 1
                warnings.append(
                    f"Form '{form.form_id}' action URL '{form.resolved_action}' is outside authorized scope and must not be contacted."
                )
                # Re-create model with is_action_in_scope=False
                form = form.model_copy(update={"is_action_in_scope": False})
            else:
                action_in_scope_count += 1

            classified_forms.append(form)

        # Classify orphan input controls
        classified_orphans = [
            self.classifier.classify_control(control) for control in parsed_page.orphan_inputs
        ]

        # 6. Page Classification
        page_classification, page_evidence = self.classifier.classify_page(
            forms=classified_forms,
            orphan_inputs=classified_orphans,
            page_url=final_url,
        )

        # 7. Calculate Summary Metrics
        total_forms = len(classified_forms)
        login_forms = sum(1 for f in classified_forms if f.is_login_candidate)

        all_controls: list[InputField] = []
        for f in classified_forms:
            all_controls.extend(f.controls)
        all_controls.extend(classified_orphans)

        hidden_fields = sum(1 for c in all_controls if c.is_hidden)
        candidate_fields = sum(
            1
            for c in all_controls
            if not c.is_hidden and c.classification != FieldClassification.SUBMIT
        )
        password_fields = sum(
            1 for c in all_controls if c.classification == FieldClassification.PASSWORD
        )
        username_fields = sum(
            1
            for c in all_controls
            if c.classification in {FieldClassification.USERNAME, FieldClassification.EMAIL}
        )
        csrf_fields = sum(
            1 for c in all_controls if c.classification == FieldClassification.CSRF_TOKEN
        )

        summary = DiscoverySummary(
            total_forms=total_forms,
            login_forms=login_forms,
            candidate_fields=candidate_fields,
            hidden_fields=hidden_fields,
            password_fields=password_fields,
            username_fields=username_fields,
            csrf_fields=csrf_fields,
            action_urls_in_scope=action_in_scope_count,
            action_urls_out_of_scope=action_out_of_scope_count,
        )

        # 8. Determine Execution Status
        status = DiscoveryStatus.COMPLETED
        if warnings:
            status = DiscoveryStatus.COMPLETED_WITH_WARNINGS

        return DiscoveryResult(
            discovery_id=discovery_id,
            target_url=target.full_url,
            final_url=final_url,
            timestamp=datetime.now(UTC),
            status=status,
            http_status_code=http_status,
            content_type=content_type,
            page_title=parsed_page.title,
            page_query_params=parsed_page.page_query_params,
            page_classification=page_classification,
            page_evidence=page_evidence,
            forms=classified_forms,
            orphan_inputs=classified_orphans,
            summary=summary,
            warnings=warnings,
            errors=errors,
        )
