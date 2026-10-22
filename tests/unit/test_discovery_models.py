import json

import pytest
from pydantic import ValidationError

from dbshield.models.discovery import (
    DiscoveredForm,
    DiscoveryResult,
    DiscoveryStatus,
    DiscoverySummary,
    FieldClassification,
    InputField,
    PageClassification,
)


def test_discovery_result_serialization() -> None:
    control = InputField(
        name="username",
        input_type="text",
        element_type="input",
        id_attr="uid",
        autocomplete="username",
        required=True,
        is_hidden=False,
        is_auth_related=True,
        classification=FieldClassification.USERNAME,
        confidence=0.95,
        evidence=["Autocomplete attribute specifies 'username'"],
    )

    form = DiscoveredForm(
        form_id="form_1",
        declared_action="/login",
        resolved_action="https://example.com/login",
        method="POST",
        enctype="application/x-www-form-urlencoded",
        controls=[control],
        is_same_origin=True,
        is_action_in_scope=True,
        is_login_candidate=True,
        confidence=0.90,
        evidence=["Contains 1 username/email input field(s)"],
    )

    summary = DiscoverySummary(
        total_forms=1,
        login_forms=1,
        candidate_fields=1,
        username_fields=1,
    )

    result = DiscoveryResult(
        target_url="https://example.com/login",
        final_url="https://example.com/login",
        status=DiscoveryStatus.COMPLETED,
        http_status_code=200,
        content_type="text/html; charset=utf-8",
        page_title="Login - Secure Portal",
        page_classification=PageClassification.LOGIN_FORM_DETECTED,
        page_evidence=["Single authoritative login form detected"],
        forms=[form],
        summary=summary,
    )

    # Validate JSON serialization
    serialized_json = result.model_dump_json()
    data = json.loads(serialized_json)

    assert data["target_url"] == "https://example.com/login"
    assert data["status"] == "completed"
    assert data["page_classification"] == "login_form_detected"
    assert len(data["forms"]) == 1
    assert data["forms"][0]["controls"][0]["classification"] == "username"
    assert data["summary"]["login_forms"] == 1

    # Validate to_safe_dict
    safe_dict = result.to_safe_dict()
    assert isinstance(safe_dict, dict)
    assert safe_dict["http_status_code"] == 200


def test_models_immutability() -> None:
    field = InputField(name="test", input_type="text", element_type="input")
    with pytest.raises(ValidationError):
        # frozen=True prevents mutation
        field.name = "new_name"  # type: ignore[misc]
