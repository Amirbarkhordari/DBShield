"""Unit tests for PayloadTransformer input mutation and isolation (Phase 6)."""

import copy
from typing import Any

import pytest

from dbshield.execution.transformer import PayloadTransformer, TransformationError
from dbshield.models.target import Target
from dbshield.sqli.models import ParameterLocation


def test_transform_query_param_preserves_unrelated() -> None:
    """Verify that transforming a single query param preserves all sibling query params."""
    target = Target.from_url("https://example.com/search?category=books&page=1&sort=asc")
    q_params, data, json_body = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.QUERY,
        param_name="page",
        payload_value="2' OR '1'='1",
    )
    assert q_params == {"category": "books", "page": "2' OR '1'='1", "sort": "asc"}
    assert data is None
    assert json_body is None


def test_transform_repeated_query_param_preservation() -> None:
    """Verify handling of repeated query parameters."""
    target = Target.from_url("https://example.com/filter?tag=books&tag=tech&author=smith")
    q_params, _, _ = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.QUERY,
        param_name="author",
        payload_value="smith'",
    )
    assert q_params is not None
    assert q_params["author"] == "smith'"
    # Sibling tags should be preserved (list or multi-value)
    assert q_params["tag"] in (["books", "tech"], "books")


def test_transform_express_bracket_query_syntax() -> None:
    """Verify support for bracket notation in query parameters (user[name]=value)."""
    target = Target.from_url("https://example.com/api?user[name]=alice&user[role]=editor")
    q_params, _, _ = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.QUERY,
        param_name="user[name]",
        payload_value="admin",
    )
    assert q_params is not None
    assert q_params["user[name]"] == "admin"
    assert q_params["user[role]"] == "editor"


def test_transform_urlencoded_form_body_mutation() -> None:
    """Verify that form body mutation preserves unrelated fields."""
    target = Target.from_url("https://example.com/login")
    orig_form = "username=admin&password=secret&remember=1"

    q_params, mutated_form, json_body = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.BODY_URLENCODED,
        param_name="username",
        payload_value="admin' OR 1=1--",
        data=orig_form,
    )
    assert q_params is None
    assert json_body is None
    assert isinstance(mutated_form, str)
    assert (
        "username=admin%27+OR+1%3D1--" in mutated_form
        or "username=admin'%20OR%201=1--" in mutated_form
        or "admin' OR 1=1--" in mutated_form
    )
    assert "password=secret" in mutated_form
    assert "remember=1" in mutated_form


def test_transform_top_level_json_mutation() -> None:
    """Verify top-level JSON parameter mutation."""
    target = Target.from_url("https://example.com/api/users")
    json_in = {"username": "alice", "active": True, "count": 10}

    _, _, mutated_json = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.BODY_JSON,
        param_name="username",
        payload_value={"$ne": None},
        json_data=json_in,
    )
    assert mutated_json == {
        "username": {"$ne": None},
        "active": True,
        "count": 10,
    }


def test_transform_nested_json_dot_path_mutation() -> None:
    """Verify nested dot-path mutation inside JSON structures."""
    target = Target.from_url("https://example.com/api/account")
    json_in = {
        "profile": {
            "name": "Bob",
            "contact": {
                "email": "bob@example.com",
                "verified": False,
            },
        },
        "role": "user",
    }

    _, _, mutated = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.BODY_JSON,
        param_name="profile.contact.email",
        payload_value={"$gt": ""},
        key_path=["profile", "contact", "email"],
        json_data=json_in,
    )
    assert mutated["profile"]["contact"]["email"] == {"$gt": ""}
    assert mutated["profile"]["contact"]["verified"] is False
    assert mutated["profile"]["name"] == "Bob"
    assert mutated["role"] == "user"


def test_transform_json_array_element_mutation() -> None:
    """Verify mutation of array elements at indexed paths."""
    target = Target.from_url("https://example.com/api/orders")
    json_in = {
        "items": [
            {"sku": "A100", "qty": 2},
            {"sku": "B200", "qty": 1},
        ],
        "discount": 0,
    }

    _, _, mutated = PayloadTransformer.transform(
        target=target,
        param_location=ParameterLocation.BODY_JSON,
        param_name="items.0.sku",
        payload_value="A100'",
        key_path=["items", "0", "sku"],
        json_data=json_in,
    )
    assert mutated["items"][0]["sku"] == "A100'"
    assert mutated["items"][0]["qty"] == 2
    assert mutated["items"][1]["sku"] == "B200"
    assert mutated["discount"] == 0


def test_transform_caller_isolation_immutability() -> None:
    """CRITICAL: Verify that the caller's original objects are never modified in place."""
    target_orig = Target.from_url("https://example.com/api/test?search=initial")
    json_orig: dict[str, Any] = {
        "filter": {"user_id": "123", "active": True},
        "tags": ["alpha", "beta"],
    }
    json_backup = copy.deepcopy(json_orig)
    form_orig = "param1=val1&param2=val2"

    # 1. Transform query
    PayloadTransformer.transform(
        target=target_orig,
        param_location=ParameterLocation.QUERY,
        param_name="search",
        payload_value="mutated_search",
    )
    assert target_orig.query == "search=initial"

    # 2. Transform JSON
    PayloadTransformer.transform(
        target=target_orig,
        param_location=ParameterLocation.BODY_JSON,
        param_name="filter.user_id",
        payload_value={"$ne": None},
        key_path=["filter", "user_id"],
        json_data=json_orig,
    )
    assert json_orig == json_backup
    assert json_orig["filter"]["user_id"] == "123"

    # 3. Transform form data
    PayloadTransformer.transform(
        target=target_orig,
        param_location=ParameterLocation.BODY_URLENCODED,
        param_name="param1",
        payload_value="mutated_val",
        data=form_orig,
    )
    assert form_orig == "param1=val1&param2=val2"


def test_transform_unsupported_path_handling() -> None:
    """Verify that invalid/unresolvable nested paths raise TransformationError."""
    target = Target.from_url("https://example.com/api/test")
    json_in = {"a": 123}

    with pytest.raises(TransformationError):
        PayloadTransformer.transform(
            target=target,
            param_location=ParameterLocation.BODY_JSON,
            param_name="a.b.c",
            payload_value="probe",
            key_path=["a", "b", "c"],
            json_data=json_in,
        )
