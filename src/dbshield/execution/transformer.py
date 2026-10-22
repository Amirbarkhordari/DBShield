"""Safe, isolated request parameter transformation for DBShield test execution (Phase 6).

Provides deterministic mutation of target parameters across URL query parameters,
form-encoded bodies, and nested JSON documents while preserving caller data,
unrelated fields, sibling keys, and document structures.
"""

import copy
import json
import logging
import urllib.parse
from typing import Any

from dbshield.exceptions import DBShieldError
from dbshield.models.target import Target
from dbshield.sqli.models import ParameterLocation

logger = logging.getLogger("dbshield.execution.transformer")


class TransformationError(DBShieldError):
    """Raised when a request structure cannot be safely transformed."""

    def __init__(self, message: str, cause: str | None = None, remedy: str | None = None) -> None:
        super().__init__(
            message=message,
            cause=cause or "Request data was malformed or could not be safely mutated.",
            remedy=remedy or "Verify request structure matches expected format.",
        )


class PayloadTransformer:
    """Transforms request parameters into isolated test variants."""

    @classmethod
    def transform(
        cls,
        target: Target,
        param_location: ParameterLocation,
        param_name: str,
        payload_value: Any,
        key_path: list[str] | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
    ) -> tuple[dict[str, Any] | None, Any | None, Any | None]:
        """Apply test payload to target parameter in an isolated clone of request data.

        Args:
            target: Target URL model.
            param_location: HTTP transport location.
            param_name: Parameter name or dot-delimited key path.
            payload_value: Payload to inject (str, dict, list, int).
            key_path: Optional path of keys for nested JSON.
            data: Form or raw body data.
            json_data: JSON document data.

        Returns:
            Tuple of (req_params, req_data, req_json) for SafeHTTPClient dispatch.

        Raises:
            TransformationError: If data cannot be safely transformed.
        """
        req_params: dict[str, Any] | None = None
        req_data: Any | None = data
        req_json: Any | None = json_data

        try:
            if param_location == ParameterLocation.QUERY:
                req_params = cls._mutate_query_param(target.query or "", param_name, payload_value)

            elif param_location == ParameterLocation.BODY_URLENCODED:
                req_data = cls._mutate_form_param(data, param_name, payload_value)

            elif param_location == ParameterLocation.BODY_JSON:
                req_json = cls._mutate_json_param(
                    json_data, key_path or param_name.split("."), payload_value
                )

            return req_params, req_data, req_json

        except TransformationError:
            raise
        except Exception as exc:
            logger.error(
                "Unexpected failure transforming parameter '%s' (%s): %s",
                param_name,
                param_location.value,
                exc,
            )
            raise TransformationError(
                message=f"Failed to safely transform parameter '{param_name}'.",
                cause=str(exc),
            ) from exc

    @classmethod
    def _mutate_query_param(
        cls, query_string: str, param_name: str, payload_value: Any
    ) -> dict[str, Any]:
        """Mutate query parameter preserving repeated parameters and handling Express/qs syntax."""
        existing = urllib.parse.parse_qs(query_string, keep_blank_values=True)

        if (
            isinstance(payload_value, str)
            and payload_value.startswith("[")
            and "]=" in payload_value
        ):
            # Express/qs style object injection into query: param[$op]=val
            op_key, op_val = payload_value.split("]=", 1)
            full_param = f"{param_name}{op_key}]"
            existing.pop(param_name, None)
            existing[full_param] = [op_val]
        else:
            # Standard scalar value replacement
            existing[param_name] = [str(payload_value) if payload_value is not None else ""]

        # Flatten single-element lists while preserving multi-element lists if present
        result: dict[str, Any] = {}
        for k, v in existing.items():
            result[k] = v[0] if len(v) == 1 else v
        return result

    @classmethod
    def _mutate_form_param(cls, data: Any | None, param_name: str, payload_value: Any) -> str:
        """Mutate URL-encoded form data preserving unrelated keys and encoding."""
        if not data or not isinstance(data, str):
            # If no form data exists, initialize with just the test parameter
            if (
                isinstance(payload_value, str)
                and payload_value.startswith("[")
                and "]=" in payload_value
            ):
                op_key, op_val = payload_value.split("]=", 1)
                return urllib.parse.urlencode({f"{param_name}{op_key}]": op_val})
            return urllib.parse.urlencode({param_name: str(payload_value)})

        try:
            parsed = urllib.parse.parse_qs(data, keep_blank_values=True)
            if (
                isinstance(payload_value, str)
                and payload_value.startswith("[")
                and "]=" in payload_value
            ):
                op_key, op_val = payload_value.split("]=", 1)
                full_param = f"{param_name}{op_key}]"
                parsed.pop(param_name, None)
                parsed[full_param] = [op_val]
            else:
                parsed[param_name] = [str(payload_value) if payload_value is not None else ""]

            flattened: dict[str, Any] = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            return urllib.parse.urlencode(flattened, doseq=True)
        except Exception as exc:
            raise TransformationError(
                message=f"Failed to parse or mutate URL-encoded form data for '{param_name}'.",
                cause=str(exc),
            ) from exc

    @classmethod
    def _mutate_json_param(
        cls, json_data: Any | None, key_path: list[str], payload_value: Any
    ) -> Any:
        """Mutate JSON structure at specified key path while preserving all sibling and parent elements."""
        if json_data is None:
            # Construct minimal dictionary for the path
            curr: Any = payload_value
            for step in reversed(key_path):
                curr = {step: curr}
            return curr

        dict_data: Any
        if isinstance(json_data, str):
            try:
                dict_data = json.loads(json_data)
            except Exception as exc:
                raise TransformationError(
                    message="JSON request body contains invalid JSON syntax.",
                    cause=str(exc),
                ) from exc
        else:
            dict_data = json_data

        # Deep clone to ensure original caller object is never mutated
        cloned = copy.deepcopy(dict_data)
        if not key_path:
            return payload_value

        curr_node = cloned
        for step in key_path[:-1]:
            if isinstance(curr_node, dict):
                if step not in curr_node:
                    curr_node[step] = {}
                curr_node = curr_node[step]
            elif isinstance(curr_node, list) and step.isdigit():
                idx = int(step)
                if idx < len(curr_node):
                    curr_node = curr_node[idx]
                else:
                    raise TransformationError(
                        message=f"Array index {idx} out of range in JSON path.",
                        cause=f"Array length is {len(curr_node)}.",
                    )
            else:
                raise TransformationError(
                    message=f"Cannot traverse non-container node at step '{step}'.",
                    cause=f"Node type is {type(curr_node).__name__}.",
                )

        last_key = key_path[-1]
        if isinstance(curr_node, dict):
            curr_node[last_key] = copy.deepcopy(payload_value)
        elif isinstance(curr_node, list) and last_key.isdigit():
            idx = int(last_key)
            if idx < len(curr_node):
                curr_node[idx] = copy.deepcopy(payload_value)
            else:
                curr_node.append(copy.deepcopy(payload_value))
        else:
            raise TransformationError(
                message=f"Cannot set property on non-container node at terminal key '{last_key}'.",
                cause=f"Terminal container type is {type(curr_node).__name__}.",
            )

        return cloned
