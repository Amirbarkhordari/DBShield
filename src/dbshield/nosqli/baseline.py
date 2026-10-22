"""Baseline response characterizer for NoSQL injection testing.

Establishes normal, unperturbed endpoint behavior and evaluates response stability
before testing candidate inputs. Unstable or error-prone baselines are flagged
to prevent inaccurate differential or operator-based classifications.
"""

import logging
from typing import Any

from dbshield.http.client import SafeHTTPClient
from dbshield.models.http import HTTPMethod, HTTPResponse
from dbshield.models.target import Target
from dbshield.nosqli.models import NoSQLBaselineProfile
from dbshield.nosqli.normalization import NoSQLResponseNormalizer

logger = logging.getLogger("dbshield.nosqli.baseline")


class NoSQLBaselineCharacterizer:
    """Probes endpoints to characterize normal response status, timing, and content."""

    def __init__(
        self,
        http_client: SafeHTTPClient,
        stability_samples: int = 2,
    ) -> None:
        """Initialize characterizer.

        Args:
            http_client: Configured, scope-enforcing SafeHTTPClient.
            stability_samples: Number of baseline sample probes to test stability (1 or 2).
        """
        self.http_client = http_client
        self.stability_samples = max(1, min(stability_samples, 3))

    def characterize(
        self,
        endpoint: str | Target,
        method: str | HTTPMethod = HTTPMethod.GET,
        params: dict[str, Any] | None = None,
        data: Any | None = None,
        json_data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[NoSQLBaselineProfile, HTTPResponse]:
        """Establish baseline response behavior for target endpoint.

        Args:
            endpoint: URL or Target object.
            method: HTTP method.
            params: Query parameters.
            data: Form-encoded or raw data.
            json_data: JSON payload.
            headers: Custom request headers.

        Returns:
            Tuple of (NoSQLBaselineProfile, initial HTTPResponse).
        """
        samples: list[HTTPResponse] = []

        for idx in range(self.stability_samples):
            logger.debug(
                "Dispatching NoSQL baseline characterization probe #%d to %s",
                idx + 1,
                endpoint,
            )
            response = self.http_client.request(
                method=method,
                url=endpoint,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
            )
            samples.append(response)

        initial_response = samples[0]
        norm_initial = NoSQLResponseNormalizer.normalize(initial_response.body)
        body_hash = NoSQLResponseNormalizer.compute_hash(norm_initial)

        # Baseline error status check (e.g. 5xx or server-side error)
        if initial_response.is_server_error:
            logger.warning(
                "NoSQL baseline probe returned server error HTTP %d; marking baseline unstable.",
                initial_response.status_code,
            )
            profile = NoSQLBaselineProfile(
                status_code=initial_response.status_code,
                content_type=initial_response.content_type,
                content_length=len(initial_response.body),
                elapsed_seconds=initial_response.elapsed_seconds,
                is_stable=False,
                instability_reason=f"Baseline endpoint returned server error HTTP {initial_response.status_code}.",
                sample_count=len(samples),
                body_hash=body_hash,
            )
            return profile, initial_response

        # Stability evaluation across multiple samples
        if len(samples) > 1:
            second_response = samples[1]

            # Check status code stability
            if initial_response.status_code != second_response.status_code:
                logger.warning(
                    "NoSQL baseline status code varied across probes: %d vs %d.",
                    initial_response.status_code,
                    second_response.status_code,
                )
                profile = NoSQLBaselineProfile(
                    status_code=initial_response.status_code,
                    content_type=initial_response.content_type,
                    content_length=len(initial_response.body),
                    elapsed_seconds=(
                        initial_response.elapsed_seconds + second_response.elapsed_seconds
                    )
                    / 2.0,
                    is_stable=False,
                    instability_reason=(
                        f"Status code varied between baseline samples: "
                        f"probe 1 returned {initial_response.status_code}, probe 2 returned {second_response.status_code}."
                    ),
                    sample_count=len(samples),
                    body_hash=body_hash,
                )
                return profile, initial_response

            # Check normalized body similarity
            norm_second = NoSQLResponseNormalizer.normalize(second_response.body)
            sim = NoSQLResponseNormalizer.compute_similarity(norm_initial, norm_second)
            if sim < 0.80:
                logger.warning(
                    "NoSQL baseline body similarity between samples was too low: %.3f.", sim
                )
                profile = NoSQLBaselineProfile(
                    status_code=initial_response.status_code,
                    content_type=initial_response.content_type,
                    content_length=len(initial_response.body),
                    elapsed_seconds=(
                        initial_response.elapsed_seconds + second_response.elapsed_seconds
                    )
                    / 2.0,
                    is_stable=False,
                    instability_reason=f"Normalized baseline response bodies fluctuated excessively (similarity: {sim:.2f} < 0.80).",
                    sample_count=len(samples),
                    body_hash=body_hash,
                )
                return profile, initial_response

        # Baseline is stable
        avg_elapsed = sum(s.elapsed_seconds for s in samples) / len(samples)
        profile = NoSQLBaselineProfile(
            status_code=initial_response.status_code,
            content_type=initial_response.content_type,
            content_length=len(initial_response.body),
            elapsed_seconds=round(avg_elapsed, 4),
            is_stable=True,
            instability_reason=None,
            sample_count=len(samples),
            body_hash=body_hash,
        )
        return profile, initial_response

    @classmethod
    def from_captured_response(
        cls, response: HTTPResponse
    ) -> tuple[NoSQLBaselineProfile, HTTPResponse]:
        """Create a baseline profile from a captured response fixture (for offline validation)."""
        norm = NoSQLResponseNormalizer.normalize(response.body)
        body_hash = NoSQLResponseNormalizer.compute_hash(norm)

        is_stable = not response.is_server_error
        instability_reason = (
            f"Captured baseline returned server error HTTP {response.status_code}."
            if response.is_server_error
            else None
        )

        profile = NoSQLBaselineProfile(
            status_code=response.status_code,
            content_type=response.content_type,
            content_length=len(response.body),
            elapsed_seconds=response.elapsed_seconds,
            is_stable=is_stable,
            instability_reason=instability_reason,
            sample_count=1,
            body_hash=body_hash,
        )
        return profile, response
