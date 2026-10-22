"""Heuristic classification engine for DBShield Phase 2.

Implements rule-based, transparent, and explainable security classification
of HTML form controls, forms, and pages without executing active payloads.
"""

import logging
import re
from urllib.parse import urlparse

from dbshield.discovery.parser import ParsedForm, ParsedInput
from dbshield.models.discovery import (
    DiscoveredForm,
    FieldClassification,
    InputField,
    PageClassification,
)

logger = logging.getLogger("dbshield.discovery.classifier")

# Regex patterns for input field classification
RE_PASSWORD = re.compile(
    r"\b(?:password|passwd|pwd|passcode|pass|secret|auth_?pass)\b",
    re.IGNORECASE,
)
RE_USERNAME = re.compile(
    r"\b(?:username|user(?:name)?|user_?id|login(?:_?id)?|account(?:_?id)?|uname|identifier|handle)\b",
    re.IGNORECASE,
)
RE_EMAIL = re.compile(
    r"\b(?:email|e-mail|user_?email|mail_?address)\b",
    re.IGNORECASE,
)
RE_OTP = re.compile(
    r"\b(?:otp|totp|2fa|mfa|verification(?:_?code)?|auth(?:_?code)?|passcode|sms(?:_?code)?|pin)\b",
    re.IGNORECASE,
)
RE_CSRF = re.compile(
    r"\b(?:csrf(?:_?token)?|xsrf(?:_?token)?|_?token|authenticity_token|csrfmiddlewaretoken|anticsrf|__requestverificationtoken|state)\b",
    re.IGNORECASE,
)
RE_SEARCH = re.compile(
    r"\b(?:search|query|find|keyword|term)\b|^q$",
    re.IGNORECASE,
)
RE_REGISTRATION = re.compile(
    r"\b(?:register|registration|signup|sign_?up|create_?account|confirm_?password|password_?confirm)\b",
    re.IGNORECASE,
)
RE_LOGIN_ACTION = re.compile(
    r"(?:login|signin|sign_?in|authenticate|auth|session|logon)",
    re.IGNORECASE,
)


class DiscoveryClassifier:
    """Rule-based classifier evaluating input fields, forms, and overall pages."""

    def classify_control(self, raw_input: ParsedInput) -> InputField:
        """Classify a single input control using transparent heuristics."""
        evidence: list[str] = []
        classification = FieldClassification.UNKNOWN
        confidence = 0.5
        is_auth_related = False

        name = raw_input.name or ""
        id_attr = raw_input.id_attr or ""
        input_type = raw_input.input_type.lower()
        autocomplete = (raw_input.autocomplete or "").lower()
        placeholder = raw_input.placeholder or ""
        labels_combined = " ".join(raw_input.labels)

        raw_signals = f"{name} {id_attr} {placeholder} {labels_combined}".strip()
        spaced_signals = re.sub(r"[_\-.:/]+", " ", raw_signals)
        text_signals = f"{raw_signals} {spaced_signals}".strip()

        # 1. Password detection
        if input_type == "password":
            classification = FieldClassification.PASSWORD
            confidence = 0.99
            is_auth_related = True
            evidence.append("HTML input type is explicitly 'password'")
        elif autocomplete in {"current-password", "new-password"}:
            classification = FieldClassification.PASSWORD
            confidence = 0.95
            is_auth_related = True
            evidence.append(f"Autocomplete specifies password attribute: '{autocomplete}'")
        elif RE_PASSWORD.search(text_signals):
            classification = FieldClassification.PASSWORD
            confidence = 0.85
            is_auth_related = True
            evidence.append(
                f"Field name/id/placeholder/labels match password pattern in '{text_signals}'"
            )

        # 2. Email detection
        elif input_type == "email":
            classification = FieldClassification.EMAIL
            confidence = 0.95
            is_auth_related = True
            evidence.append("HTML input type is explicitly 'email'")
        elif autocomplete == "email":
            classification = FieldClassification.EMAIL
            confidence = 0.92
            is_auth_related = True
            evidence.append("Autocomplete attribute specifies 'email'")
        elif RE_EMAIL.search(text_signals):
            classification = FieldClassification.EMAIL
            confidence = 0.85
            is_auth_related = True
            evidence.append(
                f"Field name/id/placeholder/labels match email pattern in '{text_signals}'"
            )

        # 3. Username detection
        elif autocomplete == "username":
            classification = FieldClassification.USERNAME
            confidence = 0.95
            is_auth_related = True
            evidence.append("Autocomplete attribute specifies 'username'")
        elif RE_USERNAME.search(text_signals):
            classification = FieldClassification.USERNAME
            confidence = 0.88
            is_auth_related = True
            evidence.append(
                f"Field name/id/placeholder/labels match username pattern in '{text_signals}'"
            )

        # 4. OTP / Verification Code detection
        elif autocomplete == "one-time-code":
            classification = FieldClassification.OTP
            confidence = 0.95
            is_auth_related = True
            evidence.append("Autocomplete attribute specifies 'one-time-code'")
        elif RE_OTP.search(text_signals):
            classification = FieldClassification.OTP
            confidence = 0.85
            is_auth_related = True
            evidence.append(
                f"Field name/id/placeholder/labels match OTP pattern in '{text_signals}'"
            )

        # 5. CSRF / Anti-Automation token detection
        elif raw_input.is_hidden and (
            RE_CSRF.search(name) or RE_CSRF.search(id_attr) or RE_CSRF.search(spaced_signals)
        ):
            classification = FieldClassification.CSRF_TOKEN
            confidence = 0.90
            is_auth_related = True
            evidence.append(
                f"Hidden input name/id matches anti-CSRF token pattern: '{name or id_attr}'"
            )

        # 6. Generic Hidden Input
        elif raw_input.is_hidden:
            classification = FieldClassification.HIDDEN
            confidence = 0.85
            is_auth_related = False
            evidence.append("Input is hidden from user interface")

        # 7. Submit / Button
        elif input_type in {"submit", "button"} or raw_input.element_type == "button":
            classification = FieldClassification.SUBMIT
            confidence = 0.90
            is_auth_related = False
            evidence.append(f"Element is an action/submission control ({input_type})")

        # 8. Generic / Search / Text
        elif input_type == "search" or RE_SEARCH.search(text_signals):
            classification = FieldClassification.GENERIC_INPUT
            confidence = 0.80
            is_auth_related = False
            evidence.append(f"Control matches generic/search pattern: '{text_signals}'")
        else:
            classification = FieldClassification.GENERIC_INPUT
            confidence = 0.60
            is_auth_related = False
            evidence.append(f"Standard form control of type '{input_type}'")

        return InputField(
            name=raw_input.name,
            input_type=input_type,
            element_type=raw_input.element_type,
            form_id=raw_input.form_id,
            id_attr=raw_input.id_attr,
            autocomplete=raw_input.autocomplete,
            placeholder=raw_input.placeholder,
            required=raw_input.required,
            is_hidden=raw_input.is_hidden,
            is_auth_related=is_auth_related,
            classification=classification,
            confidence=confidence,
            evidence=evidence,
        )

    def classify_form(
        self,
        raw_form: ParsedForm,
        page_url: str,
    ) -> DiscoveredForm:
        """Classify a parsed form to determine whether it is a login candidate."""
        evidence: list[str] = []
        controls = [self.classify_control(c) for c in raw_form.controls]

        # Analyze controls in the form
        password_controls = [
            c for c in controls if c.classification == FieldClassification.PASSWORD
        ]
        username_controls = [
            c
            for c in controls
            if c.classification in {FieldClassification.USERNAME, FieldClassification.EMAIL}
        ]
        csrf_controls = [c for c in controls if c.classification == FieldClassification.CSRF_TOKEN]
        interactive_controls = [
            c
            for c in controls
            if not c.is_hidden and c.classification != FieldClassification.SUBMIT
        ]

        # Check action URL, form ID, and attributes for login keywords
        form_text_signals = f"{raw_form.form_id} {raw_form.declared_action or ''} {raw_form.attributes.get('class', '')} {raw_form.attributes.get('name', '')}"
        action_match = RE_LOGIN_ACTION.search(raw_form.resolved_action) or RE_LOGIN_ACTION.search(
            form_text_signals
        )
        reg_match = RE_REGISTRATION.search(form_text_signals)

        # Check submit button texts/values
        submit_controls = [c for c in raw_form.controls if c.input_type in {"submit", "button"}]
        submit_auth_signal = any(
            RE_LOGIN_ACTION.search(c.attributes.get("value", ""))
            or RE_LOGIN_ACTION.search(c.attributes.get("text", ""))
            or any(RE_LOGIN_ACTION.search(lbl) for lbl in c.labels)
            for c in submit_controls
        )

        score = 0.0

        if password_controls:
            score += 0.50
            evidence.append(f"Contains {len(password_controls)} password input field(s)")

        if username_controls:
            score += 0.30
            evidence.append(f"Contains {len(username_controls)} username/email input field(s)")

        if csrf_controls:
            score += 0.10
            evidence.append(f"Contains {len(csrf_controls)} CSRF/authenticity token field(s)")

        if action_match:
            score += 0.20
            evidence.append(
                f"Action or form attributes contain authentication keyword: '{action_match.group(0)}'"
            )

        if submit_auth_signal:
            score += 0.10
            evidence.append("Submit control text/value contains authentication keyword")

        # Penalties for registration or search forms
        if reg_match:
            score -= 0.35
            evidence.append(
                f"Form attributes suggest registration/signup flow: '{reg_match.group(0)}'"
            )

        if len(interactive_controls) > 5:
            # Typical login forms have 1-3 interactive fields (user, pass, opt remember-me/otp)
            score -= 0.20
            evidence.append(
                f"Form contains excessive interactive fields ({len(interactive_controls)}), atypical for a standard login form"
            )

        # Determine if login candidate
        # A login form requires at least a password field or explicit auth action with credential fields
        is_login_candidate = False
        final_confidence = max(0.0, min(1.0, score))

        if password_controls and (
            username_controls or action_match or len(interactive_controls) <= 2
        ):
            is_login_candidate = True
        elif username_controls and action_match and len(interactive_controls) <= 2:
            # Passwordless / magic link login candidate
            is_login_candidate = True
            evidence.append("Identified as potential passwordless/identifier-first login form")

        # Check origin equality (same origin check)
        is_same_origin = self._check_same_origin(page_url, raw_form.resolved_action)
        if not is_same_origin:
            evidence.append(f"Form action is cross-origin ({raw_form.resolved_action})")

        return DiscoveredForm(
            form_id=raw_form.form_id,
            declared_action=raw_form.declared_action,
            resolved_action=raw_form.resolved_action,
            method=raw_form.method,
            enctype=raw_form.enctype,
            attributes=raw_form.attributes,
            controls=controls,
            query_params=raw_form.query_params,
            duplicate_field_names=raw_form.duplicate_field_names,
            is_same_origin=is_same_origin,
            is_action_in_scope=True,  # Will be evaluated against ScopeManager in Engine
            is_login_candidate=is_login_candidate,
            confidence=round(final_confidence, 2),
            evidence=evidence,
        )

    def classify_page(
        self,
        forms: list[DiscoveredForm],
        orphan_inputs: list[InputField],
        page_url: str,
    ) -> tuple[PageClassification, list[str]]:
        """Classify the entire page based on discovered forms and inputs."""
        page_evidence: list[str] = []
        login_forms = [f for f in forms if f.is_login_candidate]

        # URL path signal
        parsed_url = urlparse(page_url)
        url_has_login = bool(RE_LOGIN_ACTION.search(parsed_url.path))
        if url_has_login:
            page_evidence.append(f"URL path '{parsed_url.path}' contains authentication keyword")

        if len(login_forms) == 1:
            page_classification = PageClassification.LOGIN_FORM_DETECTED
            page_evidence.append(
                f"Single authoritative login form detected: '{login_forms[0].form_id}'"
            )
        elif len(login_forms) > 1:
            page_classification = PageClassification.MULTIPLE_LOGIN_FORMS
            form_ids = ", ".join(f"'{f.form_id}'" for f in login_forms)
            page_evidence.append(
                f"Multiple candidate login forms detected ({len(login_forms)}): {form_ids}"
            )
        else:
            # Check orphan inputs outside any form
            orphan_passwords = [
                i for i in orphan_inputs if i.classification == FieldClassification.PASSWORD
            ]
            orphan_users = [
                i
                for i in orphan_inputs
                if i.classification in {FieldClassification.USERNAME, FieldClassification.EMAIL}
            ]

            if orphan_passwords and orphan_users:
                page_classification = PageClassification.LOGIN_INPUTS_WITHOUT_FORM
                page_evidence.append(
                    "Identified authentication input controls outside any formal HTML <form> element"
                )
            else:
                page_classification = PageClassification.NO_LOGIN_FORM_DETECTED
                page_evidence.append(
                    "No authentication forms or credential input pairs were detected on page"
                )

        return page_classification, page_evidence

    @staticmethod
    def _check_same_origin(url_a: str, url_b: str) -> bool:
        """Check if two URLs share the exact same scheme, host, and port."""
        try:
            p_a = urlparse(url_a)
            p_b = urlparse(url_b)

            scheme_a = (p_a.scheme or "http").lower()
            scheme_b = (p_b.scheme or "http").lower()
            if scheme_a != scheme_b:
                return False

            host_a = (p_a.hostname or "").lower()
            host_b = (p_b.hostname or "").lower()
            if host_a != host_b:
                return False

            port_a = p_a.port or (443 if scheme_a == "https" else 80)
            port_b = p_b.port or (443 if scheme_b == "https" else 80)
            return port_a == port_b
        except Exception:
            return False
