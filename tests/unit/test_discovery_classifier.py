"""Unit tests for DiscoveryClassifier rule-based heuristics."""

from dbshield.discovery.classifier import DiscoveryClassifier
from dbshield.discovery.parser import ParsedForm, ParsedInput
from dbshield.models.discovery import (
    FieldClassification,
    PageClassification,
)


def test_classify_password_controls() -> None:
    classifier = DiscoveryClassifier()

    # Explicit input_type="password"
    c1 = classifier.classify_control(
        ParsedInput(name="p", input_type="password", element_type="input")
    )
    assert c1.classification == FieldClassification.PASSWORD
    assert c1.confidence >= 0.95
    assert c1.is_auth_related is True

    # Autocomplete="current-password"
    c2 = classifier.classify_control(
        ParsedInput(
            name="secret_val",
            input_type="text",
            element_type="input",
            autocomplete="current-password",
        )
    )
    assert c2.classification == FieldClassification.PASSWORD
    assert c2.is_auth_related is True

    # Name matching password regex
    c3 = classifier.classify_control(
        ParsedInput(name="user_passwd", input_type="text", element_type="input")
    )
    assert c3.classification == FieldClassification.PASSWORD
    assert c3.is_auth_related is True


def test_classify_email_and_username_controls() -> None:
    classifier = DiscoveryClassifier()

    # Email by type
    email_ctrl = classifier.classify_control(
        ParsedInput(name="contact", input_type="email", element_type="input")
    )
    assert email_ctrl.classification == FieldClassification.EMAIL
    assert email_ctrl.is_auth_related is True

    # Username by autocomplete
    user_ctrl1 = classifier.classify_control(
        ParsedInput(
            name="account",
            input_type="text",
            element_type="input",
            autocomplete="username",
        )
    )
    assert user_ctrl1.classification == FieldClassification.USERNAME
    assert user_ctrl1.is_auth_related is True

    # Username by name attribute
    user_ctrl2 = classifier.classify_control(
        ParsedInput(name="login_id", input_type="text", element_type="input")
    )
    assert user_ctrl2.classification == FieldClassification.USERNAME
    assert user_ctrl2.is_auth_related is True


def test_classify_otp_controls() -> None:
    classifier = DiscoveryClassifier()

    otp1 = classifier.classify_control(
        ParsedInput(
            name="code",
            input_type="text",
            element_type="input",
            autocomplete="one-time-code",
        )
    )
    assert otp1.classification == FieldClassification.OTP
    assert otp1.is_auth_related is True

    otp2 = classifier.classify_control(
        ParsedInput(name="2fa_token", input_type="text", element_type="input")
    )
    assert otp2.classification == FieldClassification.OTP
    assert otp2.is_auth_related is True


def test_classify_csrf_and_generic_hidden_inputs() -> None:
    classifier = DiscoveryClassifier()

    # Hidden CSRF token
    csrf = classifier.classify_control(
        ParsedInput(
            name="authenticity_token",
            input_type="hidden",
            element_type="input",
            is_hidden=True,
        )
    )
    assert csrf.classification == FieldClassification.CSRF_TOKEN
    assert csrf.is_auth_related is True

    # Non-CSRF hidden input
    generic_hidden = classifier.classify_control(
        ParsedInput(
            name="viewport_width",
            input_type="hidden",
            element_type="input",
            is_hidden=True,
        )
    )
    assert generic_hidden.classification == FieldClassification.HIDDEN
    assert generic_hidden.is_auth_related is False


def test_classify_login_form_vs_search_form() -> None:
    classifier = DiscoveryClassifier()

    # Form 1: Classic login form
    login_parsed = ParsedForm(
        form_id="login-form",
        declared_action="/api/auth",
        resolved_action="https://example.com/api/auth",
        method="POST",
        enctype="application/x-www-form-urlencoded",
        controls=[
            ParsedInput(name="username", input_type="text", element_type="input"),
            ParsedInput(name="password", input_type="password", element_type="input"),
            ParsedInput(name="submit", input_type="submit", element_type="button"),
        ],
    )
    form_result = classifier.classify_form(login_parsed, page_url="https://example.com/login")
    assert form_result.is_login_candidate is True
    assert form_result.confidence >= 0.80
    assert form_result.is_same_origin is True

    # Form 2: Search form
    search_parsed = ParsedForm(
        form_id="search-form",
        declared_action="/search",
        resolved_action="https://example.com/search",
        method="GET",
        enctype="application/x-www-form-urlencoded",
        controls=[
            ParsedInput(name="q", input_type="search", element_type="input"),
            ParsedInput(name="go", input_type="submit", element_type="button"),
        ],
    )
    search_result = classifier.classify_form(search_parsed, page_url="https://example.com/")
    assert search_result.is_login_candidate is False


def test_classify_page_single_and_multiple_login_forms() -> None:
    classifier = DiscoveryClassifier()

    login_form = classifier.classify_form(
        ParsedForm(
            form_id="form_1",
            declared_action="/login",
            resolved_action="https://example.com/login",
            method="POST",
            enctype="application/x-www-form-urlencoded",
            controls=[
                ParsedInput(name="user", input_type="text", element_type="input"),
                ParsedInput(name="pass", input_type="password", element_type="input"),
            ],
        ),
        page_url="https://example.com/login",
    )

    # 1. Single login form
    cls_single, ev_single = classifier.classify_page(
        forms=[login_form], orphan_inputs=[], page_url="https://example.com/login"
    )
    assert cls_single == PageClassification.LOGIN_FORM_DETECTED
    assert any("Single authoritative login form" in ev for ev in ev_single)

    # 2. Multiple login forms
    cls_multi, _ = classifier.classify_page(
        forms=[login_form, login_form], orphan_inputs=[], page_url="https://example.com/login"
    )
    assert cls_multi == PageClassification.MULTIPLE_LOGIN_FORMS

    # 3. No forms at all
    cls_none, _ = classifier.classify_page(
        forms=[], orphan_inputs=[], page_url="https://example.com/"
    )
    assert cls_none == PageClassification.NO_LOGIN_FORM_DETECTED


def test_classify_page_formless_inputs() -> None:
    classifier = DiscoveryClassifier()

    orphans = [
        classifier.classify_control(
            ParsedInput(name="email", input_type="email", element_type="input")
        ),
        classifier.classify_control(
            ParsedInput(name="password", input_type="password", element_type="input")
        ),
    ]

    classification, evidence = classifier.classify_page(
        forms=[], orphan_inputs=orphans, page_url="https://example.com/spa-login"
    )
    assert classification == PageClassification.LOGIN_INPUTS_WITHOUT_FORM
    assert any("outside any formal HTML <form>" in ev for ev in evidence)


def test_same_origin_and_cross_origin_detection() -> None:
    classifier = DiscoveryClassifier()

    # Same origin
    form_same = classifier.classify_form(
        ParsedForm(
            form_id="f1",
            declared_action="/login",
            resolved_action="https://example.com/login",
            method="POST",
            enctype="application/x-www-form-urlencoded",
        ),
        page_url="https://example.com/landing",
    )
    assert form_same.is_same_origin is True

    # Cross origin (different host)
    form_cross = classifier.classify_form(
        ParsedForm(
            form_id="f2",
            declared_action="https://auth.thirdparty.com/login",
            resolved_action="https://auth.thirdparty.com/login",
            method="POST",
            enctype="application/x-www-form-urlencoded",
        ),
        page_url="https://example.com/landing",
    )
    assert form_cross.is_same_origin is False
    assert any("cross-origin" in ev for ev in form_cross.evidence)
