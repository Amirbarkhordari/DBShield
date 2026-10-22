"""Unit tests for HTMLFormParser."""

from dbshield.discovery.parser import HTMLFormParser


def test_parser_basic_login_form() -> None:
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Sign In Page</title></head>
    <body>
        <form id="auth-form" action="/login" method="post" enctype="application/x-www-form-urlencoded">
            <input type="hidden" name="csrf_token" value="secret123" />
            <label for="username_input">Username</label>
            <input type="text" id="username_input" name="user" required />
            <label for="password_input">Password</label>
            <input type="password" id="password_input" name="pass" required />
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/auth")

    assert page.title == "Sign In Page"
    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.form_id == "auth-form"
    assert form.declared_action == "/login"
    assert form.resolved_action == "https://example.com/login"
    assert form.method == "POST"
    assert form.enctype == "application/x-www-form-urlencoded"
    assert len(form.controls) == 4

    # Verify CSRF control
    csrf = form.controls[0]
    assert csrf.name == "csrf_token"
    assert csrf.input_type == "hidden"
    assert csrf.is_hidden is True

    # Verify username control and label extraction
    user = form.controls[1]
    assert user.name == "user"
    assert user.id_attr == "username_input"
    assert user.required is True
    assert "Username" in user.labels

    # Verify password control
    pw = form.controls[2]
    assert pw.name == "pass"
    assert pw.input_type == "password"
    assert pw.required is True
    assert "Password" in pw.labels


def test_parser_missing_form_action_defaults_to_page_url() -> None:
    html = """
    <form method="post">
        <input type="password" name="pin" />
    </form>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/login?step=1")

    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.declared_action is None
    assert form.resolved_action == "https://example.com/login?step=1"
    assert any("defaulting to current URL" in w for w in page.warnings)


def test_parser_url_fragment_stripping_and_relative_resolution() -> None:
    html = """
    <form action="../do-login#section2" method="POST">
        <input type="text" name="u" />
    </form>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/v1/auth/page.html")

    assert len(page.forms) == 1
    form = page.forms[0]
    assert form.declared_action == "../do-login#section2"
    # Relative to /v1/auth/page.html, ../do-login resolves to /v1/do-login without fragment
    assert form.resolved_action == "https://example.com/v1/do-login"


def test_parser_query_parameters_extraction() -> None:
    html = """
    <form action="/login?ref=portal&lang=en" method="get">
        <input type="text" name="code" />
    </form>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/landing?session=active&track=1")

    assert page.page_query_params == ["session", "track"]
    assert len(page.forms) == 1
    assert page.forms[0].query_params == ["lang", "ref"]


def test_parser_duplicate_control_names() -> None:
    html = """
    <form action="/submit" method="post">
        <input type="text" name="role" value="user" />
        <input type="text" name="role" value="admin" />
    </form>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/")

    assert len(page.forms) == 1
    assert page.forms[0].duplicate_field_names == ["role"]
    assert any("duplicate control names" in w for w in page.warnings)


def test_parser_invalid_http_method_defaults_to_get() -> None:
    html = """
    <form action="/test" method="PUT">
        <input type="text" name="data" />
    </form>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/")

    assert len(page.forms) == 1
    assert page.forms[0].method == "GET"
    assert any("specifies non-standard method 'PUT'" in w for w in page.warnings)


def test_parser_orphan_inputs_outside_form() -> None:
    html = """
    <div>
        <label>Standalone Field</label>
        <input type="text" id="orphan1" name="search_bar" placeholder="Search..." />
        <textarea name="feedback"></textarea>
    </div>
    """
    parser = HTMLFormParser()
    page = parser.parse(html, base_url="https://example.com/")

    assert len(page.forms) == 0
    assert len(page.orphan_inputs) == 2
    assert page.orphan_inputs[0].name == "search_bar"
    assert page.orphan_inputs[0].element_type == "input"
    assert page.orphan_inputs[1].name == "feedback"
    assert page.orphan_inputs[1].element_type == "textarea"


def test_parser_empty_and_malformed_html() -> None:
    parser = HTMLFormParser()

    # Empty string
    empty_page = parser.parse("", base_url="https://example.com/")
    assert len(empty_page.forms) == 0
    assert any("empty HTML" in w for w in empty_page.warnings)

    # Malformed unclosed tags
    malformed_html = (
        "<form action='/test'><input name='user'><form action='/test2'><input name='pw'>"
    )
    malformed_page = parser.parse(malformed_html, base_url="https://example.com/")
    assert len(malformed_page.forms) >= 1
