"""HTML form and control extraction module for DBShield Phase 2.

Performs robust, tolerant parsing of HTML documents to identify forms, actions,
methods, encoding types, input controls, and query parameters.
Decoupled strictly from classification heuristics.
"""

import logging
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup, Tag

logger = logging.getLogger("dbshield.discovery.parser")

DEFAULT_FORM_ENCTYPE = "application/x-www-form-urlencoded"
VALID_HTTP_METHODS = {"GET", "POST"}


@dataclass
class ParsedInput:
    """Raw parsed HTML input control before classification."""

    name: str | None
    input_type: str
    element_type: str
    form_id: str | None = None
    id_attr: str | None = None
    autocomplete: str | None = None
    placeholder: str | None = None
    required: bool = False
    is_hidden: bool = False
    attributes: dict[str, str] = field(default_factory=dict)
    labels: list[str] = field(default_factory=list)


@dataclass
class ParsedForm:
    """Raw parsed HTML form before classification."""

    form_id: str
    declared_action: str | None
    resolved_action: str
    method: str
    enctype: str
    attributes: dict[str, str] = field(default_factory=dict)
    controls: list[ParsedInput] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    duplicate_field_names: list[str] = field(default_factory=list)


@dataclass
class ParsedPage:
    """Complete structural extraction of a page's HTML."""

    title: str | None
    forms: list[ParsedForm] = field(default_factory=list)
    orphan_inputs: list[ParsedInput] = field(default_factory=list)
    page_query_params: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class HTMLFormParser:
    """Tolerant HTML form parser using BeautifulSoup with html.parser."""

    def __init__(self) -> None:
        pass

    def parse(self, html_content: str, base_url: str) -> ParsedPage:
        """Parse HTML content and extract forms, controls, and parameters.

        Args:
            html_content: Raw HTML document string.
            base_url: Effective URL of the page (used for relative action resolution).

        Returns:
            ParsedPage with extracted forms, controls, query parameters, and warnings.
        """
        warnings: list[str] = []

        if not html_content or not html_content.strip():
            warnings.append("Received empty HTML content.")
            page_query_params = self._extract_query_params(base_url)
            return ParsedPage(
                title=None,
                forms=[],
                orphan_inputs=[],
                page_query_params=page_query_params,
                warnings=warnings,
            )

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as exc:
            warnings.append(f"HTML parser encountered exception during parsing: {exc}")
            soup = BeautifulSoup("", "html.parser")

        # 1. Page Title
        title: str | None = None
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            title = str(title_tag.string).strip()

        # 2. Extract Query Parameters from base_url
        page_query_params = self._extract_query_params(base_url)

        # 3. Build a lookup map of id -> label texts for fast association
        label_map = self._build_label_map(soup)

        # 4. Extract all <form> elements
        form_tags = soup.find_all("form")
        parsed_forms: list[ParsedForm] = []

        for index, form_tag in enumerate(form_tags, start=1):
            parsed_form = self._parse_form(form_tag, index, base_url, label_map, warnings)
            parsed_forms.append(parsed_form)

        # 5. Extract orphan input controls (outside any <form>)
        orphan_inputs = self._extract_orphan_inputs(soup, label_map)

        return ParsedPage(
            title=title,
            forms=parsed_forms,
            orphan_inputs=orphan_inputs,
            page_query_params=page_query_params,
            warnings=warnings,
        )

    def _parse_form(
        self,
        form_tag: Tag,
        index: int,
        base_url: str,
        label_map: dict[str, list[str]],
        warnings: list[str],
    ) -> ParsedForm:
        """Extract attributes, actions, methods, and controls from a single <form> tag."""
        # Form ID
        form_id = form_tag.get("id")
        if not form_id or not isinstance(form_id, str):
            form_name = form_tag.get("name")
            if form_name and isinstance(form_name, str):
                form_id = f"form_{form_name}"
            else:
                form_id = f"form_{index}"

        # Action resolution
        declared_action_raw = form_tag.get("action")
        declared_action: str | None = None
        if declared_action_raw is not None and isinstance(declared_action_raw, str):
            declared_action = declared_action_raw.strip()

        if not declared_action:
            # Per HTML spec: missing action defaults to the current document's URL
            resolved_action = base_url
            warnings.append(
                f"Form '{form_id}' does not declare an action attribute; defaulting to current URL '{base_url}'."
            )
        else:
            # Resolve relative URLs and strip fragments (fragments not sent in HTTP requests)
            resolved_url = urljoin(base_url, declared_action)
            clean_url, _ = urldefrag(resolved_url)
            resolved_action = clean_url

        # HTTP Method
        method_raw = form_tag.get("method")
        if method_raw and isinstance(method_raw, str):
            method = method_raw.strip().upper()
            if method not in VALID_HTTP_METHODS:
                warnings.append(
                    f"Form '{form_id}' specifies non-standard method '{method_raw}'; defaulting to GET."
                )
                method = "GET"
        else:
            method = "GET"

        # Form Encoding Type (enctype)
        enctype_raw = form_tag.get("enctype")
        if enctype_raw and isinstance(enctype_raw, str):
            enctype = enctype_raw.strip().lower()
        else:
            enctype = DEFAULT_FORM_ENCTYPE

        # Extract attributes
        attributes: dict[str, str] = {}
        for key, val in form_tag.attrs.items():
            if isinstance(val, list):
                attributes[key] = " ".join(val)
            elif isinstance(val, str):
                attributes[key] = val

        # Extract Action Query Parameters
        action_query_params = self._extract_query_params(resolved_action)

        # Extract controls inside this form
        controls: list[ParsedInput] = []
        field_name_counts: dict[str, int] = {}

        # Tags that represent interactive or data-bearing form controls
        control_tags = form_tag.find_all(["input", "textarea", "select", "button"])
        for control_tag in control_tags:
            parsed_control = self._parse_control(control_tag, form_id, label_map)
            controls.append(parsed_control)

            if parsed_control.name:
                field_name_counts[parsed_control.name] = (
                    field_name_counts.get(parsed_control.name, 0) + 1
                )

        duplicate_names = [name for name, count in field_name_counts.items() if count > 1]
        if duplicate_names:
            warnings.append(
                f"Form '{form_id}' contains duplicate control names: {', '.join(duplicate_names)}."
            )

        return ParsedForm(
            form_id=form_id,
            declared_action=declared_action,
            resolved_action=resolved_action,
            method=method,
            enctype=enctype,
            attributes=attributes,
            controls=controls,
            query_params=action_query_params,
            duplicate_field_names=duplicate_names,
        )

    @staticmethod
    def _get_str_attr(tag: Tag, attr: str) -> str | None:
        """Extract a string attribute safely from a Tag handling list or missing values."""
        val = tag.get(attr)
        if val is None:
            return None
        if isinstance(val, list):
            clean = " ".join(val).strip()
            return clean if clean else None
        clean = str(val).strip()
        return clean if clean else None

    def _parse_control(
        self,
        tag: Tag,
        form_id: str | None,
        label_map: dict[str, list[str]],
    ) -> ParsedInput:
        """Parse an individual input, textarea, select, or button tag."""
        element_type = tag.name.lower()
        id_attr = self._get_str_attr(tag, "id")
        name_attr = self._get_str_attr(tag, "name")
        placeholder = self._get_str_attr(tag, "placeholder")
        autocomplete = self._get_str_attr(tag, "autocomplete")

        # Input Type
        if element_type == "input":
            raw_type = tag.get("type", "text")
            input_type = raw_type.strip().lower() if isinstance(raw_type, str) else "text"
        elif element_type in {"textarea", "select", "button"}:
            input_type = element_type
        else:
            input_type = "text"

        required = tag.has_attr("required")
        is_hidden = (input_type == "hidden") or (tag.has_attr("hidden"))

        # Flatten attributes
        attributes: dict[str, str] = {}
        for key, val in tag.attrs.items():
            if isinstance(val, list):
                attributes[key] = " ".join(val)
            elif isinstance(val, str):
                attributes[key] = val

        # Gather associated label texts
        labels: list[str] = []
        if id_attr and id_attr in label_map:
            labels.extend(label_map[id_attr])

        # Also check if this element is wrapped inside an ancestor <label>
        parent_label = tag.find_parent("label")
        if parent_label:
            # Extract text from label excluding the control's own text
            label_text = parent_label.get_text(separator=" ", strip=True)
            if label_text and label_text not in labels:
                labels.append(label_text)

        # ARIA labels
        aria_label = tag.get("aria-label")
        if aria_label and isinstance(aria_label, str) and aria_label.strip() not in labels:
            labels.append(aria_label.strip())

        return ParsedInput(
            name=name_attr,
            input_type=input_type,
            element_type=element_type,
            form_id=form_id,
            id_attr=id_attr,
            autocomplete=autocomplete,
            placeholder=placeholder,
            required=required,
            is_hidden=is_hidden,
            attributes=attributes,
            labels=labels,
        )

    def _extract_orphan_inputs(
        self,
        soup: BeautifulSoup,
        label_map: dict[str, list[str]],
    ) -> list[ParsedInput]:
        """Find input controls that do NOT belong to any <form> tag."""
        orphans: list[ParsedInput] = []
        for tag in soup.find_all(["input", "textarea", "select"]):
            if tag.find_parent("form") is None:
                parsed_control = self._parse_control(tag, form_id=None, label_map=label_map)
                orphans.append(parsed_control)
        return orphans

    def _build_label_map(self, soup: BeautifulSoup) -> dict[str, list[str]]:
        """Map control id to list of associated label strings from <label for="...">."""
        label_map: dict[str, list[str]] = {}
        for label_tag in soup.find_all("label"):
            for_id = label_tag.get("for")
            if for_id and isinstance(for_id, str):
                text = label_tag.get_text(separator=" ", strip=True)
                if text:
                    label_map.setdefault(for_id.strip(), []).append(text)
        return label_map

    @staticmethod
    def _extract_query_params(url: str) -> list[str]:
        """Extract unique query parameter keys from a URL string."""
        if not url:
            return []
        try:
            parsed = urlparse(url)
            if not parsed.query:
                return []
            params_dict = parse_qs(parsed.query, keep_blank_values=True)
            return sorted(params_dict.keys())
        except Exception:
            return []
