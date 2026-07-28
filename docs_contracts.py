"""Bounded Google Docs text contracts shared by adapters and task brokers."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass, field


GOOGLE_DOCS_MIME_TYPE = "application/vnd.google-apps.document"
MAX_DOCS_TITLE_CHARS = 256
MAX_DOCS_BODY_CHARS = 16 * 1024
MAX_DOCS_BODY_BYTES = 64 * 1024
MAX_DOCS_TABS = 32
MAX_DOCS_PARAGRAPHS = 1_024
MAX_DOCS_STRUCTURAL_ELEMENTS = 2_048
MAX_DOCS_RESPONSE_BYTES = 1024 * 1024
MAX_DOCS_PROVIDER_REQUESTS = 6
MAX_DOCS_PROVIDER_EVIDENCE_BYTES = (
    MAX_DOCS_PROVIDER_REQUESTS * MAX_DOCS_RESPONSE_BYTES
    + MAX_DOCS_PROVIDER_REQUESTS
    - 1
)
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_TAB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
_IDEMPOTENCY_KEY = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"
)
_NAMED_STYLE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOCUMENT_KEYS = frozenset(
    {
        "body",
        "comments",
        "commentsViewMode",
        "documentFormat",
        "documentId",
        "documentStyle",
        "footers",
        "footnotes",
        "headers",
        "inlineObjects",
        "lists",
        "namedRanges",
        "namedStyles",
        "positionedObjects",
        "revisionId",
        "suggestedDocumentStyleChanges",
        "suggestedNamedStylesChanges",
        "suggestions",
        "suggestionsViewMode",
        "tabs",
        "title",
    }
)
_TAB_KEYS = frozenset({"childTabs", "documentTab", "tabProperties"})
_TAB_PROPERTY_KEYS = frozenset(
    {
        "iconEmoji",
        "index",
        "nestingLevel",
        "parentTabId",
        "tabId",
        "title",
    }
)
_DOCUMENT_TAB_KEYS = frozenset(
    {
        "body",
        "documentStyle",
        "footers",
        "footnotes",
        "headers",
        "inlineObjects",
        "lists",
        "namedRanges",
        "namedStyles",
        "positionedObjects",
        "suggestedDocumentStyleChanges",
        "suggestedNamedStylesChanges",
    }
)
_STRUCTURAL_KEYS = frozenset(
    {
        "endIndex",
        "paragraph",
        "sectionBreak",
        "startIndex",
        "table",
        "tableOfContents",
    }
)
_PARAGRAPH_KEYS = frozenset(
    {
        "bullet",
        "elements",
        "paragraphStyle",
        "positionedObjectIds",
        "suggestedBulletChanges",
        "suggestedParagraphStyleChanges",
        "suggestedPositionedObjectIds",
    }
)
_PARAGRAPH_ELEMENT_KEYS = frozenset(
    {
        "autoText",
        "columnBreak",
        "dateElement",
        "endIndex",
        "equation",
        "footnoteReference",
        "horizontalRule",
        "inlineObjectElement",
        "pageBreak",
        "person",
        "richLink",
        "startIndex",
        "textRun",
    }
)
_TEXT_RUN_KEYS = frozenset(
    {"content", "suggestedTextStyleChanges", "textStyle"}
)


class GoogleDocsUnsupportedStructureError(ValueError):
    """The document contains structure intentionally omitted from v1."""


def validate_docs_title(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or len(value) > MAX_DOCS_TITLE_CHARS
        or "\r" in value
        or "\n" in value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Google Docs title is invalid")
    return value


def validate_docs_body(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.strip()
        or len(value) > MAX_DOCS_BODY_CHARS
        or "\r" in value
        or any(
            (
                ord(character) < 32
                and character not in {"\n", "\t"}
            )
            or 0xE000 <= ord(character) <= 0xF8FF
            for character in value
        )
    ):
        raise ValueError("Google Docs body is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Google Docs body encoding is invalid") from exc
    if len(encoded) > MAX_DOCS_BODY_BYTES:
        raise ValueError("Google Docs body exceeds its byte limit")
    return value


def validate_docs_idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or _IDEMPOTENCY_KEY.fullmatch(value) is None
    ):
        raise ValueError("Google Docs idempotency key is invalid")
    return value


def validate_docs_document_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or _PROVIDER_ID.fullmatch(value) is None
    ):
        raise ValueError("Google Docs document ID is invalid")
    return value


@dataclass(frozen=True, slots=True)
class GoogleDocsParagraph:
    text: str = field(repr=False)
    named_style_type: str | None
    bullet: bool

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or "\x00" in self.text:
            raise ValueError("Google Docs paragraph text is invalid")
        try:
            encoded = self.text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(
                "Google Docs paragraph encoding is invalid"
            ) from exc
        if len(encoded) > MAX_DOCS_BODY_BYTES:
            raise ValueError("Google Docs paragraph exceeds its limit")
        if self.named_style_type is not None and (
            not isinstance(self.named_style_type, str)
            or _NAMED_STYLE.fullmatch(self.named_style_type) is None
        ):
            raise ValueError("Google Docs paragraph style is invalid")
        if type(self.bullet) is not bool:
            raise TypeError("Google Docs paragraph bullet flag is invalid")


@dataclass(frozen=True, slots=True)
class GoogleDocsTab:
    tab_id: str
    title: str
    parent_tab_id: str | None
    paragraphs: tuple[GoogleDocsParagraph, ...]
    content_text: str = field(repr=False)
    content_sha256: str

    def __post_init__(self) -> None:
        if _TAB_ID.fullmatch(self.tab_id) is None:
            raise ValueError("Google Docs tab ID is invalid")
        validate_docs_title(self.title)
        if self.parent_tab_id is not None:
            if _TAB_ID.fullmatch(self.parent_tab_id) is None:
                raise ValueError("Google Docs parent tab ID is invalid")
        if (
            not isinstance(self.paragraphs, tuple)
            or len(self.paragraphs) > MAX_DOCS_PARAGRAPHS
            or any(
                not isinstance(item, GoogleDocsParagraph)
                for item in self.paragraphs
            )
        ):
            raise ValueError("Google Docs tab paragraphs are invalid")
        if not isinstance(self.content_text, str):
            raise TypeError("Google Docs tab content is invalid")
        try:
            encoded = self.content_text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("Google Docs tab encoding is invalid") from exc
        if len(encoded) > MAX_DOCS_BODY_BYTES:
            raise ValueError("Google Docs tab content exceeds its limit")
        if (
            not isinstance(self.content_sha256, str)
            or _SHA256.fullmatch(self.content_sha256) is None
            or self.content_sha256
            != hashlib.sha256(encoded).hexdigest()
        ):
            raise ValueError("Google Docs tab digest is invalid")


@dataclass(frozen=True, slots=True)
class GoogleDocsDocument:
    document_id: str
    title: str
    tabs: tuple[GoogleDocsTab, ...]
    revision_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        validate_docs_document_id(self.document_id)
        validate_docs_title(self.title)
        if (
            not isinstance(self.tabs, tuple)
            or not self.tabs
            or len(self.tabs) > MAX_DOCS_TABS
            or any(not isinstance(item, GoogleDocsTab) for item in self.tabs)
            or len({item.tab_id for item in self.tabs}) != len(self.tabs)
            or sum(len(item.paragraphs) for item in self.tabs)
            > MAX_DOCS_PARAGRAPHS
        ):
            raise ValueError("Google Docs tabs are invalid")
        ids = {item.tab_id for item in self.tabs}
        if any(
            item.parent_tab_id is not None
            and item.parent_tab_id not in ids
            for item in self.tabs
        ):
            raise ValueError("Google Docs tab parent is invalid")
        if self.revision_id is not None and (
            not isinstance(self.revision_id, str)
            or not self.revision_id
            or len(self.revision_id) > 1_024
            or "\x00" in self.revision_id
            or not self.revision_id.isprintable()
        ):
            raise ValueError("Google Docs revision ID is invalid")

    def to_json_bytes(self) -> bytes:
        value = {
            "content_untrusted": True,
            "document_id": self.document_id,
            "tabs": [
                {
                    "content": tab.content_text,
                    "content_bytes": len(
                        tab.content_text.encode("utf-8")
                    ),
                    "content_sha256": tab.content_sha256,
                    "paragraphs": [
                        {
                            "bullet": paragraph.bullet,
                            "named_style_type": (
                                paragraph.named_style_type
                            ),
                            "text": paragraph.text,
                        }
                        for paragraph in tab.paragraphs
                    ],
                    "parent_tab_id": tab.parent_tab_id,
                    "tab_id": tab.tab_id,
                    "title": tab.title,
                }
                for tab in self.tabs
            ],
            "title": self.title,
        }
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > MAX_DOCS_RESPONSE_BYTES:
            raise ValueError("Google Docs task output exceeds its limit")
        return encoded


def parse_google_docs_document(
    body: bytes,
    *,
    expected_document_id: str,
) -> GoogleDocsDocument:
    validate_docs_document_id(expected_document_id)
    if (
        not isinstance(body, bytes)
        or not body
        or len(body) > MAX_DOCS_RESPONSE_BYTES
    ):
        raise ValueError("Google Docs response body is invalid")
    try:
        payload = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Google Docs response is not valid JSON") from exc
    if (
        not isinstance(payload, dict)
        or not {"documentId", "tabs", "title"}.issubset(payload)
        or not set(payload).issubset(_DOCUMENT_KEYS)
        or payload.get("documentId") != expected_document_id
    ):
        raise ValueError("Google Docs document identity is invalid")
    for unsupported in (
        "body",
        "comments",
        "footers",
        "footnotes",
        "headers",
        "inlineObjects",
        "namedRanges",
        "positionedObjects",
        "suggestedDocumentStyleChanges",
        "suggestedNamedStylesChanges",
        "suggestions",
    ):
        if payload.get(unsupported):
            raise GoogleDocsUnsupportedStructureError(
                "Google Docs response contains unsupported structure"
            )
    raw_tabs = payload["tabs"]
    if not isinstance(raw_tabs, list) or not raw_tabs:
        raise ValueError("Google Docs tabs are invalid")
    tabs: list[GoogleDocsTab] = []
    paragraph_count = [0]
    for raw_tab in raw_tabs:
        _parse_tab(
            raw_tab,
            expected_parent_id=None,
            output=tabs,
            paragraph_count=paragraph_count,
        )
    return GoogleDocsDocument(
        document_id=expected_document_id,
        title=validate_docs_title(payload["title"]),
        tabs=tuple(tabs),
        revision_id=_revision_id(payload.get("revisionId")),
    )


def verified_google_docs_url(value: object, document_id: str) -> str:
    validate_docs_document_id(document_id)
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("Google Docs URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    escaped_id = re.escape(document_id)
    path_pattern = re.compile(
        rf"^/(?:a/[A-Za-z0-9.-]+/)?document/d/{escaped_id}/edit$"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc != "docs.google.com"
        or path_pattern.fullmatch(parsed.path) is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
        or parsed.query not in {"", "usp=drivesdk"}
    ):
        raise ValueError("Google Docs URL is invalid")
    return value


def _parse_tab(
    value: object,
    *,
    expected_parent_id: str | None,
    output: list[GoogleDocsTab],
    paragraph_count: list[int],
) -> None:
    if (
        not isinstance(value, dict)
        or not {"documentTab", "tabProperties"}.issubset(value)
        or not set(value).issubset(_TAB_KEYS)
        or len(output) >= MAX_DOCS_TABS
    ):
        raise ValueError("Google Docs tab shape is invalid")
    properties = value["tabProperties"]
    if (
        not isinstance(properties, dict)
        or not {"tabId", "title"}.issubset(properties)
        or not set(properties).issubset(_TAB_PROPERTY_KEYS)
    ):
        raise ValueError("Google Docs tab properties are invalid")
    tab_id = properties["tabId"]
    if not isinstance(tab_id, str) or _TAB_ID.fullmatch(tab_id) is None:
        raise ValueError("Google Docs tab ID is invalid")
    parent_id = properties.get("parentTabId")
    if parent_id is not None:
        if (
            not isinstance(parent_id, str)
            or _TAB_ID.fullmatch(parent_id) is None
        ):
            raise ValueError("Google Docs parent tab ID is invalid")
    if parent_id != expected_parent_id:
        raise ValueError("Google Docs tab hierarchy is invalid")
    paragraphs, content_text = _parse_document_tab(
        value["documentTab"],
        paragraph_count,
    )
    output.append(
        GoogleDocsTab(
            tab_id=tab_id,
            title=validate_docs_title(properties["title"]),
            parent_tab_id=parent_id,
            paragraphs=paragraphs,
            content_text=content_text,
            content_sha256=hashlib.sha256(
                content_text.encode("utf-8")
            ).hexdigest(),
        )
    )
    children = value.get("childTabs", [])
    if not isinstance(children, list):
        raise ValueError("Google Docs child tabs are invalid")
    for child in children:
        _parse_tab(
            child,
            expected_parent_id=tab_id,
            output=output,
            paragraph_count=paragraph_count,
        )


def _parse_document_tab(
    value: object,
    paragraph_count: list[int],
) -> tuple[tuple[GoogleDocsParagraph, ...], str]:
    if (
        not isinstance(value, dict)
        or "body" not in value
        or not set(value).issubset(_DOCUMENT_TAB_KEYS)
    ):
        raise ValueError("Google Docs document tab is invalid")
    for unsupported in (
        "footers",
        "footnotes",
        "headers",
        "inlineObjects",
        "namedRanges",
        "positionedObjects",
        "suggestedDocumentStyleChanges",
        "suggestedNamedStylesChanges",
    ):
        if value.get(unsupported):
            raise GoogleDocsUnsupportedStructureError(
                "Google Docs tab contains unsupported structure"
            )
    body = value["body"]
    if not isinstance(body, dict) or set(body) != {"content"}:
        raise ValueError("Google Docs tab body is invalid")
    elements = body["content"]
    if (
        not isinstance(elements, list)
        or len(elements) > MAX_DOCS_STRUCTURAL_ELEMENTS
    ):
        raise ValueError("Google Docs structural elements are invalid")
    paragraphs: list[GoogleDocsParagraph] = []
    raw_text: list[str] = []
    for element in elements:
        if (
            not isinstance(element, dict)
            or not set(element).issubset(_STRUCTURAL_KEYS)
            or type(element.get("startIndex")) is not int
            or type(element.get("endIndex")) is not int
            or element["startIndex"] < 0
            or element["endIndex"] <= element["startIndex"]
        ):
            raise ValueError("Google Docs structural element is invalid")
        if element.get("table") is not None or element.get(
            "tableOfContents"
        ) is not None:
            raise GoogleDocsUnsupportedStructureError(
                "Google Docs tables are not supported in the first release"
            )
        if element.get("paragraph") is not None:
            paragraph, source_text = _parse_paragraph(
                element["paragraph"]
            )
            paragraphs.append(paragraph)
            raw_text.append(source_text)
            paragraph_count[0] += 1
            if paragraph_count[0] > MAX_DOCS_PARAGRAPHS:
                raise ValueError(
                    "Google Docs paragraph count exceeds its limit"
                )
        elif element.get("sectionBreak") is None:
            raise ValueError("Google Docs structural content is invalid")
    content = "".join(raw_text)
    if content.endswith("\n"):
        content = content[:-1]
    try:
        encoded = content.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Google Docs content encoding is invalid") from exc
    if len(encoded) > MAX_DOCS_BODY_BYTES:
        raise ValueError("Google Docs content exceeds its limit")
    return tuple(paragraphs), content


def _parse_paragraph(
    value: object,
) -> tuple[GoogleDocsParagraph, str]:
    if (
        not isinstance(value, dict)
        or "elements" not in value
        or not set(value).issubset(_PARAGRAPH_KEYS)
        or value.get("positionedObjectIds")
        or value.get("suggestedBulletChanges")
        or value.get("suggestedParagraphStyleChanges")
        or value.get("suggestedPositionedObjectIds")
    ):
        raise GoogleDocsUnsupportedStructureError(
            "Google Docs paragraph contains unsupported structure"
        )
    elements = value["elements"]
    if not isinstance(elements, list) or len(elements) > 4_096:
        raise ValueError("Google Docs paragraph elements are invalid")
    source_text: list[str] = []
    for element in elements:
        if (
            not isinstance(element, dict)
            or not set(element).issubset(_PARAGRAPH_ELEMENT_KEYS)
            or type(element.get("startIndex")) is not int
            or type(element.get("endIndex")) is not int
            or element["startIndex"] < 0
            or element["endIndex"] <= element["startIndex"]
            or "textRun" not in element
        ):
            raise GoogleDocsUnsupportedStructureError(
                "Google Docs paragraph element is not plain text"
            )
        text_run = element["textRun"]
        if (
            not isinstance(text_run, dict)
            or "content" not in text_run
            or not set(text_run).issubset(_TEXT_RUN_KEYS)
            or text_run.get("suggestedTextStyleChanges")
            or not isinstance(text_run["content"], str)
            or "\x00" in text_run["content"]
        ):
            raise GoogleDocsUnsupportedStructureError(
                "Google Docs text run is invalid or suggested"
            )
        source_text.append(text_run["content"])
    raw = "".join(source_text)
    text = raw[:-1] if raw.endswith("\n") else raw
    style = value.get("paragraphStyle", {})
    if not isinstance(style, dict):
        raise ValueError("Google Docs paragraph style is invalid")
    named_style = style.get("namedStyleType")
    if named_style is not None and (
        not isinstance(named_style, str)
        or _NAMED_STYLE.fullmatch(named_style) is None
    ):
        raise ValueError("Google Docs named style is invalid")
    bullet = value.get("bullet")
    if bullet is not None and not isinstance(bullet, dict):
        raise ValueError("Google Docs bullet structure is invalid")
    return (
        GoogleDocsParagraph(
            text=text,
            named_style_type=named_style,
            bullet=bullet is not None,
        ),
        raw,
    )


def _revision_id(value: object) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Google Docs revision ID is invalid")
    return value


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate Google Docs JSON field")
        output[key] = value
    return output


def _reject_json_constant(_value: str):
    raise ValueError("Google Docs JSON constants are invalid")


__all__ = [
    "GOOGLE_DOCS_MIME_TYPE",
    "GoogleDocsDocument",
    "GoogleDocsParagraph",
    "GoogleDocsTab",
    "GoogleDocsUnsupportedStructureError",
    "MAX_DOCS_BODY_BYTES",
    "MAX_DOCS_BODY_CHARS",
    "MAX_DOCS_PROVIDER_EVIDENCE_BYTES",
    "MAX_DOCS_PROVIDER_REQUESTS",
    "MAX_DOCS_RESPONSE_BYTES",
    "MAX_DOCS_TITLE_CHARS",
    "parse_google_docs_document",
    "validate_docs_body",
    "validate_docs_document_id",
    "validate_docs_idempotency_key",
    "validate_docs_title",
    "verified_google_docs_url",
]
