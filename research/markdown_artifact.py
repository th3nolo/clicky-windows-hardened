"""Deterministic, source-complete Markdown research report artifacts.

The model supplies strict research-record JSON, never Markdown.  This module
binds every factual value to sources observed by the bounded research adapter,
escapes all model/user text, and renders one canonical UTF-8 document that a
content-aware verifier can inspect again before adoption.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from dataclasses import dataclass, field
from datetime import datetime

from research.csv_artifact import (
    ResearchCsvError,
    ResearchCsvSchema,
    parse_research_json_records,
)
from research.models import (
    MAX_RESEARCH_BYTES,
    MAX_RESEARCH_ROWS,
    ResearchBatch,
    ResearchValidationError,
    ResearchValue,
    canonicalize_public_url,
)


MAX_RESEARCH_REPORT_TITLE_CHARS = 512
MAX_RESEARCH_REPORT_SOURCES = 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_REFERENCE = re.compile(
    r"^\[(S[0-9]{3})\] <([^<>\s]+)>$"
)
_SOURCE_ENTRY = re.compile(
    r"^- \[(S[0-9]{3})\] <([^<>\s]+)>$"
)
_MARKDOWN_SAFE_URL = re.compile(
    r"^https://[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+$"
)
_ASCII_PUNCTUATION = frozenset(string.punctuation)


class ResearchMarkdownError(ValueError):
    """A report schema, render request, or Markdown artifact is invalid."""


@dataclass(frozen=True, slots=True)
class ResearchMarkdownSchema:
    """The reviewed title and stable field order for one report."""

    title: str
    requested_field_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        title = _bounded_title(self.title)
        # Reuse the already-reviewed research field vocabulary and ordering.
        ResearchCsvSchema(self.requested_field_ids)
        object.__setattr__(self, "title", title)

    @property
    def escaped_title(self) -> str:
        return _escape_markdown(self.title)

    @property
    def title_digest(self) -> str:
        return hashlib.sha256(
            self.escaped_title.encode("utf-8")
        ).hexdigest()

    @property
    def schema_digest(self) -> str:
        return _digest_json(
            {
                "format": "research-markdown-v1",
                "requested_field_ids": self.requested_field_ids,
            }
        )


@dataclass(frozen=True, slots=True)
class ResearchMarkdownArtifact:
    """Canonical report bytes plus content-free completeness metadata."""

    content: bytes = field(repr=False)
    sha256: str
    schema_digest: str
    title_digest: str
    source_digest: str
    section_count: int
    requested_sections: int
    complete: bool
    partial_reason: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= MAX_RESEARCH_BYTES
            or self.sha256 != hashlib.sha256(self.content).hexdigest()
        ):
            raise ResearchMarkdownError(
                "Research Markdown content is invalid"
            )
        for digest in (
            self.sha256,
            self.schema_digest,
            self.title_digest,
            self.source_digest,
        ):
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise ResearchMarkdownError(
                    "Research Markdown digest is invalid"
                )
        _bounded_integer(
            self.requested_sections,
            1,
            MAX_RESEARCH_ROWS,
            "Research Markdown requested section count",
        )
        _bounded_integer(
            self.section_count,
            0,
            self.requested_sections,
            "Research Markdown section count",
        )
        if type(self.complete) is not bool:
            raise TypeError(
                "Research Markdown completeness must be explicit"
            )
        if self.complete != (
            self.section_count == self.requested_sections
        ):
            raise ResearchMarkdownError(
                "Research Markdown completeness does not match sections"
            )
        expected_partial = (
            None
            if self.complete
            else (
                "requested_sections_not_reached:"
                f"{self.section_count}/{self.requested_sections}"
            )
        )
        if self.partial_reason != expected_partial:
            raise ResearchMarkdownError(
                "Research Markdown partial reason is invalid"
            )


@dataclass(frozen=True, slots=True)
class ResearchMarkdownInspection:
    """Content-free validation result for verifier evidence."""

    structurally_valid: bool
    complete: bool
    partial: bool
    section_count: int
    requested_sections: int
    citation_count: int
    content_sha256: str
    schema_digest: str
    title_digest: str
    source_digest: str
    result_code: str

    def __post_init__(self) -> None:
        for value in (
            self.structurally_valid,
            self.complete,
            self.partial,
        ):
            if type(value) is not bool:
                raise TypeError(
                    "Research Markdown inspection flags must be explicit"
                )
        _bounded_integer(
            self.requested_sections,
            1,
            MAX_RESEARCH_ROWS,
            "Research Markdown inspected requested sections",
        )
        _bounded_integer(
            self.section_count,
            0,
            MAX_RESEARCH_ROWS,
            "Research Markdown inspected sections",
        )
        if type(self.citation_count) is not int or self.citation_count < 0:
            raise ValueError(
                "Research Markdown citation count is invalid"
            )
        for digest in (
            self.content_sha256,
            self.schema_digest,
            self.title_digest,
            self.source_digest,
        ):
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise ResearchMarkdownError(
                    "Research Markdown inspection digest is invalid"
                )
        if self.result_code not in {
            "invalid_research_markdown",
            "research_markdown_complete",
            "research_markdown_section_shortfall",
        }:
            raise ResearchMarkdownError(
                "Research Markdown inspection result is invalid"
            )
        if self.complete and (
            not self.structurally_valid or self.partial
        ):
            raise ResearchMarkdownError(
                "Complete Research Markdown inspection is inconsistent"
            )
        if self.partial and (
            not self.structurally_valid
            or self.complete
            or self.section_count >= self.requested_sections
        ):
            raise ResearchMarkdownError(
                "Partial Research Markdown inspection is inconsistent"
            )


def render_research_markdown(
    batch: ResearchBatch,
    schema: ResearchMarkdownSchema,
    *,
    requested_sections: int,
) -> ResearchMarkdownArtifact:
    """Render canonical Markdown with citations on every factual value."""

    if not isinstance(batch, ResearchBatch):
        raise TypeError(
            "Research Markdown rendering requires a typed batch"
        )
    if not isinstance(schema, ResearchMarkdownSchema):
        raise TypeError(
            "Research Markdown rendering requires a typed schema"
        )
    _bounded_integer(
        requested_sections,
        1,
        min(MAX_RESEARCH_ROWS, batch.limits.max_rows),
        "Research Markdown requested section count",
    )
    if len(batch.records) > requested_sections:
        raise ResearchMarkdownError(
            "Research Markdown has more sections than requested"
        )

    sources = tuple(
        sorted(
            {
                source
                for record in batch.records
                for source in record.all_source_urls
            }
        )
    )
    if len(sources) > MAX_RESEARCH_REPORT_SOURCES:
        raise ResearchMarkdownError(
            "Research Markdown source limit exceeded"
        )
    for source in sources:
        _markdown_safe_source_url(source)
    labels = {
        source: f"S{index:03d}"
        for index, source in enumerate(sources, 1)
    }
    lines = [f"# {schema.escaped_title}", ""]
    for index, record in enumerate(batch.records, 1):
        fields = {
            item.field_id: item.value
            for item in record.requested_fields
        }
        if tuple(fields) != schema.requested_field_ids:
            raise ResearchMarkdownError(
                "Research record fields do not match report schema"
            )
        lines.extend(
            (
                f"## {index}. {_escape_markdown(record.entity.value)}",
                "",
                _claim_line("Entity", record.entity, labels),
                _claim_line("Public URL", record.public_url, labels),
            )
        )
        for field_id in schema.requested_field_ids:
            lines.append(_claim_line(field_id, fields[field_id], labels))
        lines.extend(
            (
                _claim_line("Rationale", record.rationale, labels),
                f"- **Retrieved at:** {record.retrieved_at.isoformat()}",
                "",
            )
        )
    lines.extend(("## Sources", ""))
    lines.extend(
        f"- [{labels[source]}] <{source}>"
        for source in sources
    )
    content = ("\n".join(lines) + "\n").encode("utf-8")
    maximum = min(batch.limits.max_output_bytes, MAX_RESEARCH_BYTES)
    if len(content) > maximum:
        raise ResearchMarkdownError(
            "Research Markdown output limit exceeded"
        )
    section_count = len(batch.records)
    complete = section_count == requested_sections
    return ResearchMarkdownArtifact(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        schema_digest=schema.schema_digest,
        title_digest=schema.title_digest,
        source_digest=_source_digest(sources),
        section_count=section_count,
        requested_sections=requested_sections,
        complete=complete,
        partial_reason=(
            None
            if complete
            else (
                "requested_sections_not_reached:"
                f"{section_count}/{requested_sections}"
            )
        ),
    )


def render_research_json_to_markdown(
    records_json: str,
    schema: ResearchMarkdownSchema,
    *,
    requested_sections: int,
    maximum_output_bytes: int,
    allowed_source_urls: tuple[str, ...],
    retrieved_at: datetime | None = None,
) -> ResearchMarkdownArtifact:
    """Bind strict model JSON to observed sources, then render Markdown."""

    if not isinstance(schema, ResearchMarkdownSchema):
        raise TypeError(
            "Research JSON rendering requires a typed Markdown schema"
        )
    try:
        batch = parse_research_json_records(
            records_json,
            ResearchCsvSchema(schema.requested_field_ids),
            requested_rows=requested_sections,
            maximum_output_bytes=maximum_output_bytes,
            allowed_source_urls=allowed_source_urls,
            retrieved_at=retrieved_at,
        )
    except (ResearchCsvError, ResearchValidationError) as exc:
        raise ResearchMarkdownError(
            "Research report JSON contains invalid sourced values"
        ) from exc
    return render_research_markdown(
        batch,
        schema,
        requested_sections=requested_sections,
    )


def inspect_research_markdown(
    content: bytes,
    schema: ResearchMarkdownSchema,
    *,
    requested_sections: int,
    maximum_bytes: int,
) -> ResearchMarkdownInspection:
    """Inspect canonical report bytes without exposing report text."""

    if not isinstance(content, bytes):
        raise TypeError(
            "Research Markdown inspection requires immutable bytes"
        )
    if not isinstance(schema, ResearchMarkdownSchema):
        raise TypeError(
            "Research Markdown inspection requires a typed schema"
        )
    _bounded_integer(
        requested_sections,
        1,
        MAX_RESEARCH_ROWS,
        "Research Markdown requested section count",
    )
    _bounded_integer(
        maximum_bytes,
        1,
        MAX_RESEARCH_BYTES,
        "Research Markdown verification byte limit",
    )
    digest = hashlib.sha256(content).hexdigest()
    section_count = 0
    citation_count = 0
    title_digest = hashlib.sha256(b"").hexdigest()
    source_digest = _source_digest(())
    try:
        if not content or len(content) > maximum_bytes:
            raise ResearchMarkdownError("research_markdown_size")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResearchMarkdownError(
                "research_markdown_utf8"
            ) from exc
        if (
            not text.endswith("\n")
            or "\r" in text
            or any(
                ord(character) < 32 and character != "\n"
                for character in text
            )
            or "\x7f" in text
        ):
            raise ResearchMarkdownError(
                "research_markdown_encoding"
            )
        lines = text.splitlines()
        if (
            len(lines) < 4
            or not lines[0].startswith("# ")
            or not _is_canonical_escaped_text(lines[0][2:])
            or lines[1] != ""
        ):
            raise ResearchMarkdownError(
                "research_markdown_title"
            )
        title_digest = hashlib.sha256(
            lines[0][2:].encode("utf-8")
        ).hexdigest()
        if title_digest != schema.title_digest:
            raise ResearchMarkdownError(
                "research_markdown_title_mismatch"
            )
        index = 2
        claims: list[tuple[str, str]] = []
        headings: set[str] = set()
        expected_labels = (
            "Entity",
            "Public URL",
            *schema.requested_field_ids,
            "Rationale",
        )
        while index < len(lines) and lines[index] != "## Sources":
            section_count += 1
            if section_count > requested_sections:
                raise ResearchMarkdownError(
                    "research_markdown_extra_sections"
                )
            prefix = f"## {section_count}. "
            if (
                not lines[index].startswith(prefix)
                or not _is_canonical_escaped_text(
                    lines[index][len(prefix) :]
                )
                or lines[index] in headings
            ):
                raise ResearchMarkdownError(
                    "research_markdown_heading"
                )
            headings.add(lines[index])
            index += 1
            if index >= len(lines) or lines[index] != "":
                raise ResearchMarkdownError(
                    "research_markdown_section_spacing"
                )
            index += 1
            for label in expected_labels:
                if index >= len(lines):
                    raise ResearchMarkdownError(
                        "research_markdown_claim"
                    )
                claims.extend(
                    _inspect_claim(lines[index], expected_label=label)
                )
                index += 1
            if index >= len(lines) or not lines[index].startswith(
                "- **Retrieved at:** "
            ):
                raise ResearchMarkdownError(
                    "research_markdown_retrieval_time"
                )
            timestamp = datetime.fromisoformat(
                lines[index].removeprefix("- **Retrieved at:** ")
            )
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ResearchMarkdownError(
                    "research_markdown_retrieval_time"
                )
            index += 1
            if index >= len(lines) or lines[index] != "":
                raise ResearchMarkdownError(
                    "research_markdown_section_spacing"
                )
            index += 1
        if (
            index >= len(lines)
            or lines[index] != "## Sources"
            or index + 1 >= len(lines)
            or lines[index + 1] != ""
        ):
            raise ResearchMarkdownError(
                "research_markdown_sources_heading"
            )
        index += 2
        sources: dict[str, str] = {}
        while index < len(lines):
            match = _SOURCE_ENTRY.fullmatch(lines[index])
            if match is None:
                raise ResearchMarkdownError(
                    "research_markdown_source_entry"
                )
            label, raw_url = match.groups()
            expected_label = f"S{len(sources) + 1:03d}"
            canonical = canonicalize_public_url(
                raw_url,
                require_https=True,
            )
            if (
                label != expected_label
                or canonical != raw_url
                or _MARKDOWN_SAFE_URL.fullmatch(raw_url) is None
                or label in sources
                or raw_url in sources.values()
            ):
                raise ResearchMarkdownError(
                    "research_markdown_source_entry"
                )
            sources[label] = raw_url
            index += 1
        if len(sources) > MAX_RESEARCH_REPORT_SOURCES:
            raise ResearchMarkdownError(
                "research_markdown_source_count"
            )
        if bool(section_count) != bool(sources):
            raise ResearchMarkdownError(
                "research_markdown_source_coverage"
            )
        cited_labels: set[str] = set()
        for label, url in claims:
            if sources.get(label) != url:
                raise ResearchMarkdownError(
                    "research_markdown_unknown_citation"
                )
            cited_labels.add(label)
        citation_count = len(claims)
        if cited_labels != set(sources):
            raise ResearchMarkdownError(
                "research_markdown_source_coverage"
            )
        source_digest = _source_digest(tuple(sources.values()))
    except (
        ResearchMarkdownError,
        ResearchValidationError,
        ValueError,
    ):
        return ResearchMarkdownInspection(
            structurally_valid=False,
            complete=False,
            partial=False,
            section_count=min(section_count, MAX_RESEARCH_ROWS),
            requested_sections=requested_sections,
            citation_count=citation_count,
            content_sha256=digest,
            schema_digest=schema.schema_digest,
            title_digest=title_digest,
            source_digest=source_digest,
            result_code="invalid_research_markdown",
        )

    complete = section_count == requested_sections
    return ResearchMarkdownInspection(
        structurally_valid=True,
        complete=complete,
        partial=not complete,
        section_count=section_count,
        requested_sections=requested_sections,
        citation_count=citation_count,
        content_sha256=digest,
        schema_digest=schema.schema_digest,
        title_digest=title_digest,
        source_digest=source_digest,
        result_code=(
            "research_markdown_complete"
            if complete
            else "research_markdown_section_shortfall"
        ),
    )


def _claim_line(
    label: str,
    value: ResearchValue,
    labels: dict[str, str],
) -> str:
    references = "; ".join(
        f"[{labels[source]}] <{source}>"
        for source in sorted(value.source_urls)
    )
    if not references:
        raise ResearchMarkdownError(
            "Research Markdown claim lacks source evidence"
        )
    return (
        f"- **{label}:** {_escape_markdown(value.value)}"
        f" — {references}"
    )


def _inspect_claim(
    line: str,
    *,
    expected_label: str,
) -> tuple[tuple[str, str], ...]:
    prefix = f"- **{expected_label}:** "
    if not line.startswith(prefix) or " — " not in line:
        raise ResearchMarkdownError("research_markdown_claim")
    escaped_value, raw_references = line[len(prefix) :].rsplit(" — ", 1)
    if not _is_canonical_escaped_text(escaped_value):
        raise ResearchMarkdownError("research_markdown_claim_value")
    references: list[tuple[str, str]] = []
    for item in raw_references.split("; "):
        match = _SOURCE_REFERENCE.fullmatch(item)
        if match is None:
            raise ResearchMarkdownError(
                "research_markdown_citation"
            )
        references.append(match.groups())
    if (
        not references
        or len(references) != len(set(references))
        or references != sorted(references)
    ):
        raise ResearchMarkdownError(
            "research_markdown_citation"
        )
    return tuple(references)


def _bounded_title(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > MAX_RESEARCH_REPORT_TITLE_CHARS
        or not value.isprintable()
    ):
        raise ResearchMarkdownError(
            "Research Markdown title is invalid"
        )
    return value


def _escape_markdown(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or not value.isprintable()
    ):
        raise ResearchMarkdownError(
            "Research Markdown text is invalid"
        )
    return "".join(
        f"\\{character}"
        if character in _ASCII_PUNCTUATION
        else character
        for character in value
    )


def _is_canonical_escaped_text(value: str) -> bool:
    if not value:
        return False
    decoded: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "\\":
            index += 1
            if (
                index >= len(value)
                or value[index] not in _ASCII_PUNCTUATION
            ):
                return False
            decoded.append(value[index])
        elif character in _ASCII_PUNCTUATION:
            return False
        else:
            decoded.append(character)
        index += 1
    try:
        return _escape_markdown("".join(decoded)) == value
    except ResearchMarkdownError:
        return False


def _source_digest(sources: tuple[str, ...]) -> str:
    return _digest_json({"sources": sources})


def _markdown_safe_source_url(value: str) -> str:
    canonical = canonicalize_public_url(value, require_https=True)
    if canonical != value or _MARKDOWN_SAFE_URL.fullmatch(value) is None:
        raise ResearchMarkdownError(
            "Research Markdown source URL is not safe to embed"
        )
    return value


def _digest_json(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchMarkdownError(f"{label} is invalid")


__all__ = [
    "MAX_RESEARCH_REPORT_TITLE_CHARS",
    "ResearchMarkdownArtifact",
    "ResearchMarkdownError",
    "ResearchMarkdownInspection",
    "ResearchMarkdownSchema",
    "inspect_research_markdown",
    "render_research_json_to_markdown",
    "render_research_markdown",
]
