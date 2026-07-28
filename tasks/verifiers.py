"""Deterministic verifier interfaces over trusted, bounded host snapshots.

These verifiers do not fetch APIs, run Git, inspect the desktop, or open files.
The authority-bearing host adapter must first produce one of the exact snapshot
types below; verification then compares only immutable metadata and digests.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum

from tasks.models import ToolCall, ToolResult, ToolResultStatus


MAX_REFERENCE_CHARS = 256
MAX_MEDIA_TYPE_CHARS = 127
MAX_PATHS = 256
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OID = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MEDIA_TYPE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/"
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$"
)


class VerificationSubjectKind(str, Enum):
    FILE = "file"
    API_RESPONSE = "api_response"
    REPOSITORY = "repository"
    UI_STATE = "ui_state"


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    verifier_id: str
    subject_kind: VerificationSubjectKind
    subject_reference: str
    subject_digest: str
    postcondition_met: bool
    result_code: str
    evidence_digest: str
    evidence_bytes: int

    def __post_init__(self) -> None:
        _reference(self.verifier_id, "Verifier ID")
        if not isinstance(self.subject_kind, VerificationSubjectKind):
            raise TypeError("Verification subject kind is invalid")
        _reference(self.subject_reference, "Verification subject reference")
        _sha256(self.subject_digest, "Verification subject digest")
        if type(self.postcondition_met) is not bool:
            raise TypeError("Verification outcome must be explicit")
        _reference(self.result_code, "Verification result code")
        _sha256(self.evidence_digest, "Verification evidence digest")
        if (
            type(self.evidence_bytes) is not int
            or not 1 <= self.evidence_bytes <= 64 * 1024
        ):
            raise ValueError("Verification evidence size is invalid")

    def to_tool_result(self, call: ToolCall) -> ToolResult:
        if not isinstance(call, ToolCall):
            raise TypeError("Verification result requires a ToolCall")
        return ToolResult(
            result_id=_result_id(call),
            call_id=call.call_id,
            run_id=call.run_id,
            step_id=call.step_id,
            status=ToolResultStatus.SUCCEEDED,
            output_digest=self.evidence_digest,
            output_bytes=self.evidence_bytes,
            verifier_id=self.verifier_id,
            postcondition_met=self.postcondition_met,
            evidence_digest=self.evidence_digest,
        )


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    artifact_id: str
    name: str
    media_type: str
    byte_count: int
    sha256: str
    provenance_digest: str
    complete: bool

    def __post_init__(self) -> None:
        _reference(self.artifact_id, "File artifact ID")
        _bounded_name(self.name)
        _media_type(self.media_type)
        _bounded_size(self.byte_count, 64 * 1024 * 1024, "File size")
        _sha256(self.sha256, "File digest")
        _sha256(self.provenance_digest, "File provenance digest")
        if type(self.complete) is not bool:
            raise TypeError("File completeness must be explicit")


@dataclass(frozen=True, slots=True)
class FileExpectation:
    expected_sha256: str | None = None
    expected_media_type: str | None = None
    minimum_bytes: int | None = None
    maximum_bytes: int | None = None
    required_utf8_substrings: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.expected_sha256 is not None:
            _sha256(self.expected_sha256, "Expected file digest")
        if self.expected_media_type is not None:
            _media_type(self.expected_media_type)
        if self.minimum_bytes is not None:
            _bounded_size(
                self.minimum_bytes,
                64 * 1024 * 1024,
                "Minimum file size",
            )
        if self.maximum_bytes is not None:
            _bounded_size(
                self.maximum_bytes,
                64 * 1024 * 1024,
                "Maximum file size",
            )
        if (
            self.minimum_bytes is not None
            and self.maximum_bytes is not None
            and self.minimum_bytes > self.maximum_bytes
        ):
            raise ValueError("File verification size range is invalid")
        _bounded_strings(
            self.required_utf8_substrings,
            maximum_items=16,
            maximum_chars=1_024,
            label="Required file substrings",
        )
        if not any(
            (
                self.expected_sha256 is not None,
                self.expected_media_type is not None,
                self.minimum_bytes is not None,
                self.maximum_bytes is not None,
                bool(self.required_utf8_substrings),
            )
        ):
            raise ValueError("File verifier requires a postcondition")


@dataclass(frozen=True, slots=True)
class ResearchCsvFileExpectation:
    """Exact file and research-table postconditions for one CSV artifact."""

    file: FileExpectation
    requested_field_ids: tuple[str, ...]
    requested_rows: int

    def __post_init__(self) -> None:
        if not isinstance(self.file, FileExpectation):
            raise TypeError(
                "Research CSV file expectation must be typed"
            )
        from research.csv_artifact import ResearchCsvSchema
        from research.models import MAX_RESEARCH_BYTES

        ResearchCsvSchema(self.requested_field_ids)
        if type(self.requested_rows) is not int or not (
            1 <= self.requested_rows <= 100
        ):
            raise ValueError(
                "Research CSV requested row count is invalid"
            )
        if (
            self.file.expected_sha256 is None
            or self.file.expected_media_type != "text/csv"
            or self.file.maximum_bytes is None
            or self.file.maximum_bytes > MAX_RESEARCH_BYTES
        ):
            raise ValueError(
                "Research CSV verification requires digest, media type, "
                "and a bounded maximum size"
            )


@dataclass(frozen=True, slots=True)
class ResearchCsvFileVerification:
    """Verifier evidence plus a content-free shortfall classification."""

    evidence: VerificationEvidence
    row_count: int
    requested_rows: int
    partial: bool

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, VerificationEvidence):
            raise TypeError(
                "Research CSV verification evidence is invalid"
            )
        if (
            type(self.row_count) is not int
            or type(self.requested_rows) is not int
            or not 0 <= self.row_count <= 100
            or not 1 <= self.requested_rows <= 100
            or type(self.partial) is not bool
        ):
            raise ValueError(
                "Research CSV verification metadata is invalid"
            )
        if self.partial and (
            self.evidence.postcondition_met
            or self.row_count >= self.requested_rows
        ):
            raise ValueError(
                "Research CSV partial verification is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class ResearchMarkdownFileExpectation:
    """Exact file and source-complete report postconditions."""

    file: FileExpectation
    report_title: str
    requested_field_ids: tuple[str, ...]
    requested_sections: int
    source_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.file, FileExpectation):
            raise TypeError(
                "Research Markdown file expectation must be typed"
            )
        from research.markdown_artifact import ResearchMarkdownSchema
        from research.models import MAX_RESEARCH_BYTES

        ResearchMarkdownSchema(
            self.report_title,
            self.requested_field_ids,
        )
        if type(self.requested_sections) is not int or not (
            1 <= self.requested_sections <= 100
        ):
            raise ValueError(
                "Research Markdown requested section count is invalid"
            )
        _sha256(
            self.source_digest,
            "Research Markdown source digest",
        )
        if (
            self.file.expected_sha256 is None
            or self.file.expected_media_type != "text/markdown"
            or self.file.maximum_bytes is None
            or self.file.maximum_bytes > MAX_RESEARCH_BYTES
        ):
            raise ValueError(
                "Research Markdown verification requires digest, media "
                "type, and a bounded maximum size"
            )


@dataclass(frozen=True, slots=True)
class ResearchMarkdownFileVerification:
    """Verifier evidence plus a content-free shortfall classification."""

    evidence: VerificationEvidence
    section_count: int
    requested_sections: int
    citation_count: int
    partial: bool

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, VerificationEvidence):
            raise TypeError(
                "Research Markdown verification evidence is invalid"
            )
        if (
            type(self.section_count) is not int
            or type(self.requested_sections) is not int
            or type(self.citation_count) is not int
            or not 0 <= self.section_count <= 100
            or not 1 <= self.requested_sections <= 100
            or self.citation_count < 0
            or type(self.partial) is not bool
        ):
            raise ValueError(
                "Research Markdown verification metadata is invalid"
            )
        if self.partial and (
            self.evidence.postcondition_met
            or self.section_count >= self.requested_sections
        ):
            raise ValueError(
                "Research Markdown partial verification is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class ResearchDocxFileExpectation:
    """Exact file, safe OOXML, and report-derived text postconditions."""

    file: FileExpectation
    report_title: str
    requested_field_ids: tuple[str, ...]
    requested_sections: int
    report_sha256: str
    document_digest: str
    source_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.file, FileExpectation):
            raise TypeError(
                "Research DOCX file expectation must be typed"
            )
        from research.docx_artifact import (
            DOCX_MEDIA_TYPE,
            MAX_RESEARCH_DOCX_BYTES,
        )
        from research.markdown_artifact import ResearchMarkdownSchema

        ResearchMarkdownSchema(
            self.report_title,
            self.requested_field_ids,
        )
        if type(self.requested_sections) is not int or not (
            1 <= self.requested_sections <= 100
        ):
            raise ValueError(
                "Research DOCX requested section count is invalid"
            )
        for value, label in (
            (self.report_sha256, "report"),
            (self.document_digest, "document"),
            (self.source_digest, "source"),
        ):
            _sha256(value, f"Research DOCX {label} digest")
        if (
            self.file.expected_sha256 is None
            or self.file.expected_media_type != DOCX_MEDIA_TYPE
            or self.file.maximum_bytes is None
            or self.file.maximum_bytes > MAX_RESEARCH_DOCX_BYTES
        ):
            raise ValueError(
                "Research DOCX verification requires digest, media type, "
                "and a bounded maximum size"
            )


@dataclass(frozen=True, slots=True)
class ResearchPdfFileExpectation:
    """Exact file, canonical PDF, and visible report text postconditions."""

    file: FileExpectation
    report_title: str
    requested_field_ids: tuple[str, ...]
    requested_sections: int
    report_sha256: str
    document_digest: str
    source_digest: str
    page_count: int

    def __post_init__(self) -> None:
        if not isinstance(self.file, FileExpectation):
            raise TypeError(
                "Research PDF file expectation must be typed"
            )
        from research.markdown_artifact import ResearchMarkdownSchema
        from research.pdf_artifact import (
            MAX_RESEARCH_PDF_BYTES,
            MAX_RESEARCH_PDF_PAGES,
            PDF_MEDIA_TYPE,
        )

        ResearchMarkdownSchema(
            self.report_title,
            self.requested_field_ids,
        )
        if type(self.requested_sections) is not int or not (
            1 <= self.requested_sections <= 100
        ):
            raise ValueError(
                "Research PDF requested section count is invalid"
            )
        for value, label in (
            (self.report_sha256, "report"),
            (self.document_digest, "document"),
            (self.source_digest, "source"),
        ):
            _sha256(value, f"Research PDF {label} digest")
        if type(self.page_count) is not int or not (
            1 <= self.page_count <= MAX_RESEARCH_PDF_PAGES
        ):
            raise ValueError(
                "Research PDF page count is invalid"
            )
        if (
            self.file.expected_sha256 is None
            or self.file.expected_media_type != PDF_MEDIA_TYPE
            or self.file.maximum_bytes is None
            or self.file.maximum_bytes > MAX_RESEARCH_PDF_BYTES
        ):
            raise ValueError(
                "Research PDF verification requires digest, media type, "
                "and a bounded maximum size"
            )


def verify_file(
    snapshot: FileSnapshot,
    expectation: FileExpectation,
    *,
    verifier_id: str,
    content: bytes,
) -> VerificationEvidence:
    if not isinstance(snapshot, FileSnapshot):
        raise TypeError("File verifier snapshot is invalid")
    if not isinstance(expectation, FileExpectation):
        raise TypeError("File verifier expectation is invalid")
    if not isinstance(content, bytes):
        raise TypeError("File verifier content must be immutable bytes")
    integrity = (
        len(content) == snapshot.byte_count
        and hashlib.sha256(content).hexdigest() == snapshot.sha256
    )
    checks = {
        "complete": snapshot.complete,
        "integrity": integrity,
    }
    if expectation.expected_sha256 is not None:
        checks["sha256"] = snapshot.sha256 == expectation.expected_sha256
    if expectation.expected_media_type is not None:
        checks["media_type"] = (
            snapshot.media_type == expectation.expected_media_type
        )
    if expectation.minimum_bytes is not None:
        checks["minimum_bytes"] = (
            snapshot.byte_count >= expectation.minimum_bytes
        )
    if expectation.maximum_bytes is not None:
        checks["maximum_bytes"] = (
            snapshot.byte_count <= expectation.maximum_bytes
        )
    if expectation.required_utf8_substrings:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            checks["required_utf8_substrings"] = False
        else:
            checks["required_utf8_substrings"] = all(
                substring in text
                for substring in expectation.required_utf8_substrings
            )
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.FILE,
        subject_reference=snapshot.artifact_id,
        subject_digest=snapshot.sha256,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "provenance_digest": snapshot.provenance_digest,
        },
    )


def verify_research_csv_file(
    snapshot: FileSnapshot,
    expectation: ResearchCsvFileExpectation,
    *,
    verifier_id: str,
    content: bytes,
) -> ResearchCsvFileVerification:
    """Verify exact file identity plus canonical, source-backed CSV content."""

    if not isinstance(snapshot, FileSnapshot):
        raise TypeError("Research CSV verifier snapshot is invalid")
    if not isinstance(expectation, ResearchCsvFileExpectation):
        raise TypeError("Research CSV verifier expectation is invalid")
    if not isinstance(content, bytes):
        raise TypeError(
            "Research CSV verifier content must be immutable bytes"
        )
    from research.csv_artifact import (
        ResearchCsvSchema,
        inspect_research_csv,
    )

    file = expectation.file
    integrity = (
        len(content) == snapshot.byte_count
        and hashlib.sha256(content).hexdigest() == snapshot.sha256
    )
    checks = {
        "complete_pending_file": snapshot.complete,
        "content_integrity": integrity,
        "expected_sha256": (
            snapshot.sha256 == file.expected_sha256
        ),
        "expected_media_type": (
            snapshot.media_type == file.expected_media_type
        ),
        "maximum_bytes": (
            file.maximum_bytes is not None
            and snapshot.byte_count <= file.maximum_bytes
        ),
    }
    if file.minimum_bytes is not None:
        checks["minimum_bytes"] = (
            snapshot.byte_count >= file.minimum_bytes
        )
    if file.required_utf8_substrings:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            checks["required_utf8_substrings"] = False
        else:
            checks["required_utf8_substrings"] = all(
                substring in text
                for substring in file.required_utf8_substrings
            )
    inspection = inspect_research_csv(
        content,
        ResearchCsvSchema(expectation.requested_field_ids),
        requested_rows=expectation.requested_rows,
        maximum_bytes=file.maximum_bytes,
    )
    checks["research_csv_structure"] = inspection.structurally_valid
    checks["research_csv_requested_rows"] = inspection.complete
    evidence = _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.FILE,
        subject_reference=snapshot.artifact_id,
        subject_digest=snapshot.sha256,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "provenance_digest": snapshot.provenance_digest,
            "research_csv_result": inspection.result_code,
            "research_csv_rows": inspection.row_count,
            "research_csv_schema_digest": inspection.schema_digest,
            "requested_rows": inspection.requested_rows,
        },
    )
    file_checks_without_row_count = all(
        value
        for name, value in checks.items()
        if name != "research_csv_requested_rows"
    )
    partial = (
        inspection.partial
        and file_checks_without_row_count
    )
    return ResearchCsvFileVerification(
        evidence=evidence,
        row_count=inspection.row_count,
        requested_rows=inspection.requested_rows,
        partial=partial,
    )


def verify_research_markdown_file(
    snapshot: FileSnapshot,
    expectation: ResearchMarkdownFileExpectation,
    *,
    verifier_id: str,
    content: bytes,
) -> ResearchMarkdownFileVerification:
    """Verify exact identity plus canonical, source-complete Markdown."""

    if not isinstance(snapshot, FileSnapshot):
        raise TypeError(
            "Research Markdown verifier snapshot is invalid"
        )
    if not isinstance(expectation, ResearchMarkdownFileExpectation):
        raise TypeError(
            "Research Markdown verifier expectation is invalid"
        )
    if not isinstance(content, bytes):
        raise TypeError(
            "Research Markdown verifier content must be immutable bytes"
        )
    from research.markdown_artifact import (
        ResearchMarkdownSchema,
        inspect_research_markdown,
    )

    file = expectation.file
    integrity = (
        len(content) == snapshot.byte_count
        and hashlib.sha256(content).hexdigest() == snapshot.sha256
    )
    checks = {
        "complete_pending_file": snapshot.complete,
        "content_integrity": integrity,
        "expected_sha256": (
            snapshot.sha256 == file.expected_sha256
        ),
        "expected_media_type": (
            snapshot.media_type == file.expected_media_type
        ),
        "maximum_bytes": (
            file.maximum_bytes is not None
            and snapshot.byte_count <= file.maximum_bytes
        ),
    }
    if file.minimum_bytes is not None:
        checks["minimum_bytes"] = (
            snapshot.byte_count >= file.minimum_bytes
        )
    if file.required_utf8_substrings:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            checks["required_utf8_substrings"] = False
        else:
            checks["required_utf8_substrings"] = all(
                substring in text
                for substring in file.required_utf8_substrings
            )
    inspection = inspect_research_markdown(
        content,
        ResearchMarkdownSchema(
            expectation.report_title,
            expectation.requested_field_ids,
        ),
        requested_sections=expectation.requested_sections,
        maximum_bytes=file.maximum_bytes,
    )
    checks["research_markdown_structure"] = (
        inspection.structurally_valid
    )
    checks["research_markdown_requested_sections"] = (
        inspection.complete
    )
    checks["research_markdown_sources"] = (
        inspection.source_digest == expectation.source_digest
    )
    evidence = _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.FILE,
        subject_reference=snapshot.artifact_id,
        subject_digest=snapshot.sha256,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "provenance_digest": snapshot.provenance_digest,
            "research_markdown_citations": inspection.citation_count,
            "research_markdown_result": inspection.result_code,
            "research_markdown_schema_digest": inspection.schema_digest,
            "research_markdown_sections": inspection.section_count,
            "research_markdown_source_digest": inspection.source_digest,
            "research_markdown_title_digest": inspection.title_digest,
            "requested_sections": inspection.requested_sections,
        },
    )
    file_checks_without_section_count = all(
        value
        for name, value in checks.items()
        if name != "research_markdown_requested_sections"
    )
    partial = (
        inspection.partial
        and file_checks_without_section_count
    )
    return ResearchMarkdownFileVerification(
        evidence=evidence,
        section_count=inspection.section_count,
        requested_sections=inspection.requested_sections,
        citation_count=inspection.citation_count,
        partial=partial,
    )


def verify_research_docx_file(
    snapshot: FileSnapshot,
    expectation: ResearchDocxFileExpectation,
    *,
    verifier_id: str,
    content: bytes,
) -> VerificationEvidence:
    """Verify exact identity, inert OOXML, and report-derived plain text."""

    if not isinstance(snapshot, FileSnapshot):
        raise TypeError(
            "Research DOCX verifier snapshot is invalid"
        )
    if not isinstance(expectation, ResearchDocxFileExpectation):
        raise TypeError(
            "Research DOCX verifier expectation is invalid"
        )
    if not isinstance(content, bytes):
        raise TypeError(
            "Research DOCX verifier content must be immutable bytes"
        )
    from research.docx_artifact import inspect_research_docx
    from research.markdown_artifact import ResearchMarkdownSchema

    file = expectation.file
    integrity = (
        len(content) == snapshot.byte_count
        and hashlib.sha256(content).hexdigest() == snapshot.sha256
    )
    checks = {
        "complete_pending_file": snapshot.complete,
        "content_integrity": integrity,
        "expected_sha256": (
            snapshot.sha256 == file.expected_sha256
        ),
        "expected_media_type": (
            snapshot.media_type == file.expected_media_type
        ),
        "maximum_bytes": (
            file.maximum_bytes is not None
            and snapshot.byte_count <= file.maximum_bytes
        ),
    }
    if file.minimum_bytes is not None:
        checks["minimum_bytes"] = (
            snapshot.byte_count >= file.minimum_bytes
        )
    inspection = inspect_research_docx(
        content,
        ResearchMarkdownSchema(
            expectation.report_title,
            expectation.requested_field_ids,
        ),
        requested_sections=expectation.requested_sections,
        maximum_bytes=file.maximum_bytes,
    )
    checks["research_docx_structure"] = inspection.structurally_valid
    checks["research_docx_sections"] = (
        inspection.section_count == expectation.requested_sections
    )
    checks["research_docx_document"] = (
        inspection.document_digest == expectation.document_digest
    )
    checks["research_docx_sources"] = (
        inspection.source_digest == expectation.source_digest
    )
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.FILE,
        subject_reference=snapshot.artifact_id,
        subject_digest=snapshot.sha256,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "provenance_digest": snapshot.provenance_digest,
            "research_docx_citations": inspection.citation_count,
            "research_docx_document_digest": inspection.document_digest,
            "research_docx_paragraphs": inspection.paragraph_count,
            "research_docx_parts": inspection.package_part_count,
            "research_docx_report_sha256": expectation.report_sha256,
            "research_docx_result": inspection.result_code,
            "research_docx_sections": inspection.section_count,
            "research_docx_source_digest": inspection.source_digest,
            "requested_sections": expectation.requested_sections,
        },
    )


def verify_research_pdf_file(
    snapshot: FileSnapshot,
    expectation: ResearchPdfFileExpectation,
    *,
    verifier_id: str,
    content: bytes,
) -> VerificationEvidence:
    """Verify exact identity, canonical inert PDF, and visible report text."""

    if not isinstance(snapshot, FileSnapshot):
        raise TypeError(
            "Research PDF verifier snapshot is invalid"
        )
    if not isinstance(expectation, ResearchPdfFileExpectation):
        raise TypeError(
            "Research PDF verifier expectation is invalid"
        )
    if not isinstance(content, bytes):
        raise TypeError(
            "Research PDF verifier content must be immutable bytes"
        )
    from research.markdown_artifact import ResearchMarkdownSchema
    from research.pdf_artifact import inspect_research_pdf

    file = expectation.file
    integrity = (
        len(content) == snapshot.byte_count
        and hashlib.sha256(content).hexdigest() == snapshot.sha256
    )
    checks = {
        "complete_pending_file": snapshot.complete,
        "content_integrity": integrity,
        "expected_sha256": (
            snapshot.sha256 == file.expected_sha256
        ),
        "expected_media_type": (
            snapshot.media_type == file.expected_media_type
        ),
        "maximum_bytes": (
            file.maximum_bytes is not None
            and snapshot.byte_count <= file.maximum_bytes
        ),
    }
    if file.minimum_bytes is not None:
        checks["minimum_bytes"] = (
            snapshot.byte_count >= file.minimum_bytes
        )
    inspection = inspect_research_pdf(
        content,
        ResearchMarkdownSchema(
            expectation.report_title,
            expectation.requested_field_ids,
        ),
        requested_sections=expectation.requested_sections,
        maximum_bytes=file.maximum_bytes,
    )
    checks["research_pdf_structure"] = inspection.structurally_valid
    checks["research_pdf_sections"] = (
        inspection.section_count == expectation.requested_sections
    )
    checks["research_pdf_document"] = (
        inspection.document_digest == expectation.document_digest
    )
    checks["research_pdf_sources"] = (
        inspection.source_digest == expectation.source_digest
    )
    checks["research_pdf_pages"] = (
        inspection.page_count == expectation.page_count
    )
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.FILE,
        subject_reference=snapshot.artifact_id,
        subject_digest=snapshot.sha256,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "provenance_digest": snapshot.provenance_digest,
            "research_pdf_citations": inspection.citation_count,
            "research_pdf_document_digest": inspection.document_digest,
            "research_pdf_lines": inspection.text_line_count,
            "research_pdf_pages": inspection.page_count,
            "research_pdf_paragraphs": inspection.paragraph_count,
            "research_pdf_report_sha256": expectation.report_sha256,
            "research_pdf_result": inspection.result_code,
            "research_pdf_sections": inspection.section_count,
            "research_pdf_source_digest": inspection.source_digest,
            "requested_sections": expectation.requested_sections,
        },
    )


@dataclass(frozen=True, slots=True)
class ApiResponseSnapshot:
    response_id: str
    request_digest: str
    status_code: int
    media_type: str
    byte_count: int
    body_digest: str

    def __post_init__(self) -> None:
        _reference(self.response_id, "API response ID")
        _sha256(self.request_digest, "API request digest")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("API response status is invalid")
        _media_type(self.media_type)
        _bounded_size(
            self.byte_count,
            MAX_RESPONSE_BYTES,
            "API response size",
        )
        _sha256(self.body_digest, "API response body digest")


@dataclass(frozen=True, slots=True)
class ApiResponseExpectation:
    allowed_status_codes: tuple[int, ...]
    expected_request_digest: str
    expected_media_type: str | None = None
    expected_body_digest: str | None = None
    maximum_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if (
            not isinstance(self.allowed_status_codes, tuple)
            or not self.allowed_status_codes
            or len(self.allowed_status_codes) > 16
            or len(self.allowed_status_codes)
            != len(set(self.allowed_status_codes))
            or any(
                type(status) is not int or not 100 <= status <= 599
                for status in self.allowed_status_codes
            )
        ):
            raise ValueError("Allowed API statuses are invalid")
        _sha256(self.expected_request_digest, "Expected API request digest")
        if self.expected_media_type is not None:
            _media_type(self.expected_media_type)
        if self.expected_body_digest is not None:
            _sha256(
                self.expected_body_digest,
                "Expected API response digest",
            )
        _bounded_size(
            self.maximum_bytes,
            MAX_RESPONSE_BYTES,
            "Maximum API response size",
        )


def verify_api_response(
    snapshot: ApiResponseSnapshot,
    expectation: ApiResponseExpectation,
    *,
    verifier_id: str,
) -> VerificationEvidence:
    if not isinstance(snapshot, ApiResponseSnapshot):
        raise TypeError("API verifier snapshot is invalid")
    if not isinstance(expectation, ApiResponseExpectation):
        raise TypeError("API verifier expectation is invalid")
    checks = {
        "request_digest": (
            snapshot.request_digest == expectation.expected_request_digest
        ),
        "status_code": snapshot.status_code in expectation.allowed_status_codes,
        "maximum_bytes": snapshot.byte_count <= expectation.maximum_bytes,
    }
    if expectation.expected_media_type is not None:
        checks["media_type"] = (
            snapshot.media_type == expectation.expected_media_type
        )
    if expectation.expected_body_digest is not None:
        checks["body_digest"] = (
            snapshot.body_digest == expectation.expected_body_digest
        )
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.API_RESPONSE,
        subject_reference=snapshot.response_id,
        subject_digest=snapshot.body_digest,
        checks=checks,
        observed={
            "byte_count": snapshot.byte_count,
            "media_type": snapshot.media_type,
            "request_digest": snapshot.request_digest,
            "status_code": snapshot.status_code,
        },
    )


@dataclass(frozen=True, slots=True)
class RepositorySnapshot:
    repository_id: str
    head_oid: str
    tree_digest: str
    clean: bool
    changed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        _reference(self.repository_id, "Repository ID")
        if not isinstance(self.head_oid, str) or _OID.fullmatch(
            self.head_oid
        ) is None:
            raise ValueError("Repository head OID is invalid")
        _sha256(self.tree_digest, "Repository tree digest")
        if type(self.clean) is not bool:
            raise TypeError("Repository cleanliness must be explicit")
        _paths(self.changed_paths, "Repository changed paths")


@dataclass(frozen=True, slots=True)
class RepositoryExpectation:
    expected_head_oid: str | None = None
    expected_tree_digest: str | None = None
    require_clean: bool | None = None
    allowed_changed_paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.expected_head_oid is not None and _OID.fullmatch(
            self.expected_head_oid
        ) is None:
            raise ValueError("Expected repository head is invalid")
        if self.expected_tree_digest is not None:
            _sha256(
                self.expected_tree_digest,
                "Expected repository tree digest",
            )
        if self.require_clean is not None and type(self.require_clean) is not bool:
            raise TypeError("Repository clean expectation is invalid")
        _paths(self.allowed_changed_paths, "Allowed repository paths")
        if not any(
            (
                self.expected_head_oid is not None,
                self.expected_tree_digest is not None,
                self.require_clean is not None,
                bool(self.allowed_changed_paths),
            )
        ):
            raise ValueError("Repository verifier requires a postcondition")


def verify_repository(
    snapshot: RepositorySnapshot,
    expectation: RepositoryExpectation,
    *,
    verifier_id: str,
) -> VerificationEvidence:
    if not isinstance(snapshot, RepositorySnapshot):
        raise TypeError("Repository verifier snapshot is invalid")
    if not isinstance(expectation, RepositoryExpectation):
        raise TypeError("Repository verifier expectation is invalid")
    checks: dict[str, bool] = {}
    if expectation.expected_head_oid is not None:
        checks["head_oid"] = (
            snapshot.head_oid == expectation.expected_head_oid
        )
    if expectation.expected_tree_digest is not None:
        checks["tree_digest"] = (
            snapshot.tree_digest == expectation.expected_tree_digest
        )
    if expectation.require_clean is not None:
        checks["clean"] = snapshot.clean is expectation.require_clean
    if expectation.allowed_changed_paths:
        checks["changed_paths"] = set(snapshot.changed_paths).issubset(
            expectation.allowed_changed_paths
        )
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.REPOSITORY,
        subject_reference=snapshot.repository_id,
        subject_digest=snapshot.tree_digest,
        checks=checks,
        observed={
            "changed_paths": list(snapshot.changed_paths),
            "clean": snapshot.clean,
            "head_oid": snapshot.head_oid,
        },
    )


@dataclass(frozen=True, slots=True)
class UiStateSnapshot:
    application_id: str
    window_id: str
    control_id: str
    property_name: str
    value_digest: str

    def __post_init__(self) -> None:
        _reference(self.application_id, "UI application ID")
        _reference(self.window_id, "UI window ID")
        _reference(self.control_id, "UI control ID")
        _reference(self.property_name, "UI property name")
        _sha256(self.value_digest, "UI value digest")


@dataclass(frozen=True, slots=True)
class UiStateExpectation:
    application_id: str
    window_id: str
    control_id: str
    property_name: str
    expected_value_digest: str

    def __post_init__(self) -> None:
        _reference(self.application_id, "Expected UI application ID")
        _reference(self.window_id, "Expected UI window ID")
        _reference(self.control_id, "Expected UI control ID")
        _reference(self.property_name, "Expected UI property name")
        _sha256(self.expected_value_digest, "Expected UI value digest")


def verify_ui_state(
    snapshot: UiStateSnapshot,
    expectation: UiStateExpectation,
    *,
    verifier_id: str,
) -> VerificationEvidence:
    if not isinstance(snapshot, UiStateSnapshot):
        raise TypeError("UI verifier snapshot is invalid")
    if not isinstance(expectation, UiStateExpectation):
        raise TypeError("UI verifier expectation is invalid")
    checks = {
        "application_id": (
            snapshot.application_id == expectation.application_id
        ),
        "control_id": snapshot.control_id == expectation.control_id,
        "property_name": (
            snapshot.property_name == expectation.property_name
        ),
        "value_digest": (
            snapshot.value_digest == expectation.expected_value_digest
        ),
        "window_id": snapshot.window_id == expectation.window_id,
    }
    return _evidence(
        verifier_id=verifier_id,
        subject_kind=VerificationSubjectKind.UI_STATE,
        subject_reference=snapshot.control_id,
        subject_digest=snapshot.value_digest,
        checks=checks,
        observed={
            "application_id": snapshot.application_id,
            "property_name": snapshot.property_name,
            "window_id": snapshot.window_id,
        },
    )


def _evidence(
    *,
    verifier_id: str,
    subject_kind: VerificationSubjectKind,
    subject_reference: str,
    subject_digest: str,
    checks: dict[str, bool],
    observed: dict[str, object],
) -> VerificationEvidence:
    _reference(verifier_id, "Verifier ID")
    if not checks or not all(type(value) is bool for value in checks.values()):
        raise ValueError("Verifier checks must be explicit booleans")
    postcondition_met = all(checks.values())
    result_code = (
        "postcondition_met"
        if postcondition_met
        else "postcondition_not_met"
    )
    encoded = _canonical_json(
        {
            "checks": checks,
            "observed": observed,
            "postcondition_met": postcondition_met,
            "result_code": result_code,
            "subject_digest": subject_digest,
            "subject_kind": subject_kind.value,
            "subject_reference": subject_reference,
            "verifier_id": verifier_id,
        }
    )
    return VerificationEvidence(
        verifier_id=verifier_id,
        subject_kind=subject_kind,
        subject_reference=subject_reference,
        subject_digest=subject_digest,
        postcondition_met=postcondition_met,
        result_code=result_code,
        evidence_digest=hashlib.sha256(encoded).hexdigest(),
        evidence_bytes=len(encoded),
    )


def _result_id(call: ToolCall) -> str:
    digest = hashlib.sha256(
        f"{call.run_id}\0{call.call_id}".encode("utf-8")
    ).hexdigest()
    return f"result-{digest[:32]}"


def _reference(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_REFERENCE_CHARS
        or _REFERENCE.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _media_type(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_MEDIA_TYPE_CHARS
        or _MEDIA_TYPE.fullmatch(value) is None
    ):
        raise ValueError("Verifier media type is invalid")
    return value


def _bounded_size(value: object, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or "/" in value
        or "\\" in value
        or "\x00" in value
    ):
        raise ValueError("Verifier file name is invalid")
    return value


def _bounded_strings(
    values: object,
    *,
    maximum_items: int,
    maximum_chars: int,
    label: str,
) -> tuple[str, ...]:
    if (
        not isinstance(values, tuple)
        or len(values) > maximum_items
        or len(values) != len(set(values))
        or any(
            not isinstance(value, str)
            or not value
            or len(value) > maximum_chars
            or "\x00" in value
            for value in values
        )
    ):
        raise ValueError(f"{label} are invalid")
    return values


def _paths(values: object, label: str) -> tuple[str, ...]:
    _bounded_strings(
        values,
        maximum_items=MAX_PATHS,
        maximum_chars=512,
        label=label,
    )
    for path in values:
        if (
            path.startswith(("/", "\\"))
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise ValueError(f"{label} must be relative normalized paths")
    return values


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


__all__ = [
    "ApiResponseExpectation",
    "ApiResponseSnapshot",
    "FileExpectation",
    "FileSnapshot",
    "ResearchCsvFileExpectation",
    "ResearchCsvFileVerification",
    "ResearchDocxFileExpectation",
    "ResearchPdfFileExpectation",
    "ResearchMarkdownFileExpectation",
    "ResearchMarkdownFileVerification",
    "RepositoryExpectation",
    "RepositorySnapshot",
    "UiStateExpectation",
    "UiStateSnapshot",
    "VerificationEvidence",
    "VerificationSubjectKind",
    "verify_api_response",
    "verify_file",
    "verify_research_csv_file",
    "verify_research_docx_file",
    "verify_research_markdown_file",
    "verify_research_pdf_file",
    "verify_repository",
    "verify_ui_state",
]
