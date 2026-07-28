"""Deterministic, inert PDF export for source-backed research reports.

Only canonical Markdown produced by :mod:`research.markdown_artifact` is
accepted.  The renderer emits a deliberately tiny PDF subset: plain visible
text, two built-in Type 1 fonts, a fixed page tree, and no links, forms,
attachments, scripts, actions, annotations, images, or incremental updates.
The parser accepts only bytes that can be reproduced exactly by this module.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from research.docx_artifact import (
    ResearchDocxError,
    ResearchDocxParagraph,
    research_markdown_to_docx_model,
    research_report_paragraph_digest,
    validate_research_report_paragraphs,
)
from research.markdown_artifact import ResearchMarkdownSchema
from research.models import MAX_RESEARCH_BYTES, MAX_RESEARCH_ROWS


PDF_MEDIA_TYPE = "application/pdf"
MAX_RESEARCH_PDF_BYTES = 8 * 1024 * 1024
MAX_RESEARCH_PDF_PAGES = 200
MAX_RESEARCH_PDF_LINES = 20_000
MAX_RESEARCH_PDF_PARAGRAPHS = 10_000
_HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
_PAGE_WIDTH = 612
_PAGE_HEIGHT = 792
_LEFT = 72
_TOP = 740
_BOTTOM = 54
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_HEADER = re.compile(rb"([1-9][0-9]*) 0 obj\n")
_STREAM_BODY = re.compile(
    rb"<< /Length ([1-9][0-9]*) >>\nstream\n(.*)endstream",
    re.DOTALL,
)
_MARKER = re.compile(r"/P([0-9]{5}) BMC")
_FONT = re.compile(r"/(F1|F2) ([1-9][0-9]*) Tf")
_MATRIX = re.compile(r"1 0 0 1 ([0-9]+) ([0-9]+) Tm")
_TEXT = re.compile(r"<([0-9A-F]+)> Tj")
_BANNED_TOKENS = (
    b"/AA",
    b"/AcroForm",
    b"/Action",
    b"/Annots",
    b"/EmbeddedFile",
    b"/Encrypt",
    b"/Filespec",
    b"/GoToR",
    b"/ImportData",
    b"/JavaScript",
    b"/JS",
    b"/Launch",
    b"/OpenAction",
    b"/RichMedia",
    b"/SubmitForm",
    b"/URI",
    b"/XFA",
)
_STYLE = {
    "Title": ("F2", 18, 24, 48, 10),
    "Heading1": ("F2", 14, 19, 64, 8),
    "Body": ("F1", 10, 14, 88, 4),
}
_FONT_STYLE = {
    ("F2", 18): "Title",
    ("F2", 14): "Heading1",
    ("F1", 10): "Body",
}
_CATALOG = b"<< /Type /Catalog /Pages 2 0 R >>"
_FONT_REGULAR = (
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
    b"/Encoding /WinAnsiEncoding >>"
)
_FONT_BOLD = (
    b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold "
    b"/Encoding /WinAnsiEncoding >>"
)


class ResearchPdfError(ValueError):
    """A PDF report request, document, or extracted value is invalid."""


@dataclass(frozen=True, slots=True)
class ResearchPdfArtifact:
    content: bytes = field(repr=False)
    sha256: str
    report_sha256: str
    document_digest: str
    source_digest: str
    section_count: int
    page_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= MAX_RESEARCH_PDF_BYTES
            or self.sha256 != hashlib.sha256(self.content).hexdigest()
        ):
            raise ResearchPdfError(
                "Research PDF artifact content is invalid"
            )
        for digest in (
            self.sha256,
            self.report_sha256,
            self.document_digest,
            self.source_digest,
        ):
            _digest(digest, "Research PDF artifact")
        _bounded_integer(
            self.section_count,
            1,
            MAX_RESEARCH_ROWS,
            "Research PDF artifact section count",
        )
        _bounded_integer(
            self.page_count,
            1,
            MAX_RESEARCH_PDF_PAGES,
            "Research PDF artifact page count",
        )


@dataclass(frozen=True, slots=True)
class ResearchPdfInspection:
    structurally_valid: bool
    section_count: int
    citation_count: int
    paragraph_count: int
    text_line_count: int
    page_count: int
    content_sha256: str
    document_digest: str
    source_digest: str
    result_code: str

    def __post_init__(self) -> None:
        if type(self.structurally_valid) is not bool:
            raise TypeError(
                "Research PDF inspection validity must be explicit"
            )
        for value, maximum, label in (
            (self.section_count, MAX_RESEARCH_ROWS, "section"),
            (self.citation_count, 10_000, "citation"),
            (
                self.paragraph_count,
                MAX_RESEARCH_PDF_PARAGRAPHS,
                "paragraph",
            ),
            (self.text_line_count, MAX_RESEARCH_PDF_LINES, "line"),
            (self.page_count, MAX_RESEARCH_PDF_PAGES, "page"),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ResearchPdfError(
                    f"Research PDF inspection {label} count is invalid"
                )
        for digest in (
            self.content_sha256,
            self.document_digest,
            self.source_digest,
        ):
            _digest(digest, "Research PDF inspection")
        if self.result_code not in {
            "invalid_research_pdf",
            "research_pdf_complete",
        }:
            raise ResearchPdfError(
                "Research PDF inspection result is invalid"
            )
        if self.structurally_valid != (
            self.result_code == "research_pdf_complete"
        ):
            raise ResearchPdfError(
                "Research PDF inspection outcome is inconsistent"
            )


@dataclass(frozen=True, slots=True)
class ResearchPdfDocument:
    paragraphs: tuple[ResearchDocxParagraph, ...]
    page_count: int
    text_line_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.paragraphs, tuple)
            or not self.paragraphs
            or len(self.paragraphs) > MAX_RESEARCH_PDF_PARAGRAPHS
            or any(
                not isinstance(item, ResearchDocxParagraph)
                for item in self.paragraphs
            )
        ):
            raise ResearchPdfError(
                "Research PDF extracted paragraphs are invalid"
            )
        _bounded_integer(
            self.page_count,
            1,
            MAX_RESEARCH_PDF_PAGES,
            "Research PDF document page count",
        )
        _bounded_integer(
            self.text_line_count,
            1,
            MAX_RESEARCH_PDF_LINES,
            "Research PDF document line count",
        )


@dataclass(frozen=True, slots=True)
class _PdfLine:
    paragraph_index: int
    style: str
    text: str = field(repr=False)
    x: int
    y: int

    def __post_init__(self) -> None:
        _bounded_integer(
            self.paragraph_index,
            1,
            MAX_RESEARCH_PDF_PARAGRAPHS,
            "Research PDF paragraph index",
        )
        if self.style not in _STYLE:
            raise ResearchPdfError(
                "Research PDF line style is invalid"
            )
        try:
            encoded = self.text.encode("cp1252")
        except UnicodeEncodeError as exc:
            raise ResearchPdfError(
                "Research PDF text requires an unsupported character"
            ) from exc
        if (
            not self.text
            or len(encoded) > 512
            or not self.text.isprintable()
        ):
            raise ResearchPdfError(
                "Research PDF line text is invalid"
            )
        _bounded_integer(
            self.x,
            0,
            _PAGE_WIDTH,
            "Research PDF line x coordinate",
        )
        _bounded_integer(
            self.y,
            0,
            _PAGE_HEIGHT,
            "Research PDF line y coordinate",
        )


def render_research_markdown_to_pdf(
    report_content: bytes,
    schema: ResearchMarkdownSchema,
    *,
    requested_sections: int,
    maximum_output_bytes: int,
) -> ResearchPdfArtifact:
    """Render one deterministic plain-text PDF and self-verify exact bytes."""

    _bounded_integer(
        maximum_output_bytes,
        1,
        MAX_RESEARCH_PDF_BYTES,
        "Research PDF output limit",
    )
    try:
        model = research_markdown_to_docx_model(
            report_content,
            schema,
            requested_sections=requested_sections,
            maximum_report_bytes=MAX_RESEARCH_BYTES,
        )
    except ResearchDocxError as exc:
        raise ResearchPdfError(
            "Research PDF source report is not complete and canonical"
        ) from exc
    pages = _layout_paragraphs(model.paragraphs)
    content = _serialize_pdf(pages)
    if len(content) > maximum_output_bytes:
        raise ResearchPdfError(
            "Research PDF output limit exceeded"
        )
    inspection = inspect_research_pdf(
        content,
        schema,
        requested_sections=requested_sections,
        maximum_bytes=maximum_output_bytes,
    )
    if (
        not inspection.structurally_valid
        or inspection.document_digest != model.document_digest
        or inspection.source_digest != model.source_digest
        or inspection.page_count != len(pages)
    ):
        raise ResearchPdfError(
            "Rendered Research PDF failed exact self-verification"
        )
    return ResearchPdfArtifact(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        report_sha256=model.report_sha256,
        document_digest=model.document_digest,
        source_digest=model.source_digest,
        section_count=model.section_count,
        page_count=len(pages),
    )


def validate_safe_pdf_document(
    content: bytes,
    *,
    maximum_bytes: int = MAX_RESEARCH_PDF_BYTES,
) -> ResearchPdfDocument:
    """Accept only this renderer's canonical, action-free PDF subset."""

    _bounded_integer(
        maximum_bytes,
        1,
        MAX_RESEARCH_PDF_BYTES,
        "Research PDF verification byte limit",
    )
    if (
        not isinstance(content, bytes)
        or not 1 <= len(content) <= maximum_bytes
    ):
        raise ResearchPdfError(
            "Research PDF document size is invalid"
        )
    if any(token in content for token in _BANNED_TOKENS):
        raise ResearchPdfError(
            "Research PDF contains an active or unreviewed feature"
        )
    pages = _parse_canonical_pdf(content)
    paragraphs = _paragraphs_from_pages(pages)
    expected_pages = _layout_paragraphs(paragraphs)
    if expected_pages != pages or _serialize_pdf(expected_pages) != content:
        raise ResearchPdfError(
            "Research PDF is not in canonical rendered form"
        )
    return ResearchPdfDocument(
        paragraphs=paragraphs,
        page_count=len(pages),
        text_line_count=sum(len(page) for page in pages),
    )


def safe_pdf_text_preview(
    content: bytes,
    *,
    maximum_chars: int = 24 * 1024,
) -> str:
    """Return bounded visible text from an already canonical inert PDF."""

    _bounded_integer(
        maximum_chars,
        1,
        64 * 1024,
        "Research PDF preview character limit",
    )
    document = validate_safe_pdf_document(content)
    return "\n".join(
        item.text for item in document.paragraphs
    )[:maximum_chars]


def inspect_research_pdf(
    content: bytes,
    schema: ResearchMarkdownSchema,
    *,
    requested_sections: int,
    maximum_bytes: int,
) -> ResearchPdfInspection:
    """Inspect canonical PDF structure, visible text, and source coverage."""

    if not isinstance(content, bytes):
        raise TypeError(
            "Research PDF inspection requires immutable bytes"
        )
    if not isinstance(schema, ResearchMarkdownSchema):
        raise TypeError(
            "Research PDF inspection requires a typed report schema"
        )
    _bounded_integer(
        requested_sections,
        1,
        MAX_RESEARCH_ROWS,
        "Research PDF requested section count",
    )
    _bounded_integer(
        maximum_bytes,
        1,
        MAX_RESEARCH_PDF_BYTES,
        "Research PDF verification byte limit",
    )
    content_digest = hashlib.sha256(content).hexdigest()
    empty_digest = hashlib.sha256(b"").hexdigest()
    section_count = 0
    citation_count = 0
    paragraph_count = 0
    line_count = 0
    page_count = 0
    document_digest = empty_digest
    source_digest = _source_digest(())
    try:
        document = validate_safe_pdf_document(
            content,
            maximum_bytes=maximum_bytes,
        )
        paragraph_count = len(document.paragraphs)
        line_count = document.text_line_count
        page_count = document.page_count
        section_count, citation_count, sources = (
            validate_research_report_paragraphs(
                document.paragraphs,
                schema,
                requested_sections=requested_sections,
            )
        )
        document_digest = research_report_paragraph_digest(
            document.paragraphs
        )
        source_digest = _source_digest(sources)
    except (ResearchPdfError, TypeError, ValueError):
        return ResearchPdfInspection(
            structurally_valid=False,
            section_count=min(section_count, MAX_RESEARCH_ROWS),
            citation_count=min(citation_count, 10_000),
            paragraph_count=min(
                paragraph_count,
                MAX_RESEARCH_PDF_PARAGRAPHS,
            ),
            text_line_count=min(line_count, MAX_RESEARCH_PDF_LINES),
            page_count=min(page_count, MAX_RESEARCH_PDF_PAGES),
            content_sha256=content_digest,
            document_digest=document_digest,
            source_digest=source_digest,
            result_code="invalid_research_pdf",
        )
    return ResearchPdfInspection(
        structurally_valid=True,
        section_count=section_count,
        citation_count=citation_count,
        paragraph_count=paragraph_count,
        text_line_count=line_count,
        page_count=page_count,
        content_sha256=content_digest,
        document_digest=document_digest,
        source_digest=source_digest,
        result_code="research_pdf_complete",
    )


def _layout_paragraphs(
    paragraphs: tuple[ResearchDocxParagraph, ...],
) -> tuple[tuple[_PdfLine, ...], ...]:
    if (
        not isinstance(paragraphs, tuple)
        or not paragraphs
        or len(paragraphs) > MAX_RESEARCH_PDF_PARAGRAPHS
    ):
        raise ResearchPdfError(
            "Research PDF paragraph collection is invalid"
        )
    pages: list[list[_PdfLine]] = [[]]
    y = _TOP
    total_lines = 0
    for paragraph_index, paragraph in enumerate(paragraphs, 1):
        if not isinstance(paragraph, ResearchDocxParagraph):
            raise ResearchPdfError(
                "Research PDF paragraph is invalid"
            )
        _font, _size, line_height, width, gap = _STYLE[paragraph.style]
        chunks = _wrap_exact(paragraph.text, width)
        for chunk in chunks:
            if y < _BOTTOM:
                if len(pages) >= MAX_RESEARCH_PDF_PAGES:
                    raise ResearchPdfError(
                        "Research PDF page limit exceeded"
                    )
                pages.append([])
                y = _TOP
            pages[-1].append(
                _PdfLine(
                    paragraph_index=paragraph_index,
                    style=paragraph.style,
                    text=chunk,
                    x=_LEFT,
                    y=y,
                )
            )
            total_lines += 1
            if total_lines > MAX_RESEARCH_PDF_LINES:
                raise ResearchPdfError(
                    "Research PDF visible line limit exceeded"
                )
            y -= line_height
        y -= gap
    return tuple(tuple(page) for page in pages)


def _wrap_exact(text: str, width: int) -> tuple[str, ...]:
    try:
        text.encode("cp1252")
    except UnicodeEncodeError as exc:
        raise ResearchPdfError(
            "Research PDF text requires an unsupported character"
        ) from exc
    if not text or not text.isprintable():
        raise ResearchPdfError(
            "Research PDF paragraph text is invalid"
        )
    remaining = text
    chunks: list[str] = []
    while len(remaining) > width:
        cut = remaining.rfind(" ", 0, width + 1)
        if cut <= 0:
            cut = width
        else:
            cut += 1
        chunks.append(remaining[:cut])
        remaining = remaining[cut:]
    if remaining:
        chunks.append(remaining)
    if not chunks or "".join(chunks) != text:
        raise ResearchPdfError(
            "Research PDF line wrapping failed"
        )
    return tuple(chunks)


def _serialize_pdf(
    pages: tuple[tuple[_PdfLine, ...], ...],
) -> bytes:
    if not 1 <= len(pages) <= MAX_RESEARCH_PDF_PAGES:
        raise ResearchPdfError(
            "Research PDF page collection is invalid"
        )
    streams = tuple(_page_stream(page) for page in pages)
    kids = " ".join(
        f"{5 + index * 2} 0 R"
        for index in range(len(pages))
    )
    objects: list[bytes] = [
        _CATALOG,
        (
            f"<< /Type /Pages /Kids [{kids}] "
            f"/Count {len(pages)} >>"
        ).encode("ascii"),
        _FONT_REGULAR,
        _FONT_BOLD,
    ]
    for index, stream in enumerate(streams):
        page_id = 5 + index * 2
        content_id = page_id + 1
        objects.append(_page_object(content_id))
        objects.append(
            (
                f"<< /Length {len(stream)} >>\nstream\n"
            ).encode("ascii")
            + stream
            + b"endstream"
        )
    output = bytearray(_HEADER)
    offsets = [0]
    for object_id, body in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(body)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(
        _xref_bytes(
            offsets,
            root_id=1,
            xref_offset=xref_offset,
        )
    )
    if len(output) > MAX_RESEARCH_PDF_BYTES:
        raise ResearchPdfError(
            "Research PDF byte limit exceeded"
        )
    return bytes(output)


def _page_object(content_id: int) -> bytes:
    return (
        f"<< /Type /Page /Parent 2 0 R "
        f"/MediaBox [0 0 {_PAGE_WIDTH} {_PAGE_HEIGHT}] "
        "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
        f"/Contents {content_id} 0 R >>"
    ).encode("ascii")


def _page_stream(page: tuple[_PdfLine, ...]) -> bytes:
    if not page:
        raise ResearchPdfError(
            "Research PDF page cannot be empty"
        )
    output: list[str] = []
    active_paragraph: int | None = None
    for line in page:
        if line.paragraph_index != active_paragraph:
            if active_paragraph is not None:
                output.append("EMC")
            active_paragraph = line.paragraph_index
            output.append(f"/P{active_paragraph:05d} BMC")
        font, size, _height, _width, _gap = _STYLE[line.style]
        encoded = line.text.encode("cp1252").hex().upper()
        output.extend(
            (
                "BT",
                f"/{font} {size} Tf",
                f"1 0 0 1 {line.x} {line.y} Tm",
                f"<{encoded}> Tj",
                "ET",
            )
        )
    output.append("EMC")
    return ("\n".join(output) + "\n").encode("ascii")


def _xref_bytes(
    offsets: list[int],
    *,
    root_id: int,
    xref_offset: int,
) -> bytes:
    size = len(offsets)
    lines = [
        "xref",
        f"0 {size}",
        "0000000000 65535 f ",
        *(
            f"{offset:010d} 00000 n "
            for offset in offsets[1:]
        ),
        "trailer",
        f"<< /Size {size} /Root {root_id} 0 R >>",
        "startxref",
        str(xref_offset),
        "%%EOF",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def _parse_canonical_pdf(
    content: bytes,
) -> tuple[tuple[_PdfLine, ...], ...]:
    if (
        not content.startswith(_HEADER)
        or not content.endswith(b"%%EOF\n")
        or content.count(b"\nxref\n") != 1
        or content.count(b"\nstartxref\n") != 1
        or content.count(b"%%EOF") != 1
    ):
        raise ResearchPdfError(
            "Research PDF envelope is invalid"
        )
    xref_offset = content.index(b"xref\n", len(_HEADER))
    objects: list[bytes] = []
    offsets = [0]
    cursor = len(_HEADER)
    object_id = 1
    while cursor < xref_offset:
        match = _OBJECT_HEADER.match(content, cursor)
        if match is None or int(match.group(1)) != object_id:
            raise ResearchPdfError(
                "Research PDF object sequence is invalid"
            )
        offsets.append(cursor)
        body_start = match.end()
        body_end = content.find(b"\nendobj\n", body_start)
        if body_end < 0 or body_end >= xref_offset:
            raise ResearchPdfError(
                "Research PDF object boundary is invalid"
            )
        objects.append(content[body_start:body_end])
        cursor = body_end + len(b"\nendobj\n")
        object_id += 1
    if cursor != xref_offset or len(objects) < 6:
        raise ResearchPdfError(
            "Research PDF object table is invalid"
        )
    size = len(objects) + 1
    if (size - 5) % 2:
        raise ResearchPdfError(
            "Research PDF page object count is invalid"
        )
    page_count = (size - 5) // 2
    if not 1 <= page_count <= MAX_RESEARCH_PDF_PAGES:
        raise ResearchPdfError(
            "Research PDF page count is invalid"
        )
    expected_xref = _xref_bytes(
        offsets,
        root_id=1,
        xref_offset=xref_offset,
    )
    if content[xref_offset:] != expected_xref:
        raise ResearchPdfError(
            "Research PDF cross-reference table is invalid"
        )
    expected_kids = " ".join(
        f"{5 + index * 2} 0 R"
        for index in range(page_count)
    )
    expected_pages = (
        f"<< /Type /Pages /Kids [{expected_kids}] "
        f"/Count {page_count} >>"
    ).encode("ascii")
    if (
        objects[0] != _CATALOG
        or objects[1] != expected_pages
        or objects[2] != _FONT_REGULAR
        or objects[3] != _FONT_BOLD
    ):
        raise ResearchPdfError(
            "Research PDF catalog or resources are invalid"
        )
    pages: list[tuple[_PdfLine, ...]] = []
    for index in range(page_count):
        page_id = 5 + index * 2
        content_id = page_id + 1
        if objects[page_id - 1] != _page_object(content_id):
            raise ResearchPdfError(
                "Research PDF page dictionary is invalid"
            )
        stream_body = objects[content_id - 1]
        match = _STREAM_BODY.fullmatch(stream_body)
        if match is None:
            raise ResearchPdfError(
                "Research PDF content stream is invalid"
            )
        stream = match.group(2)
        if int(match.group(1)) != len(stream):
            raise ResearchPdfError(
                "Research PDF content length is invalid"
            )
        pages.append(_parse_page_stream(stream))
    return tuple(pages)


def _parse_page_stream(stream: bytes) -> tuple[_PdfLine, ...]:
    try:
        raw_lines = stream.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ResearchPdfError(
            "Research PDF content stream is not canonical ASCII"
        ) from exc
    if not raw_lines:
        raise ResearchPdfError(
            "Research PDF content stream is empty"
        )
    parsed: list[_PdfLine] = []
    cursor = 0
    while cursor < len(raw_lines):
        marker = _MARKER.fullmatch(raw_lines[cursor])
        if marker is None:
            raise ResearchPdfError(
                "Research PDF paragraph marker is invalid"
            )
        paragraph_index = int(marker.group(1))
        cursor += 1
        block_lines = 0
        while cursor < len(raw_lines) and raw_lines[cursor] != "EMC":
            if (
                cursor + 4 >= len(raw_lines)
                or raw_lines[cursor] != "BT"
                or raw_lines[cursor + 4] != "ET"
            ):
                raise ResearchPdfError(
                    "Research PDF visible text command is invalid"
                )
            font = _FONT.fullmatch(raw_lines[cursor + 1])
            matrix = _MATRIX.fullmatch(raw_lines[cursor + 2])
            text = _TEXT.fullmatch(raw_lines[cursor + 3])
            if font is None or matrix is None or text is None:
                raise ResearchPdfError(
                    "Research PDF visible text operands are invalid"
                )
            style = _FONT_STYLE.get(
                (font.group(1), int(font.group(2)))
            )
            if style is None:
                raise ResearchPdfError(
                    "Research PDF visible text style is invalid"
                )
            try:
                encoded = bytes.fromhex(text.group(1))
                decoded = encoded.decode("cp1252")
            except (UnicodeDecodeError, ValueError) as exc:
                raise ResearchPdfError(
                    "Research PDF visible text encoding is invalid"
                ) from exc
            parsed.append(
                _PdfLine(
                    paragraph_index=paragraph_index,
                    style=style,
                    text=decoded,
                    x=int(matrix.group(1)),
                    y=int(matrix.group(2)),
                )
            )
            block_lines += 1
            cursor += 5
        if (
            block_lines == 0
            or cursor >= len(raw_lines)
            or raw_lines[cursor] != "EMC"
        ):
            raise ResearchPdfError(
                "Research PDF marked content is invalid"
            )
        cursor += 1
    if not parsed:
        raise ResearchPdfError(
            "Research PDF has no visible text"
        )
    return tuple(parsed)


def _paragraphs_from_pages(
    pages: tuple[tuple[_PdfLine, ...], ...],
) -> tuple[ResearchDocxParagraph, ...]:
    if not pages or any(not page for page in pages):
        raise ResearchPdfError(
            "Research PDF pages are invalid"
        )
    paragraphs: list[ResearchDocxParagraph] = []
    active_id = 0
    active_style = ""
    active_text: list[str] = []
    line_count = 0
    for page in pages:
        for line in page:
            line_count += 1
            if line_count > MAX_RESEARCH_PDF_LINES:
                raise ResearchPdfError(
                    "Research PDF visible line limit exceeded"
                )
            if line.paragraph_index != active_id:
                if active_id:
                    paragraphs.append(
                        ResearchDocxParagraph(
                            active_style,
                            "".join(active_text),
                        )
                    )
                if line.paragraph_index != active_id + 1:
                    raise ResearchPdfError(
                        "Research PDF paragraph order is invalid"
                    )
                active_id = line.paragraph_index
                active_style = line.style
                active_text = []
            elif line.style != active_style:
                raise ResearchPdfError(
                    "Research PDF paragraph style changed"
                )
            active_text.append(line.text)
    if active_id:
        paragraphs.append(
            ResearchDocxParagraph(
                active_style,
                "".join(active_text),
            )
        )
    if not paragraphs:
        raise ResearchPdfError(
            "Research PDF has no extracted paragraphs"
        )
    return tuple(paragraphs)


def _source_digest(sources: tuple[str, ...]) -> str:
    import json

    return hashlib.sha256(
        json.dumps(
            {"sources": sources},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: object, label: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ResearchPdfError(f"{label} digest is invalid")


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchPdfError(f"{label} is invalid")


__all__ = [
    "MAX_RESEARCH_PDF_BYTES",
    "MAX_RESEARCH_PDF_PAGES",
    "PDF_MEDIA_TYPE",
    "ResearchPdfArtifact",
    "ResearchPdfDocument",
    "ResearchPdfError",
    "ResearchPdfInspection",
    "inspect_research_pdf",
    "render_research_markdown_to_pdf",
    "safe_pdf_text_preview",
    "validate_safe_pdf_document",
]
