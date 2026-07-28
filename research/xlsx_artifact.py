"""Deterministic, formula-safe XLSX export for verified research tables.

Only complete canonical CSV produced by :mod:`research.csv_artifact` is
accepted.  Workbooks contain one visible worksheet and inline string cells
only.  Inspection never invokes Excel and rejects formulas, macros, external
links, hidden content, extra ZIP parts, and non-canonical package metadata.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zipfile
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from research.csv_artifact import (
    MAX_RESEARCH_CSV_COLUMNS,
    ResearchCsvSchema,
    inspect_research_csv,
)
from research.models import MAX_RESEARCH_BYTES, MAX_RESEARCH_ROWS


XLSX_MEDIA_TYPE = (
    "application/vnd.openxmlformats-officedocument."
    "spreadsheetml.sheet"
)
MAX_RESEARCH_XLSX_BYTES = 8 * 1024 * 1024
MAX_RESEARCH_XLSX_PART_BYTES = 4 * 1024 * 1024
MAX_RESEARCH_XLSX_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
MAX_RESEARCH_XLSX_CELL_CHARS = 32_767
MAX_RESEARCH_XLSX_ENTRIES = 8
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORMULA_PREFIX = re.compile(r"^[\t\r\n ]*[=+\-@]")
_ILLEGAL_XML = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]"
)
_DANGEROUS_XML = (b"<!doctype", b"<!entity")
_SPREADSHEET_NS = (
    "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
)
_REL_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)
_REQUIRED_PARTS = (
    "[Content_Types].xml",
    "_rels/.rels",
    "docProps/core.xml",
    "docProps/app.xml",
    "xl/workbook.xml",
    "xl/_rels/workbook.xml.rels",
    "xl/styles.xml",
    "xl/worksheets/sheet1.xml",
)
_ZERO_DIGEST = "0" * 64


class ResearchXlsxError(ValueError):
    """An XLSX render request or package is invalid."""


@dataclass(frozen=True, slots=True)
class ResearchXlsxArtifact:
    content: bytes = field(repr=False)
    sha256: str
    source_csv_sha256: str
    schema_digest: str
    table_digest: str
    row_count: int
    column_count: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= MAX_RESEARCH_XLSX_BYTES
            or self.sha256 != hashlib.sha256(self.content).hexdigest()
        ):
            raise ResearchXlsxError("Research XLSX artifact content is invalid")
        for digest in (
            self.sha256,
            self.source_csv_sha256,
            self.schema_digest,
            self.table_digest,
        ):
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise ResearchXlsxError(
                    "Research XLSX artifact digest is invalid"
                )
        _bounded_integer(
            self.row_count,
            1,
            MAX_RESEARCH_ROWS,
            "Research XLSX row count",
        )
        _bounded_integer(
            self.column_count,
            7,
            MAX_RESEARCH_CSV_COLUMNS,
            "Research XLSX column count",
        )


@dataclass(frozen=True, slots=True)
class ResearchXlsxInspection:
    structurally_valid: bool
    row_count: int
    column_count: int
    cell_count: int
    package_part_count: int
    content_sha256: str
    source_csv_sha256: str
    schema_digest: str
    table_digest: str
    result_code: str

    def __post_init__(self) -> None:
        if type(self.structurally_valid) is not bool:
            raise TypeError("Research XLSX validity must be explicit")
        for value, maximum, label in (
            (self.row_count, MAX_RESEARCH_ROWS, "row"),
            (self.column_count, MAX_RESEARCH_CSV_COLUMNS, "column"),
            (
                self.cell_count,
                (MAX_RESEARCH_ROWS + 1) * MAX_RESEARCH_CSV_COLUMNS,
                "cell",
            ),
            (
                self.package_part_count,
                MAX_RESEARCH_XLSX_ENTRIES,
                "package part",
            ),
        ):
            _bounded_integer(
                value,
                0,
                maximum,
                f"Research XLSX inspected {label} count",
            )
        for digest in (
            self.content_sha256,
            self.source_csv_sha256,
            self.schema_digest,
            self.table_digest,
        ):
            if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
                raise ResearchXlsxError(
                    "Research XLSX inspection digest is invalid"
                )
        if self.result_code not in {
            "invalid_research_xlsx",
            "research_xlsx_complete",
        }:
            raise ResearchXlsxError(
                "Research XLSX inspection result is invalid"
            )
        if self.structurally_valid != (
            self.result_code == "research_xlsx_complete"
        ):
            raise ResearchXlsxError(
                "Research XLSX inspection outcome is inconsistent"
            )


def render_research_csv_to_xlsx(
    csv_content: bytes,
    schema: ResearchCsvSchema,
    *,
    requested_rows: int,
    maximum_output_bytes: int = MAX_RESEARCH_XLSX_BYTES,
) -> ResearchXlsxArtifact:
    """Render a complete canonical research CSV as a deterministic XLSX."""

    _bounded_integer(
        maximum_output_bytes,
        1,
        MAX_RESEARCH_XLSX_BYTES,
        "Research XLSX output limit",
    )
    source = inspect_research_csv(
        csv_content,
        schema,
        requested_rows=requested_rows,
        maximum_bytes=MAX_RESEARCH_BYTES,
    )
    if not source.complete:
        raise ResearchXlsxError(
            "Research XLSX source CSV is not complete and canonical"
        )
    rows = _read_csv_rows(csv_content)
    _validate_table(rows)
    content = _serialize_xlsx(rows)
    if len(content) > maximum_output_bytes:
        raise ResearchXlsxError("Research XLSX output limit exceeded")
    inspection = inspect_research_xlsx(
        content,
        schema,
        requested_rows=requested_rows,
        maximum_bytes=maximum_output_bytes,
    )
    if (
        not inspection.structurally_valid
        or inspection.source_csv_sha256 != source.content_sha256
    ):
        raise ResearchXlsxError("Research XLSX self-verification failed")
    return ResearchXlsxArtifact(
        content=content,
        sha256=inspection.content_sha256,
        source_csv_sha256=inspection.source_csv_sha256,
        schema_digest=inspection.schema_digest,
        table_digest=inspection.table_digest,
        row_count=inspection.row_count,
        column_count=inspection.column_count,
    )


def inspect_research_xlsx(
    content: bytes,
    schema: ResearchCsvSchema,
    *,
    requested_rows: int,
    maximum_bytes: int,
) -> ResearchXlsxInspection:
    """Inspect bounded workbook bytes without returning cell contents."""

    if not isinstance(content, bytes):
        raise TypeError("Research XLSX inspection requires immutable bytes")
    if not isinstance(schema, ResearchCsvSchema):
        raise TypeError("Research XLSX inspection requires a typed schema")
    _bounded_integer(
        requested_rows,
        1,
        MAX_RESEARCH_ROWS,
        "Research XLSX requested row count",
    )
    _bounded_integer(
        maximum_bytes,
        1,
        MAX_RESEARCH_XLSX_BYTES,
        "Research XLSX verification byte limit",
    )
    digest = hashlib.sha256(content).hexdigest()
    row_count = 0
    column_count = 0
    cell_count = 0
    part_count = 0
    try:
        if not content or len(content) > maximum_bytes:
            raise ResearchXlsxError("research_xlsx_size")
        rows, part_count = _extract_canonical_rows(content)
        _validate_table(rows)
        if tuple(rows[0]) != schema.columns:
            raise ResearchXlsxError("research_xlsx_schema")
        row_count = len(rows) - 1
        column_count = len(rows[0])
        cell_count = len(rows) * column_count
        if row_count != requested_rows:
            raise ResearchXlsxError("research_xlsx_row_count")
        csv_content = _write_csv_rows(rows)
        csv_inspection = inspect_research_csv(
            csv_content,
            schema,
            requested_rows=requested_rows,
            maximum_bytes=MAX_RESEARCH_BYTES,
        )
        if not csv_inspection.complete:
            raise ResearchXlsxError("research_xlsx_source_table")
    except (ResearchXlsxError, ET.ParseError, OSError, zipfile.BadZipFile):
        return ResearchXlsxInspection(
            structurally_valid=False,
            row_count=min(row_count, MAX_RESEARCH_ROWS),
            column_count=min(column_count, MAX_RESEARCH_CSV_COLUMNS),
            cell_count=min(
                cell_count,
                (MAX_RESEARCH_ROWS + 1) * MAX_RESEARCH_CSV_COLUMNS,
            ),
            package_part_count=min(
                part_count,
                MAX_RESEARCH_XLSX_ENTRIES,
            ),
            content_sha256=digest,
            source_csv_sha256=_ZERO_DIGEST,
            schema_digest=schema.schema_digest,
            table_digest=_ZERO_DIGEST,
            result_code="invalid_research_xlsx",
        )
    return ResearchXlsxInspection(
        structurally_valid=True,
        row_count=row_count,
        column_count=column_count,
        cell_count=cell_count,
        package_part_count=part_count,
        content_sha256=digest,
        source_csv_sha256=hashlib.sha256(csv_content).hexdigest(),
        schema_digest=schema.schema_digest,
        table_digest=_table_digest(rows),
        result_code="research_xlsx_complete",
    )


def validate_safe_xlsx_package(content: bytes) -> None:
    """Reject any XLSX outside Clicky's closed, canonical workbook profile."""

    if (
        not isinstance(content, bytes)
        or not content
        or len(content) > MAX_RESEARCH_XLSX_BYTES
    ):
        raise ResearchXlsxError("Research XLSX package size is invalid")
    try:
        rows, _ = _extract_canonical_rows(content)
    except (ET.ParseError, OSError, zipfile.BadZipFile) as exc:
        raise ResearchXlsxError(
            "Research XLSX package is malformed"
        ) from exc
    _validate_table(rows)
    schema = ResearchCsvSchema.from_columns(tuple(rows[0]))
    requested_rows = len(rows) - 1
    if requested_rows < 1:
        raise ResearchXlsxError("Research XLSX package has no data rows")
    csv_content = _write_csv_rows(rows)
    if not inspect_research_csv(
        csv_content,
        schema,
        requested_rows=requested_rows,
        maximum_bytes=MAX_RESEARCH_BYTES,
    ).complete:
        raise ResearchXlsxError(
            "Research XLSX package table is not canonical"
        )


def safe_xlsx_table_preview(
    content: bytes,
    *,
    maximum_rows: int = 5,
    maximum_cell_chars: int = 160,
) -> str:
    """Return a bounded approval preview after full safe-package validation."""

    _bounded_integer(maximum_rows, 1, 10, "Research XLSX preview row limit")
    _bounded_integer(
        maximum_cell_chars,
        32,
        512,
        "Research XLSX preview cell limit",
    )
    validate_safe_xlsx_package(content)
    rows, _ = _extract_canonical_rows(content)

    def clipped(value: str) -> str:
        if len(value) <= maximum_cell_chars:
            return value
        return value[: maximum_cell_chars - 1] + "…"

    payload = {
        "columns": [clipped(value) for value in rows[0]],
        "representative_rows": [
            [clipped(value) for value in row]
            for row in rows[1 : maximum_rows + 1]
        ],
        "row_count": len(rows) - 1,
        "truncated": len(rows) - 1 > maximum_rows,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _extract_canonical_rows(
    content: bytes,
) -> tuple[tuple[tuple[str, ...], ...], int]:
    with zipfile.ZipFile(io.BytesIO(content), "r") as package:
        infos = package.infolist()
        if (
            len(infos) != MAX_RESEARCH_XLSX_ENTRIES
            or tuple(info.filename for info in infos) != _REQUIRED_PARTS
            or len({info.filename for info in infos}) != len(infos)
        ):
            raise ResearchXlsxError("research_xlsx_parts")
        total = 0
        parts: dict[str, bytes] = {}
        for info in infos:
            if (
                info.is_dir()
                or info.flag_bits & 0x1
                or info.compress_type != zipfile.ZIP_STORED
                or info.date_time != _FIXED_ZIP_TIME
                or info.file_size > MAX_RESEARCH_XLSX_PART_BYTES
                or info.compress_size != info.file_size
            ):
                raise ResearchXlsxError("research_xlsx_zip_metadata")
            total += info.file_size
            if total > MAX_RESEARCH_XLSX_UNCOMPRESSED_BYTES:
                raise ResearchXlsxError("research_xlsx_uncompressed_size")
            parts[info.filename] = package.read(info)
        if package.comment:
            raise ResearchXlsxError("research_xlsx_zip_comment")
    for name, part in parts.items():
        if name.endswith(".xml") or name.endswith(".rels"):
            lowered = part.lower()
            if any(marker in lowered for marker in _DANGEROUS_XML):
                raise ResearchXlsxError("research_xlsx_xml_entity")
    rows = _parse_sheet(parts["xl/worksheets/sheet1.xml"])
    if content != _serialize_xlsx(rows):
        raise ResearchXlsxError("research_xlsx_not_canonical")
    return rows, len(parts)


def _parse_sheet(content: bytes) -> tuple[tuple[str, ...], ...]:
    root = ET.fromstring(content)
    if root.tag != f"{{{_SPREADSHEET_NS}}}worksheet" or root.attrib:
        raise ResearchXlsxError("research_xlsx_worksheet")
    children = list(root)
    if len(children) != 1 or children[0].tag != (
        f"{{{_SPREADSHEET_NS}}}sheetData"
    ):
        raise ResearchXlsxError("research_xlsx_sheet_data")
    sheet_data = children[0]
    if sheet_data.attrib:
        raise ResearchXlsxError("research_xlsx_sheet_data")
    rows: list[tuple[str, ...]] = []
    for expected_row, row in enumerate(list(sheet_data), start=1):
        if (
            row.tag != f"{{{_SPREADSHEET_NS}}}row"
            or row.attrib != {"r": str(expected_row)}
        ):
            raise ResearchXlsxError("research_xlsx_row")
        values: list[str] = []
        for expected_column, cell in enumerate(list(row), start=1):
            reference = f"{_column_name(expected_column)}{expected_row}"
            expected_attributes = {"r": reference, "t": "inlineStr"}
            if expected_row == 1:
                expected_attributes["s"] = "1"
            if (
                cell.tag != f"{{{_SPREADSHEET_NS}}}c"
                or cell.attrib != expected_attributes
            ):
                raise ResearchXlsxError("research_xlsx_cell")
            cell_children = list(cell)
            if (
                len(cell_children) != 1
                or cell_children[0].tag
                != f"{{{_SPREADSHEET_NS}}}is"
                or cell_children[0].attrib
            ):
                raise ResearchXlsxError("research_xlsx_inline_string")
            text_nodes = list(cell_children[0])
            if (
                len(text_nodes) != 1
                or text_nodes[0].tag != f"{{{_SPREADSHEET_NS}}}t"
                or text_nodes[0].attrib
            ):
                raise ResearchXlsxError("research_xlsx_text")
            values.append(text_nodes[0].text or "")
        rows.append(tuple(values))
    return tuple(rows)


def _serialize_xlsx(rows: tuple[tuple[str, ...], ...]) -> bytes:
    worksheet = _worksheet_xml(rows)
    parts = (
        ("[Content_Types].xml", _CONTENT_TYPES_XML),
        ("_rels/.rels", _ROOT_RELS_XML),
        ("docProps/core.xml", _CORE_XML),
        ("docProps/app.xml", _APP_XML),
        ("xl/workbook.xml", _WORKBOOK_XML),
        ("xl/_rels/workbook.xml.rels", _WORKBOOK_RELS_XML),
        ("xl/styles.xml", _STYLES_XML),
        ("xl/worksheets/sheet1.xml", worksheet),
    )
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
    ) as package:
        for name, content in parts:
            info = zipfile.ZipInfo(name, _FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o600 << 16
            package.writestr(info, content)
    return output.getvalue()


def _worksheet_xml(rows: tuple[tuple[str, ...], ...]) -> bytes:
    rendered_rows: list[str] = []
    for row_number, row in enumerate(rows, start=1):
        cells: list[str] = []
        for column_number, value in enumerate(row, start=1):
            attributes = (
                f' r="{_column_name(column_number)}{row_number}"'
                ' t="inlineStr"'
            )
            if row_number == 1:
                attributes += ' s="1"'
            cells.append(
                f"<c{attributes}><is><t>{escape(value)}</t></is></c>"
            )
        rendered_rows.append(
            f'<row r="{row_number}">{"".join(cells)}</row>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{_SPREADSHEET_NS}"><sheetData>'
        f'{"".join(rendered_rows)}</sheetData></worksheet>'
    ).encode("utf-8")


def _validate_table(rows: tuple[tuple[str, ...], ...]) -> None:
    if (
        not isinstance(rows, tuple)
        or not 2 <= len(rows) <= MAX_RESEARCH_ROWS + 1
        or not isinstance(rows[0], tuple)
        or not 7 <= len(rows[0]) <= MAX_RESEARCH_CSV_COLUMNS
    ):
        raise ResearchXlsxError("Research XLSX table dimensions are invalid")
    width = len(rows[0])
    for row in rows:
        if not isinstance(row, tuple) or len(row) != width:
            raise ResearchXlsxError("Research XLSX row width is invalid")
        for cell in row:
            if (
                not isinstance(cell, str)
                or not cell
                or len(cell) > MAX_RESEARCH_XLSX_CELL_CHARS
                or _ILLEGAL_XML.search(cell) is not None
                or _FORMULA_PREFIX.match(cell) is not None
            ):
                raise ResearchXlsxError("Research XLSX cell is unsafe")


def _read_csv_rows(content: bytes) -> tuple[tuple[str, ...], ...]:
    try:
        text = content.decode("utf-8")
        return tuple(
            tuple(row)
            for row in csv.reader(io.StringIO(text, newline=""))
        )
    except (UnicodeDecodeError, csv.Error) as exc:
        raise ResearchXlsxError("Research XLSX source CSV is invalid") from exc


def _write_csv_rows(rows: tuple[tuple[str, ...], ...]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(
        output,
        dialect="excel",
        lineterminator="\r\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def _table_digest(rows: tuple[tuple[str, ...], ...]) -> str:
    payload = json.dumps(
        rows,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _column_name(number: int) -> str:
    _bounded_integer(
        number,
        1,
        MAX_RESEARCH_CSV_COLUMNS,
        "Research XLSX column index",
    )
    value = number
    result = ""
    while value:
        value, remainder = divmod(value - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _bounded_integer(value: int, minimum: int, maximum: int, label: str) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchXlsxError(f"{label} is invalid")


_CONTENT_TYPES_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    b'<Default Extension="xml" ContentType="application/xml"/>'
    b'<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
    b'<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
    b'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    b'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
    b'<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
    b"</Types>"
)
_ROOT_RELS_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
    b'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
    b'<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>'
    b"</Relationships>"
)
_CORE_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
    b'xmlns:dc="http://purl.org/dc/elements/1.1/" '
    b'xmlns:dcterms="http://purl.org/dc/terms/" '
    b'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    b"<dc:creator>Clicky</dc:creator>"
    b"<cp:lastModifiedBy>Clicky</cp:lastModifiedBy>"
    b'<dcterms:created xsi:type="dcterms:W3CDTF">2000-01-01T00:00:00Z</dcterms:created>'
    b'<dcterms:modified xsi:type="dcterms:W3CDTF">2000-01-01T00:00:00Z</dcterms:modified>'
    b"</cp:coreProperties>"
)
_APP_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
    b'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
    b"<Application>Clicky</Application>"
    b"<AppVersion>1.0</AppVersion>"
    b"</Properties>"
)
_WORKBOOK_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
    b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
    b'<sheets><sheet name="Research" sheetId="1" state="visible" r:id="rId1"/></sheets>'
    b"</workbook>"
)
_WORKBOOK_RELS_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    b'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
    b'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    b"</Relationships>"
)
_STYLES_XML = (
    b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    b'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
    b'<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
    b'<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
    b'<fills count="2"><fill><patternFill patternType="none"/></fill>'
    b'<fill><patternFill patternType="gray125"/></fill></fills>'
    b'<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
    b'<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
    b'<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
    b'<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
    b'<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
    b"</styleSheet>"
)
