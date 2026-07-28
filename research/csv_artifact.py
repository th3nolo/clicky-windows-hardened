"""Deterministic rendering and bounded inspection of research CSV artifacts."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from research.models import (
    MAX_FIELD_ID_CHARS,
    MAX_RESEARCH_BYTES,
    MAX_RESEARCH_ROWS,
    MAX_SOURCES_PER_FIELD,
    ResearchBatch,
    ResearchField,
    ResearchLimits,
    ResearchRecord,
    ResearchValidationError,
    ResearchValue,
    canonicalize_public_url,
)


MAX_RESEARCH_CSV_FIELDS = 28
MAX_RESEARCH_CSV_COLUMNS = 2 * MAX_RESEARCH_CSV_FIELDS + 7
MAX_RESEARCH_CSV_CELL_CHARS = 64 * 1024
_FIELD_ID = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_FORMULA_PREFIX = re.compile(r"^[\t\r\n ]*[=+\-@]")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BASE_PREFIX = (
    "entity",
    "entity_sources",
    "public_url",
    "public_url_sources",
)
_BASE_SUFFIX = (
    "rationale",
    "rationale_sources",
    "retrieved_at",
)
_RECORD_FIELDS = frozenset(
    {"entity", "public_url", "rationale", "requested_fields"}
)
_VALUE_FIELDS = frozenset({"source_urls", "value"})


class ResearchCsvError(ValueError):
    """A research CSV schema, render request, or artifact is invalid."""


@dataclass(frozen=True, slots=True)
class ResearchCsvSchema:
    """Stable column order for one reviewed set of requested attributes."""

    requested_field_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.requested_field_ids, tuple)
            or len(self.requested_field_ids) > MAX_RESEARCH_CSV_FIELDS
        ):
            raise ResearchCsvError(
                "Research CSV requested fields are invalid"
            )
        for field_id in self.requested_field_ids:
            if (
                not isinstance(field_id, str)
                or len(field_id) > MAX_FIELD_ID_CHARS
                or _FIELD_ID.fullmatch(field_id) is None
                or field_id
                in {
                    "entity",
                    "public_url",
                    "rationale",
                    "retrieved_at",
                }
                or field_id.endswith("_sources")
            ):
                raise ResearchCsvError(
                    "Research CSV field ID is invalid"
                )
        if len(self.requested_field_ids) != len(
            set(self.requested_field_ids)
        ):
            raise ResearchCsvError(
                "Research CSV field IDs must be unique"
            )

    @property
    def columns(self) -> tuple[str, ...]:
        dynamic = tuple(
            column
            for field_id in self.requested_field_ids
            for column in (field_id, f"{field_id}_sources")
        )
        return (*_BASE_PREFIX, *dynamic, *_BASE_SUFFIX)

    @property
    def schema_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self.columns,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    @classmethod
    def from_columns(
        cls,
        columns: tuple[str, ...],
    ) -> ResearchCsvSchema:
        if (
            not isinstance(columns, tuple)
            or len(columns) < len(_BASE_PREFIX) + len(_BASE_SUFFIX)
            or columns[: len(_BASE_PREFIX)] != _BASE_PREFIX
            or columns[-len(_BASE_SUFFIX) :] != _BASE_SUFFIX
        ):
            raise ResearchCsvError(
                "Research CSV columns are not a supported schema"
            )
        dynamic = columns[
            len(_BASE_PREFIX) : -len(_BASE_SUFFIX)
        ]
        if len(dynamic) % 2:
            raise ResearchCsvError(
                "Research CSV dynamic columns are incomplete"
            )
        fields: list[str] = []
        for index in range(0, len(dynamic), 2):
            field_id = dynamic[index]
            if dynamic[index + 1] != f"{field_id}_sources":
                raise ResearchCsvError(
                    "Research CSV source columns are not paired"
                )
            fields.append(field_id)
        schema = cls(tuple(fields))
        if schema.columns != columns:
            raise ResearchCsvError(
                "Research CSV columns are not canonical"
            )
        return schema


@dataclass(frozen=True, slots=True)
class ResearchCsvArtifact:
    """Rendered bytes and truthful completeness metadata."""

    content: bytes = field(repr=False)
    sha256: str
    schema_digest: str
    row_count: int
    requested_rows: int
    complete: bool
    partial_reason: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content, bytes)
            or not 1 <= len(self.content) <= MAX_RESEARCH_BYTES
        ):
            raise ResearchCsvError("Research CSV content is invalid")
        digest = hashlib.sha256(self.content).hexdigest()
        if self.sha256 != digest:
            raise ResearchCsvError("Research CSV digest is invalid")
        for value, label in (
            (self.schema_digest, "schema"),
            (self.sha256, "content"),
        ):
            if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                raise ResearchCsvError(
                    f"Research CSV {label} digest is invalid"
                )
        _bounded_integer(
            self.requested_rows,
            1,
            MAX_RESEARCH_ROWS,
            "Research CSV requested row count",
        )
        _bounded_integer(
            self.row_count,
            0,
            self.requested_rows,
            "Research CSV row count",
        )
        if type(self.complete) is not bool:
            raise TypeError(
                "Research CSV completeness must be explicit"
            )
        if self.complete != (self.row_count == self.requested_rows):
            raise ResearchCsvError(
                "Research CSV completeness does not match its row count"
            )
        if self.complete:
            if self.partial_reason is not None:
                raise ResearchCsvError(
                    "Complete research CSV cannot have a partial reason"
                )
        elif self.partial_reason != (
            f"requested_rows_not_reached:{self.row_count}/"
            f"{self.requested_rows}"
        ):
            raise ResearchCsvError(
                "Partial research CSV reason is invalid"
            )


@dataclass(frozen=True, slots=True)
class ResearchCsvInspection:
    """Content-free validation result for verifier evidence."""

    structurally_valid: bool
    complete: bool
    partial: bool
    row_count: int
    requested_rows: int
    content_sha256: str
    schema_digest: str
    result_code: str

    def __post_init__(self) -> None:
        for value in (
            self.structurally_valid,
            self.complete,
            self.partial,
        ):
            if type(value) is not bool:
                raise TypeError(
                    "Research CSV inspection flags must be explicit"
                )
        _bounded_integer(
            self.requested_rows,
            1,
            MAX_RESEARCH_ROWS,
            "Research CSV inspected requested rows",
        )
        _bounded_integer(
            self.row_count,
            0,
            MAX_RESEARCH_ROWS,
            "Research CSV inspected row count",
        )
        if not isinstance(self.result_code, str) or self.result_code not in {
            "invalid_research_csv",
            "research_csv_complete",
            "research_csv_row_shortfall",
        }:
            raise ResearchCsvError(
                "Research CSV inspection result is invalid"
            )
        for digest in (self.content_sha256, self.schema_digest):
            if not isinstance(digest, str) or _SHA256.fullmatch(
                digest
            ) is None:
                raise ResearchCsvError(
                    "Research CSV inspection digest is invalid"
                )
        if self.complete and (
            not self.structurally_valid or self.partial
        ):
            raise ResearchCsvError(
                "Complete research CSV inspection is inconsistent"
            )
        if self.partial and (
            not self.structurally_valid
            or self.complete
            or self.row_count >= self.requested_rows
        ):
            raise ResearchCsvError(
                "Partial research CSV inspection is inconsistent"
            )


def render_research_csv(
    batch: ResearchBatch,
    schema: ResearchCsvSchema,
    *,
    requested_rows: int,
) -> ResearchCsvArtifact:
    """Render one canonical Excel-safe UTF-8 CSV using the stdlib writer."""

    if not isinstance(batch, ResearchBatch):
        raise TypeError("Research CSV rendering requires a typed batch")
    if not isinstance(schema, ResearchCsvSchema):
        raise TypeError("Research CSV rendering requires a typed schema")
    _bounded_integer(
        requested_rows,
        1,
        min(MAX_RESEARCH_ROWS, batch.limits.max_rows),
        "Research CSV requested row count",
    )
    if len(batch.records) > requested_rows:
        raise ResearchCsvError(
            "Research CSV contains more rows than requested"
        )

    rows: list[tuple[str, ...]] = [schema.columns]
    for record in batch.records:
        fields = {
            item.field_id: item.value
            for item in record.requested_fields
        }
        if tuple(fields) != schema.requested_field_ids:
            raise ResearchCsvError(
                "Research record fields do not match CSV schema"
            )
        row = [
            _excel_safe_text(record.entity.value),
            _source_cell(record.entity.source_urls),
            record.canonical_public_url,
            _source_cell(record.public_url.source_urls),
        ]
        for field_id in schema.requested_field_ids:
            value = fields[field_id]
            row.extend(
                (
                    _excel_safe_text(value.value),
                    _source_cell(value.source_urls),
                )
            )
        row.extend(
            (
                _excel_safe_text(record.rationale.value),
                _source_cell(record.rationale.source_urls),
                record.retrieved_at.isoformat(),
            )
        )
        rows.append(tuple(row))

    content = _write_rows(tuple(rows))
    maximum = min(batch.limits.max_output_bytes, MAX_RESEARCH_BYTES)
    if len(content) > maximum:
        raise ResearchCsvError("Research CSV output limit exceeded")
    row_count = len(batch.records)
    complete = row_count == requested_rows
    partial_reason = None
    if not complete:
        partial_reason = (
            f"requested_rows_not_reached:{row_count}/{requested_rows}"
        )
    return ResearchCsvArtifact(
        content=content,
        sha256=hashlib.sha256(content).hexdigest(),
        schema_digest=schema.schema_digest,
        row_count=row_count,
        requested_rows=requested_rows,
        complete=complete,
        partial_reason=partial_reason,
    )


def render_research_json_to_csv(
    records_json: str,
    schema: ResearchCsvSchema,
    *,
    requested_rows: int,
    maximum_output_bytes: int,
    allowed_source_urls: tuple[str, ...],
    retrieved_at: datetime | None = None,
) -> ResearchCsvArtifact:
    """Parse strict inert model JSON, bind sources, then render canonical CSV."""

    if (
        not isinstance(records_json, str)
        or not records_json
        or len(records_json.encode("utf-8")) > MAX_RESEARCH_BYTES
        or "\x00" in records_json
    ):
        raise ResearchCsvError("Research record JSON is invalid")
    if not isinstance(schema, ResearchCsvSchema):
        raise TypeError("Research JSON rendering requires a typed schema")
    _bounded_integer(
        requested_rows,
        1,
        MAX_RESEARCH_ROWS,
        "Research JSON requested row count",
    )
    _bounded_integer(
        maximum_output_bytes,
        1,
        MAX_RESEARCH_BYTES,
        "Research JSON output limit",
    )
    if (
        not isinstance(allowed_source_urls, tuple)
        or not 1 <= len(allowed_source_urls) <= 64
    ):
        raise ResearchCsvError(
            "Research JSON needs bounded observed sources"
        )
    allowed = tuple(
        canonicalize_public_url(url, require_https=True)
        for url in allowed_source_urls
    )
    if len(allowed) != len(set(allowed)):
        raise ResearchCsvError(
            "Observed research sources must be unique"
        )
    timestamp = retrieved_at or datetime.now(timezone.utc)
    if (
        not isinstance(timestamp, datetime)
        or timestamp.tzinfo is None
        or timestamp.utcoffset() is None
    ):
        raise ResearchCsvError(
            "Research JSON retrieval time must be timezone-aware"
        )
    try:
        payload = json.loads(
            records_json,
            object_pairs_hook=_reject_duplicate_json_fields,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError, ResearchCsvError) as exc:
        raise ResearchCsvError(
            "Research record JSON is malformed"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"records"}
        or not isinstance(payload["records"], list)
        or len(payload["records"]) > requested_rows
    ):
        raise ResearchCsvError(
            "Research record JSON envelope is invalid"
        )
    try:
        records = tuple(
            _record_from_json(
                item,
                schema=schema,
                allowed_sources=frozenset(allowed),
                retrieved_at=timestamp,
            )
            for item in payload["records"]
        )
    except ResearchValidationError as exc:
        raise ResearchCsvError(
            "Research record JSON contains invalid sourced values"
        ) from exc
    limits = ResearchLimits(
        max_rows=requested_rows,
        max_fields_per_record=len(schema.requested_field_ids),
        max_sources_per_record=64,
        max_total_sources=min(2_048, max(1, len(allowed))),
        max_output_bytes=maximum_output_bytes,
    )
    return render_research_csv(
        ResearchBatch(records, limits),
        schema,
        requested_rows=requested_rows,
    )


def inspect_research_csv(
    content: bytes,
    schema: ResearchCsvSchema,
    *,
    requested_rows: int,
    maximum_bytes: int,
) -> ResearchCsvInspection:
    """Inspect bounded bytes without returning any research cell contents."""

    if not isinstance(content, bytes):
        raise TypeError("Research CSV inspection requires immutable bytes")
    if not isinstance(schema, ResearchCsvSchema):
        raise TypeError("Research CSV inspection requires a typed schema")
    _bounded_integer(
        requested_rows,
        1,
        MAX_RESEARCH_ROWS,
        "Research CSV requested row count",
    )
    _bounded_integer(
        maximum_bytes,
        1,
        MAX_RESEARCH_BYTES,
        "Research CSV verification byte limit",
    )
    digest = hashlib.sha256(content).hexdigest()
    row_count = 0
    try:
        if not content or len(content) > maximum_bytes:
            raise ResearchCsvError("research_csv_size")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ResearchCsvError("research_csv_utf8") from exc
        if "\x00" in text:
            raise ResearchCsvError("research_csv_null")
        try:
            rows = tuple(csv.reader(io.StringIO(text, newline="")))
        except (csv.Error, UnicodeError) as exc:
            raise ResearchCsvError("research_csv_parse") from exc
        if not rows or tuple(rows[0]) != schema.columns:
            raise ResearchCsvError("research_csv_schema")
        if len(rows[0]) > MAX_RESEARCH_CSV_COLUMNS:
            raise ResearchCsvError("research_csv_columns")
        data_rows = rows[1:]
        row_count = len(data_rows)
        if row_count > requested_rows:
            raise ResearchCsvError("research_csv_extra_rows")
        if _write_rows(rows) != content:
            raise ResearchCsvError("research_csv_not_canonical")
        canonical_urls: set[str] = set()
        for row in data_rows:
            _validate_row(row, schema, canonical_urls)
    except (ResearchCsvError, ResearchValidationError):
        return ResearchCsvInspection(
            structurally_valid=False,
            complete=False,
            partial=False,
            row_count=min(row_count, MAX_RESEARCH_ROWS),
            requested_rows=requested_rows,
            content_sha256=digest,
            schema_digest=schema.schema_digest,
            result_code="invalid_research_csv",
        )

    complete = row_count == requested_rows
    return ResearchCsvInspection(
        structurally_valid=True,
        complete=complete,
        partial=not complete,
        row_count=row_count,
        requested_rows=requested_rows,
        content_sha256=digest,
        schema_digest=schema.schema_digest,
        result_code=(
            "research_csv_complete"
            if complete
            else "research_csv_row_shortfall"
        ),
    )


def _validate_row(
    row: tuple[str, ...] | list[str],
    schema: ResearchCsvSchema,
    canonical_urls: set[str],
) -> None:
    if len(row) != len(schema.columns):
        raise ResearchCsvError("research_csv_row_width")
    if any(
        not isinstance(cell, str)
        or not cell
        or len(cell) > MAX_RESEARCH_CSV_CELL_CHARS
        for cell in row
    ):
        raise ResearchCsvError("research_csv_required_cell")
    if any(_FORMULA_PREFIX.match(cell) for cell in row):
        raise ResearchCsvError("research_csv_formula")

    public_url = canonicalize_public_url(row[2])
    if public_url != row[2] or public_url in canonical_urls:
        raise ResearchCsvError("research_csv_duplicate_url")
    canonical_urls.add(public_url)

    source_indexes = [1, 3]
    source_indexes.extend(
        5 + (index * 2)
        for index in range(len(schema.requested_field_ids))
    )
    source_indexes.append(len(row) - 2)
    for index in source_indexes:
        _validate_source_cell(row[index])

    retrieved_at = row[-1]
    try:
        timestamp = datetime.fromisoformat(retrieved_at)
    except ValueError as exc:
        raise ResearchCsvError("research_csv_retrieval_time") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ResearchCsvError("research_csv_retrieval_time")


def _source_cell(urls: tuple[str, ...]) -> str:
    if (
        not isinstance(urls, tuple)
        or not 1 <= len(urls) <= MAX_SOURCES_PER_FIELD
    ):
        raise ResearchCsvError(
            "Research CSV source references are invalid"
        )
    canonical = tuple(canonicalize_public_url(url) for url in urls)
    if len(canonical) != len(set(canonical)):
        raise ResearchCsvError(
            "Research CSV source references are duplicated"
        )
    return json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _record_from_json(
    value: object,
    *,
    schema: ResearchCsvSchema,
    allowed_sources: frozenset[str],
    retrieved_at: datetime,
) -> ResearchRecord:
    if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
        raise ResearchCsvError("Research JSON record fields are invalid")
    requested = value["requested_fields"]
    if (
        not isinstance(requested, dict)
        or set(requested) != set(schema.requested_field_ids)
    ):
        raise ResearchCsvError(
            "Research JSON requested fields do not match the schema"
        )
    entity = _value_from_json(
        value["entity"],
        allowed_sources=allowed_sources,
    )
    public_url = _value_from_json(
        value["public_url"],
        allowed_sources=allowed_sources,
    )
    canonical_public_url = canonicalize_public_url(
        public_url.value,
        require_https=True,
    )
    if (
        canonical_public_url != public_url.value
        or canonical_public_url not in allowed_sources
    ):
        raise ResearchCsvError(
            "Research JSON public URL was not observed"
        )
    rationale = _value_from_json(
        value["rationale"],
        allowed_sources=allowed_sources,
    )
    fields = tuple(
        ResearchField(
            field_id,
            _value_from_json(
                requested[field_id],
                allowed_sources=allowed_sources,
            ),
        )
        for field_id in schema.requested_field_ids
    )
    return ResearchRecord(
        entity=entity,
        public_url=public_url,
        requested_fields=fields,
        rationale=rationale,
        retrieved_at=retrieved_at,
    )


def _value_from_json(
    value: object,
    *,
    allowed_sources: frozenset[str],
) -> ResearchValue:
    if not isinstance(value, dict) or set(value) != _VALUE_FIELDS:
        raise ResearchCsvError(
            "Research JSON factual value is invalid"
        )
    sources = value["source_urls"]
    if (
        not isinstance(sources, list)
        or any(not isinstance(source, str) for source in sources)
    ):
        raise ResearchCsvError(
            "Research JSON factual sources are invalid"
        )
    typed = ResearchValue(
        value["value"],
        tuple(sources),
    )
    if not set(typed.source_urls).issubset(allowed_sources):
        raise ResearchCsvError(
            "Research JSON cites an unobserved source"
        )
    return typed


def _reject_duplicate_json_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ResearchCsvError(
                "Research JSON contains duplicate fields"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str):
    raise ResearchCsvError(
        f"Research JSON constant is invalid: {value}"
    )


def _validate_source_cell(value: str) -> None:
    try:
        sources = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ResearchCsvError("research_csv_source_json") from exc
    if (
        not isinstance(sources, list)
        or not 1 <= len(sources) <= MAX_SOURCES_PER_FIELD
        or any(not isinstance(source, str) for source in sources)
    ):
        raise ResearchCsvError("research_csv_source_count")
    canonical = tuple(canonicalize_public_url(source) for source in sources)
    if list(canonical) != sources or len(canonical) != len(set(canonical)):
        raise ResearchCsvError("research_csv_source_url")


def _excel_safe_text(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResearchCsvError("Research CSV factual value is invalid")
    return "'" + value if _FORMULA_PREFIX.match(value) else value


def _write_rows(rows: tuple[tuple[str, ...], ...]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(
        stream,
        dialect="excel",
        lineterminator="\r\n",
        quoting=csv.QUOTE_MINIMAL,
    )
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _bounded_integer(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResearchCsvError(f"{label} is invalid")


__all__ = [
    "MAX_RESEARCH_CSV_FIELDS",
    "ResearchCsvArtifact",
    "ResearchCsvError",
    "ResearchCsvInspection",
    "ResearchCsvSchema",
    "inspect_research_csv",
    "render_research_csv",
    "render_research_json_to_csv",
]
