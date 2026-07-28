"""Provider-neutral contracts for exporting one verified local CSV table.

The trusted task broker uses these models before any Google adapter receives
authority.  They deliberately contain no credentials, endpoints, or provider
SDK objects.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from dataclasses import dataclass, field


MAX_SHEETS_PROVIDER_REQUESTS = 6
MAX_SHEETS_SOURCE_BYTES = 8 * 1024 * 1024
MAX_SHEETS_PROVIDER_RESPONSE_BYTES = 9 * 1024 * 1024
MAX_SHEETS_PROVIDER_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_SHEETS_DATA_ROWS = 100
MAX_SHEETS_COLUMNS = 63
MAX_SHEETS_CELL_CHARS = 50_000
MAX_SHEETS_COLUMN_CHARS = 256
MAX_SHEETS_TITLE_CHARS = 255
MAX_SHEETS_IDEMPOTENCY_KEY_CHARS = 128
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SheetsTableValidationError(ValueError):
    """The local artifact is not a bounded, rectangular CSV table."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Sheets value is not canonical JSON") from exc


def validate_sheets_title(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value.strip() != value
        or len(value) > MAX_SHEETS_TITLE_CHARS
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Google Sheets title is invalid")
    return value


def validate_sheets_idempotency_key(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > MAX_SHEETS_IDEMPOTENCY_KEY_CHARS
        or _IDEMPOTENCY_KEY.fullmatch(value) is None
    ):
        raise ValueError("Google Sheets idempotency key is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ValidatedSheetTable:
    """Exact immutable cells revalidated from an adopted CSV artifact."""

    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...] = field(repr=False)
    source_sha256: str
    source_bytes: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.columns, tuple)
            or not 1 <= len(self.columns) <= MAX_SHEETS_COLUMNS
            or any(
                not isinstance(column, str)
                or not column
                or len(column) > MAX_SHEETS_COLUMN_CHARS
                or "\x00" in column
                or not column.isprintable()
                for column in self.columns
            )
            or len(set(self.columns)) != len(self.columns)
        ):
            raise SheetsTableValidationError(
                "Google Sheets columns are invalid"
            )
        if (
            not isinstance(self.rows, tuple)
            or not 1 <= len(self.rows) <= MAX_SHEETS_DATA_ROWS
        ):
            raise SheetsTableValidationError(
                "Google Sheets data row count is invalid"
            )
        for row in self.rows:
            if (
                not isinstance(row, tuple)
                or len(row) != len(self.columns)
                or all(not cell for cell in row)
                or any(
                    not isinstance(cell, str)
                    or len(cell) > MAX_SHEETS_CELL_CHARS
                    or "\x00" in cell
                    for cell in row
                )
            ):
                raise SheetsTableValidationError(
                    "Google Sheets data rows are invalid"
                )
        if (
            not isinstance(self.source_sha256, str)
            or _SHA256.fullmatch(self.source_sha256) is None
        ):
            raise SheetsTableValidationError(
                "Google Sheets source digest is invalid"
            )
        if (
            type(self.source_bytes) is not int
            or not 1 <= self.source_bytes <= MAX_SHEETS_SOURCE_BYTES
        ):
            raise SheetsTableValidationError(
                "Google Sheets source size is invalid"
            )

    @property
    def data_row_count(self) -> int:
        return len(self.rows)

    @property
    def column_count(self) -> int:
        return len(self.columns)

    @property
    def values(self) -> tuple[tuple[str, ...], ...]:
        return (self.columns, *self.rows)

    @property
    def provider_row_count(self) -> int:
        return 1 + self.data_row_count

    @property
    def a1_range(self) -> str:
        return (
            f"A1:{_column_name(self.column_count)}"
            f"{self.provider_row_count}"
        )

    def preview_bytes(
        self,
        *,
        authorization_id: str,
        title: str,
        idempotency_key: str,
    ) -> bytes:
        validate_sheets_title(title)
        validate_sheets_idempotency_key(idempotency_key)
        if (
            not isinstance(authorization_id, str)
            or not authorization_id
            or len(authorization_id) > 128
        ):
            raise ValueError(
                "Google Sheets account authorization ID is invalid"
            )
        return _canonical_json(
            {
                "columns": list(self.columns),
                "destination_account_authorization_id": authorization_id,
                "idempotency_key_sha256": hashlib.sha256(
                    idempotency_key.encode("utf-8")
                ).hexdigest(),
                "row_count": self.data_row_count,
                "source_bytes": self.source_bytes,
                "source_sha256": self.source_sha256,
                "title": title,
            }
        )


def parse_validated_sheet_csv(
    content: bytes,
    *,
    expected_sha256: str,
) -> ValidatedSheetTable:
    """Revalidate exact adopted bytes before any external write is approved."""

    if (
        not isinstance(content, bytes)
        or not 1 <= len(content) <= MAX_SHEETS_SOURCE_BYTES
        or not isinstance(expected_sha256, str)
        or _SHA256.fullmatch(expected_sha256) is None
        or hashlib.sha256(content).hexdigest() != expected_sha256
    ):
        raise SheetsTableValidationError(
            "Google Sheets source identity is invalid"
        )
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SheetsTableValidationError(
            "Google Sheets source must be UTF-8 CSV"
        ) from exc
    if not text or text.startswith("\ufeff") or "\x00" in text:
        raise SheetsTableValidationError(
            "Google Sheets source text is invalid"
        )
    try:
        parsed = tuple(
            tuple(cell for cell in row)
            for row in csv.reader(
                io.StringIO(text, newline=""),
                strict=True,
            )
        )
    except (csv.Error, UnicodeError) as exc:
        raise SheetsTableValidationError(
            "Google Sheets source CSV is malformed"
        ) from exc
    if not parsed:
        raise SheetsTableValidationError(
            "Google Sheets source CSV is empty"
        )
    return ValidatedSheetTable(
        columns=parsed[0],
        rows=parsed[1:],
        source_sha256=expected_sha256,
        source_bytes=len(content),
    )


def _column_name(column_count: int) -> str:
    if (
        type(column_count) is not int
        or not 1 <= column_count <= MAX_SHEETS_COLUMNS
    ):
        raise ValueError("Google Sheets column count is invalid")
    output = ""
    value = column_count
    while value:
        value, remainder = divmod(value - 1, 26)
        output = chr(65 + remainder) + output
    return output


__all__ = [
    "MAX_SHEETS_CELL_CHARS",
    "MAX_SHEETS_COLUMNS",
    "MAX_SHEETS_COLUMN_CHARS",
    "MAX_SHEETS_DATA_ROWS",
    "MAX_SHEETS_IDEMPOTENCY_KEY_CHARS",
    "MAX_SHEETS_PROVIDER_EVIDENCE_BYTES",
    "MAX_SHEETS_PROVIDER_REQUESTS",
    "MAX_SHEETS_PROVIDER_RESPONSE_BYTES",
    "MAX_SHEETS_SOURCE_BYTES",
    "MAX_SHEETS_TITLE_CHARS",
    "SheetsTableValidationError",
    "ValidatedSheetTable",
    "parse_validated_sheet_csv",
    "validate_sheets_idempotency_key",
    "validate_sheets_title",
]
