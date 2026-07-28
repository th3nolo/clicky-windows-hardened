"""Least-privilege export of one verified local CSV to Google Sheets.

The adapter can only create a private spreadsheet file owned by the selected
account, replace the exact A1 range with RAW string values, and read that same
file and range back.  It exposes no file search, sharing, append, delete, or
arbitrary-range surface.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, Protocol

from capability_registry import CapabilityId, ConnectorId
from connectors.base import (
    ConnectedAccount,
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorCallResult,
    ConnectorError,
    ConnectorExecution,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenExpiredError,
    SecretValue,
    validate_connector_authority,
)
from sheets_contracts import (
    MAX_SHEETS_COLUMNS,
    MAX_SHEETS_COLUMN_CHARS,
    MAX_SHEETS_DATA_ROWS,
    MAX_SHEETS_PROVIDER_EVIDENCE_BYTES,
    MAX_SHEETS_PROVIDER_REQUESTS,
    MAX_SHEETS_PROVIDER_RESPONSE_BYTES,
    ValidatedSheetTable,
    validate_sheets_idempotency_key,
    validate_sheets_title,
)


GOOGLE_DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
GOOGLE_SHEETS_API_ROOT = "https://sheets.googleapis.com/v4/spreadsheets"
GOOGLE_SHEETS_MIME_TYPE = "application/vnd.google-apps.spreadsheet"
GOOGLE_SHEETS_EXPORT_OPERATION_ID = "google_sheets.export_validated_table"
MAX_SHEETS_RESPONSE_BYTES = MAX_SHEETS_PROVIDER_RESPONSE_BYTES
MAX_SHEETS_REQUEST_BYTES = 9 * 1024 * 1024
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_A1_RANGE = re.compile(r"^A1:[A-Z]{1,3}[1-9][0-9]{0,3}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_APP_PROPERTY_KEYS = frozenset(
    {
        "clickyExportId",
        "clickyRequestSha256",
        "clickySourceSha256",
    }
)


class GoogleSheetsExportOutcomeUnknownError(ConnectorRequestError):
    """A mutation might have succeeded; automatic creation is unsafe."""


class GoogleSheetsExportVerificationError(ConnectorResponseError):
    """The provider mutation did not pass exact metadata/value read-back."""


class GoogleSheetsIdempotencyConflictError(ConnectorResponseError):
    """An idempotency key already names a different or ambiguous export."""


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
        raise ValueError("Google Sheets value is not canonical JSON") from exc


def _provider_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or _PROVIDER_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class GoogleSheetsExportRequest:
    """One exact table export bound to a recoverable idempotency key."""

    title: str
    table: ValidatedSheetTable = field(repr=False)
    idempotency_key: str = field(repr=False)
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_SHEETS,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.SHEETS_VALUES_WRITE,
        init=False,
    )
    operation_id: str = field(
        default=GOOGLE_SHEETS_EXPORT_OPERATION_ID,
        init=False,
    )
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        validate_sheets_title(self.title)
        if not isinstance(self.table, ValidatedSheetTable):
            raise TypeError("Google Sheets export table is invalid")
        validate_sheets_idempotency_key(self.idempotency_key)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "columns": list(self.table.columns),
                        "idempotency_key_sha256": self.export_id,
                        "row_count": self.table.data_row_count,
                        "source_bytes": self.table.source_bytes,
                        "source_sha256": self.table.source_sha256,
                        "title": self.title,
                    }
                )
            ).hexdigest(),
        )

    @property
    def export_id(self) -> str:
        return hashlib.sha256(
            self.idempotency_key.encode("utf-8")
        ).hexdigest()

    @property
    def app_properties(self) -> dict[str, str]:
        return {
            "clickyExportId": self.export_id,
            "clickyRequestSha256": self.request_digest,
            "clickySourceSha256": self.table.source_sha256,
        }

    def create_payload(self) -> dict[str, object]:
        return {
            "appProperties": self.app_properties,
            "mimeType": GOOGLE_SHEETS_MIME_TYPE,
            "name": self.title,
        }

    def values_payload(self) -> dict[str, object]:
        return {
            "majorDimension": "ROWS",
            "range": self.table.a1_range,
            "values": [list(row) for row in self.table.values],
        }


@dataclass(frozen=True, slots=True)
class GoogleSheetsExportResult:
    spreadsheet_id: str
    title: str
    spreadsheet_url: str
    columns: tuple[str, ...]
    row_count: int
    column_count: int
    source_sha256: str
    idempotency_status: str
    provider_request_ids: tuple[str, ...] = ()
    verified: bool = True

    def __post_init__(self) -> None:
        _provider_id(self.spreadsheet_id, "Google spreadsheet ID")
        validate_sheets_title(self.title)
        if (
            not isinstance(self.columns, tuple)
            or not self.columns
            or len(self.columns) > MAX_SHEETS_COLUMNS
            or len(self.columns) != self.column_count
            or len(set(self.columns)) != len(self.columns)
            or any(
                not isinstance(column, str)
                or not column
                or len(column) > MAX_SHEETS_COLUMN_CHARS
                or "\x00" in column
                or not column.isprintable()
                for column in self.columns
            )
        ):
            raise ValueError("Google Sheets result columns are invalid")
        if (
            type(self.row_count) is not int
            or not 1 <= self.row_count <= MAX_SHEETS_DATA_ROWS
            or type(self.column_count) is not int
            or not 1 <= self.column_count <= MAX_SHEETS_COLUMNS
        ):
            raise ValueError("Google Sheets result shape is invalid")
        if (
            not isinstance(self.source_sha256, str)
            or _SHA256.fullmatch(self.source_sha256) is None
        ):
            raise ValueError("Google Sheets result source digest is invalid")
        if self.idempotency_status not in {
            "created",
            "recovered_empty",
            "recovered_verified",
        }:
            raise ValueError(
                "Google Sheets idempotency status is invalid"
            )
        _verified_spreadsheet_url(
            self.spreadsheet_url,
            self.spreadsheet_id,
        )
        if (
            not isinstance(self.provider_request_ids, tuple)
            or len(self.provider_request_ids)
            > MAX_SHEETS_PROVIDER_REQUESTS
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 256
                or "\x00" in item
                or not item.isprintable()
                for item in self.provider_request_ids
            )
        ):
            raise ValueError(
                "Google Sheets provider request evidence is invalid"
            )
        if self.verified is not True:
            raise ValueError(
                "Google Sheets export requires read-back verification"
            )

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "column_count": self.column_count,
                "columns": list(self.columns),
                "idempotency_status": self.idempotency_status,
                "provider_request_ids": list(self.provider_request_ids),
                "row_count": self.row_count,
                "source_sha256": self.source_sha256,
                "spreadsheet_id": self.spreadsheet_id,
                "spreadsheet_url": self.spreadsheet_url,
                "title": self.title,
                "verified": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SheetsHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Google Sheets HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Google Sheets content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_SHEETS_RESPONSE_BYTES
        ):
            raise ValueError("Google Sheets response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Google Sheets retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError(
                "Google Sheets provider request ID is invalid"
            )


class SheetsHttpTransport(Protocol):
    def list_exports(
        self,
        *,
        export_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse: ...

    def create_spreadsheet(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse: ...

    def update_values(
        self,
        *,
        spreadsheet_id: str,
        a1_range: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse: ...

    def get_spreadsheet(
        self,
        *,
        spreadsheet_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse: ...

    def get_values(
        self,
        *,
        spreadsheet_id: str,
        a1_range: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleSheetsHttpsTransport:
    """Fixed Drive/Sheets hosts, bounded bodies, no proxies or redirects."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 15.0,
        _opener=None,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0.01 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("Google Sheets request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def list_exports(
        self,
        *,
        export_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse:
        if not isinstance(export_id, str) or _SHA256.fullmatch(
            export_id
        ) is None:
            raise ValueError("Google Sheets export lookup ID is invalid")
        query = (
            "appProperties has { key='clickyExportId' and "
            f"value='{export_id}' }} and "
            f"mimeType = '{GOOGLE_SHEETS_MIME_TYPE}' and trashed = false"
        )
        endpoint = GOOGLE_DRIVE_FILES_ENDPOINT + "?" + urllib.parse.urlencode(
            {
                "corpora": "user",
                "fields": (
                    "files(id,name,mimeType,appProperties),"
                    "incompleteSearch,nextPageToken"
                ),
                "pageSize": "2",
                "q": query,
                "spaces": "drive",
            },
            quote_via=urllib.parse.quote,
        )
        return self._request(
            endpoint=endpoint,
            method="GET",
            body=None,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=False,
        )

    def create_spreadsheet(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse:
        encoded = _request_body(payload)
        endpoint = GOOGLE_DRIVE_FILES_ENDPOINT + "?" + urllib.parse.urlencode(
            {
                "fields": "id,name,mimeType,appProperties",
                "ignoreDefaultVisibility": "true",
            }
        )
        return self._request(
            endpoint=endpoint,
            method="POST",
            body=encoded,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=True,
        )

    def update_values(
        self,
        *,
        spreadsheet_id: str,
        a1_range: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse:
        spreadsheet_id = _provider_id(
            spreadsheet_id,
            "Google spreadsheet ID",
        )
        if not isinstance(a1_range, str) or _A1_RANGE.fullmatch(
            a1_range
        ) is None:
            raise ValueError("Google Sheets A1 range is invalid")
        encoded_id = urllib.parse.quote(spreadsheet_id, safe="")
        encoded_range = urllib.parse.quote(a1_range, safe="")
        endpoint = (
            f"{GOOGLE_SHEETS_API_ROOT}/{encoded_id}/values/{encoded_range}?"
            + urllib.parse.urlencode(
                {
                    "includeValuesInResponse": "false",
                    "valueInputOption": "RAW",
                }
            )
        )
        return self._request(
            endpoint=endpoint,
            method="PUT",
            body=_request_body(payload),
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=True,
        )

    def get_spreadsheet(
        self,
        *,
        spreadsheet_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse:
        spreadsheet_id = _provider_id(
            spreadsheet_id,
            "Google spreadsheet ID",
        )
        encoded_id = urllib.parse.quote(spreadsheet_id, safe="")
        endpoint = (
            f"{GOOGLE_SHEETS_API_ROOT}/{encoded_id}?"
            + urllib.parse.urlencode(
                {
                    "fields": (
                        "spreadsheetId,properties(title),spreadsheetUrl,"
                        "sheets(properties(sheetId,title,index,sheetType,"
                        "gridProperties(rowCount,columnCount)))"
                    ),
                    "includeGridData": "false",
                }
            )
        )
        return self._request(
            endpoint=endpoint,
            method="GET",
            body=None,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=False,
        )

    def get_values(
        self,
        *,
        spreadsheet_id: str,
        a1_range: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SheetsHttpResponse:
        spreadsheet_id = _provider_id(
            spreadsheet_id,
            "Google spreadsheet ID",
        )
        if not isinstance(a1_range, str) or _A1_RANGE.fullmatch(
            a1_range
        ) is None:
            raise ValueError("Google Sheets A1 range is invalid")
        encoded_id = urllib.parse.quote(spreadsheet_id, safe="")
        encoded_range = urllib.parse.quote(a1_range, safe="")
        endpoint = (
            f"{GOOGLE_SHEETS_API_ROOT}/{encoded_id}/values/{encoded_range}?"
            + urllib.parse.urlencode(
                {
                    "dateTimeRenderOption": "SERIAL_NUMBER",
                    "majorDimension": "ROWS",
                    "valueRenderOption": "UNFORMATTED_VALUE",
                }
            )
        )
        return self._request(
            endpoint=endpoint,
            method="GET",
            body=None,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=False,
        )

    def _request(
        self,
        *,
        endpoint: str,
        method: str,
        body: bytes | None,
        access_token: SecretValue,
        maximum_response_bytes: int,
        mutation: bool,
    ) -> SheetsHttpResponse:
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Sheets access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1
            <= maximum_response_bytes
            <= MAX_SHEETS_RESPONSE_BYTES
        ):
            raise ValueError("Google Sheets response limit is invalid")
        _validate_fixed_endpoint(endpoint, method)
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Google Sheets access token encoding is invalid"
                ) from exc
            headers = {
                "Accept": "application/json",
                "Authorization": authorization,
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Sheets/1",
            }
            if body is not None:
                headers["Content-Type"] = "application/json; charset=utf-8"
            request = urllib.request.Request(
                endpoint,
                data=body,
                method=method,
                headers=headers,
            )
            try:
                try:
                    response = self._opener.open(
                        request,
                        timeout=self._timeout,
                    )
                except urllib.error.HTTPError as exc:
                    response = exc
                with response:
                    return _bounded_http_response(
                        response,
                        maximum_response_bytes,
                    )
            except ConnectorResponseError:
                raise
            except (OSError, urllib.error.URLError) as exc:
                error_type = (
                    GoogleSheetsExportOutcomeUnknownError
                    if mutation
                    else ConnectorRequestError
                )
                raise error_type(
                    "Google Sheets provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleSheetsExportAdapter:
    """Create once, recover by app property, and verify metadata plus values."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_SHEETS

    def __init__(
        self,
        account: ConnectedAccount,
        transport: SheetsHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError(
                "Google Sheets adapter requires a connected account"
            )
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Google Sheets adapter account is invalid")
        candidate = transport or FixedGoogleSheetsHttpsTransport()
        required = (
            "list_exports",
            "create_spreadsheet",
            "update_values",
            "get_spreadsheet",
            "get_values",
        )
        if any(not callable(getattr(candidate, name, None)) for name in required):
            raise TypeError("Google Sheets adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Google Sheets revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: GoogleSheetsExportRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[GoogleSheetsExportResult]:
        if not isinstance(request, GoogleSheetsExportRequest):
            raise TypeError("Google Sheets adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Sheets adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_SHEETS_RESPONSE_BYTES,
        )
        responses: list[SheetsHttpResponse] = []

        lookup = self._transport.list_exports(
            export_id=request.export_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(lookup)
        _raise_for_status(lookup, mutation=False)
        matches = _parse_export_matches(lookup, request)

        if not matches:
            create = self._transport.create_spreadsheet(
                payload=MappingProxyType(request.create_payload()),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(create)
            try:
                _raise_for_status(create, mutation=True)
                spreadsheet_id = _parse_created_file(create, request)
            except GoogleSheetsExportOutcomeUnknownError:
                raise
            except GoogleSheetsExportVerificationError:
                raise
            except ConnectorResponseError as exc:
                raise GoogleSheetsExportVerificationError(
                    "Created Google spreadsheet could not be verified"
                ) from exc
            idempotency_status = "created"
            metadata = None
        else:
            spreadsheet_id = matches[0]
            metadata_response = self._transport.get_spreadsheet(
                spreadsheet_id=spreadsheet_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(metadata_response)
            _raise_for_status(metadata_response, mutation=False)
            metadata = _parse_spreadsheet_metadata(
                metadata_response,
                request,
                spreadsheet_id,
                require_capacity=False,
            )
            current = self._transport.get_values(
                spreadsheet_id=spreadsheet_id,
                a1_range=request.table.a1_range,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(current)
            _raise_for_status(current, mutation=False)
            current_values = _parse_values(current, request.table)
            if current_values == request.table.values:
                if (
                    metadata.row_count < request.table.provider_row_count
                    or metadata.column_count
                    < request.table.column_count
                ):
                    raise GoogleSheetsExportVerificationError(
                        "Recovered Google spreadsheet grid is too small"
                    )
                return _execution(
                    call,
                    request,
                    spreadsheet_id,
                    metadata.spreadsheet_url,
                    "recovered_verified",
                    responses,
                )
            if current_values:
                raise GoogleSheetsIdempotencyConflictError(
                    "Recovered Google spreadsheet contains different values"
                )
            idempotency_status = "recovered_empty"

        update = self._transport.update_values(
            spreadsheet_id=spreadsheet_id,
            a1_range=request.table.a1_range,
            payload=MappingProxyType(request.values_payload()),
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(update)
        try:
            _raise_for_status(update, mutation=True)
        except GoogleSheetsExportOutcomeUnknownError:
            raise
        except ConnectorResponseError as exc:
            raise GoogleSheetsExportVerificationError(
                "Google spreadsheet update response could not be verified"
            ) from exc
        try:
            _verify_update(update, request, spreadsheet_id)

            metadata_response = self._transport.get_spreadsheet(
                spreadsheet_id=spreadsheet_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(metadata_response)
            _raise_for_status(metadata_response, mutation=False)
            metadata = _parse_spreadsheet_metadata(
                metadata_response,
                request,
                spreadsheet_id,
                require_capacity=True,
            )

            values_response = self._transport.get_values(
                spreadsheet_id=spreadsheet_id,
                a1_range=request.table.a1_range,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(values_response)
            _raise_for_status(values_response, mutation=False)
            if _parse_values(
                values_response,
                request.table,
            ) != request.table.values:
                raise GoogleSheetsExportVerificationError(
                    "Google spreadsheet values failed exact read-back"
                )
            return _execution(
                call,
                request,
                spreadsheet_id,
                metadata.spreadsheet_url,
                idempotency_status,
                responses,
            )
        except GoogleSheetsExportVerificationError:
            raise
        except ConnectorError as exc:
            raise GoogleSheetsExportVerificationError(
                "Google spreadsheet write could not be verified"
            ) from exc

    async def revoke(
        self,
        request: ConnectorRevocationRequest,
        refresh_token: SecretValue,
    ) -> ConnectorRevocationResult:
        if self._revoker is None:
            from connectors.oauth import OAuthTokenClient

            revoker = OAuthTokenClient().revoke
        else:
            revoker = self._revoker
        result = revoker(self.provider, request, refresh_token)
        if not isinstance(result, ConnectorRevocationResult):
            raise TypeError(
                "Google Sheets revocation evidence is invalid"
            )
        return result


@dataclass(frozen=True, slots=True)
class _SpreadsheetMetadata:
    spreadsheet_url: str
    row_count: int
    column_count: int


def _execution(
    call: ConnectorCall,
    request: GoogleSheetsExportRequest,
    spreadsheet_id: str,
    spreadsheet_url: str,
    idempotency_status: str,
    responses: list[SheetsHttpResponse],
) -> ConnectorExecution[GoogleSheetsExportResult]:
    if not 1 <= len(responses) <= MAX_SHEETS_PROVIDER_REQUESTS:
        raise ConnectorResponseError(
            "Google Sheets provider request count is invalid"
        )
    evidence = b"\x00".join(response.body for response in responses)
    if len(evidence) > MAX_SHEETS_PROVIDER_EVIDENCE_BYTES:
        raise ConnectorResponseError(
            "Google Sheets provider evidence exceeds its limit"
        )
    request_ids = tuple(
        response.provider_request_id
        for response in responses
        if response.provider_request_id is not None
    )
    output = GoogleSheetsExportResult(
        spreadsheet_id=spreadsheet_id,
        title=request.title,
        spreadsheet_url=spreadsheet_url,
        columns=request.table.columns,
        row_count=request.table.data_row_count,
        column_count=request.table.column_count,
        source_sha256=request.table.source_sha256,
        idempotency_status=idempotency_status,
        provider_request_ids=request_ids,
    )
    return ConnectorExecution(
        result=ConnectorCallResult(
            call_id=call.call_id,
            run_id=call.run_id,
            operation_id=call.operation_id,
            http_status=responses[-1].status,
            response_digest=hashlib.sha256(evidence).hexdigest(),
            response_bytes=len(evidence),
            provider_request_id=(
                responses[-1].provider_request_id
            ),
        ),
        output=output,
    )


def _parse_export_matches(
    response: SheetsHttpResponse,
    request: GoogleSheetsExportRequest,
) -> tuple[str, ...]:
    payload = _json_object(response, "Google Drive export lookup")
    if not set(payload).issubset(
        {"files", "incompleteSearch", "nextPageToken"}
    ):
        raise ConnectorResponseError(
            "Google Drive export lookup shape is invalid"
        )
    if payload.get("incompleteSearch") is True or payload.get(
        "nextPageToken"
    ):
        raise GoogleSheetsIdempotencyConflictError(
            "Google Drive export lookup is incomplete"
        )
    files = payload.get("files")
    if (
        not isinstance(files, list)
        or len(files) > 1
    ):
        raise GoogleSheetsIdempotencyConflictError(
            "Google Sheets idempotency key is ambiguous"
        )
    matches: list[str] = []
    for raw in files:
        spreadsheet_id, properties = _parse_drive_file(raw, request)
        if properties != request.app_properties:
            raise GoogleSheetsIdempotencyConflictError(
                "Google Sheets idempotency key names another export"
            )
        matches.append(spreadsheet_id)
    return tuple(matches)


def _parse_created_file(
    response: SheetsHttpResponse,
    request: GoogleSheetsExportRequest,
) -> str:
    payload = _json_object(response, "Google Drive create response")
    spreadsheet_id, properties = _parse_drive_file(payload, request)
    if properties != request.app_properties:
        raise GoogleSheetsExportVerificationError(
            "Created Google spreadsheet metadata does not match"
        )
    return spreadsheet_id


def _parse_drive_file(
    raw: object,
    request: GoogleSheetsExportRequest,
) -> tuple[str, dict[str, str]]:
    if (
        not isinstance(raw, dict)
        or set(raw) != {"appProperties", "id", "mimeType", "name"}
        or raw.get("mimeType") != GOOGLE_SHEETS_MIME_TYPE
        or raw.get("name") != request.title
        or not isinstance(raw.get("appProperties"), dict)
        or set(raw["appProperties"]) != _APP_PROPERTY_KEYS
        or any(
            not isinstance(value, str)
            for value in raw["appProperties"].values()
        )
    ):
        raise ConnectorResponseError(
            "Google Drive spreadsheet metadata is invalid"
        )
    try:
        spreadsheet_id = _provider_id(
            raw["id"],
            "Google spreadsheet ID",
        )
    except ValueError as exc:
        raise ConnectorResponseError(
            "Google spreadsheet ID is invalid"
        ) from exc
    return spreadsheet_id, dict(raw["appProperties"])


def _parse_spreadsheet_metadata(
    response: SheetsHttpResponse,
    request: GoogleSheetsExportRequest,
    spreadsheet_id: str,
    *,
    require_capacity: bool,
) -> _SpreadsheetMetadata:
    payload = _json_object(response, "Google Sheets metadata")
    if set(payload) != {
        "properties",
        "sheets",
        "spreadsheetId",
        "spreadsheetUrl",
    }:
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet metadata shape is invalid"
        )
    if (
        payload.get("spreadsheetId") != spreadsheet_id
        or payload.get("properties") != {"title": request.title}
        or not isinstance(payload.get("sheets"), list)
        or len(payload["sheets"]) != 1
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet identity does not match"
        )
    sheet = payload["sheets"][0]
    if not isinstance(sheet, dict) or set(sheet) != {"properties"}:
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet sheet metadata is invalid"
        )
    properties = sheet["properties"]
    if (
        not isinstance(properties, dict)
        or set(properties)
        != {"gridProperties", "index", "sheetId", "sheetType", "title"}
        or properties.get("index") != 0
        or properties.get("sheetType") != "GRID"
        or type(properties.get("sheetId")) is not int
        or properties["sheetId"] < 0
        or not isinstance(properties.get("title"), str)
        or not properties["title"]
        or not isinstance(properties.get("gridProperties"), dict)
        or set(properties["gridProperties"])
        != {"columnCount", "rowCount"}
        or type(properties["gridProperties"].get("rowCount")) is not int
        or type(properties["gridProperties"].get("columnCount")) is not int
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet grid metadata is invalid"
        )
    row_count = properties["gridProperties"]["rowCount"]
    column_count = properties["gridProperties"]["columnCount"]
    if (
        row_count < 1
        or column_count < 1
        or (
            require_capacity
            and (
                row_count < request.table.provider_row_count
                or column_count < request.table.column_count
            )
        )
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet grid shape is invalid"
        )
    try:
        spreadsheet_url = _verified_spreadsheet_url(
            payload["spreadsheetUrl"],
            spreadsheet_id,
        )
    except ValueError as exc:
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet URL is invalid"
        ) from exc
    return _SpreadsheetMetadata(
        spreadsheet_url=spreadsheet_url,
        row_count=row_count,
        column_count=column_count,
    )


def _parse_values(
    response: SheetsHttpResponse,
    table: ValidatedSheetTable,
) -> tuple[tuple[str, ...], ...]:
    payload = _json_object(response, "Google Sheets values")
    if not set(payload).issubset({"majorDimension", "range", "values"}):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet values shape is invalid"
        )
    if payload.get("majorDimension", "ROWS") != "ROWS":
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet values dimension is invalid"
        )
    returned_range = payload.get("range")
    if (
        not isinstance(returned_range, str)
        or not (
            returned_range == table.a1_range
            or returned_range.endswith("!" + table.a1_range)
        )
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet values range does not match"
        )
    raw_values = payload.get("values", [])
    if not isinstance(raw_values, list):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet values are invalid"
        )
    if not raw_values:
        return ()
    if len(raw_values) > table.provider_row_count:
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet returned too many rows"
        )
    normalized: list[tuple[str, ...]] = []
    for raw_row in raw_values:
        if (
            not isinstance(raw_row, list)
            or len(raw_row) > table.column_count
            or any(not isinstance(cell, str) for cell in raw_row)
        ):
            raise GoogleSheetsExportVerificationError(
                "Google spreadsheet returned invalid cells"
            )
        normalized.append(
            tuple(raw_row)
            + ("",) * (table.column_count - len(raw_row))
        )
    if all(all(not cell for cell in row) for row in normalized):
        return ()
    normalized.extend(
        [("",) * table.column_count]
        * (table.provider_row_count - len(normalized))
    )
    return tuple(normalized)


def _verify_update(
    response: SheetsHttpResponse,
    request: GoogleSheetsExportRequest,
    spreadsheet_id: str,
) -> None:
    payload = _json_object(response, "Google Sheets update")
    if not set(payload).issubset(
        {
            "spreadsheetId",
            "updatedCells",
            "updatedColumns",
            "updatedRange",
            "updatedRows",
        }
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet update shape is invalid"
        )
    expected_cells = (
        request.table.provider_row_count * request.table.column_count
    )
    updated_range = payload.get("updatedRange")
    if (
        payload.get("spreadsheetId") != spreadsheet_id
        or payload.get("updatedRows")
        != request.table.provider_row_count
        or payload.get("updatedColumns") != request.table.column_count
        or payload.get("updatedCells") != expected_cells
        or not isinstance(updated_range, str)
        or not (
            updated_range == request.table.a1_range
            or updated_range.endswith("!" + request.table.a1_range)
        )
    ):
        raise GoogleSheetsExportVerificationError(
            "Google spreadsheet update did not match the exact table shape"
        )


def _raise_for_status(
    response: SheetsHttpResponse,
    *,
    mutation: bool,
) -> None:
    if not isinstance(response, SheetsHttpResponse):
        raise TypeError("Google Sheets transport response is invalid")
    if 200 <= response.status <= 299:
        if not response.content_type.casefold().split(";", 1)[0].strip() == (
            "application/json"
        ):
            raise ConnectorResponseError(
                "Google Sheets response content type is invalid"
            )
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Google Sheets access token was rejected"
        )
    if response.status == 429:
        if mutation:
            raise GoogleSheetsExportOutcomeUnknownError(
                "Google Sheets mutation outcome is unknown"
            )
        raise ConnectorRateLimitError(response.retry_after_seconds or 0)
    if mutation and (
        response.status in {408, 425}
        or 500 <= response.status <= 599
    ):
        raise GoogleSheetsExportOutcomeUnknownError(
            "Google Sheets mutation outcome is unknown"
        )
    raise ConnectorRequestError("Google Sheets provider request failed")


def _json_object(
    response: SheetsHttpResponse,
    label: str,
) -> dict[str, object]:
    try:
        payload = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ConnectorResponseError(f"{label} JSON is invalid") from exc
    if not isinstance(payload, dict):
        raise ConnectorResponseError(f"{label} must be an object")
    return payload


def _reject_duplicate_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate Google Sheets JSON field")
        output[key] = value
    return output


def _reject_json_constant(_value: str):
    raise ValueError("Google Sheets JSON constants are invalid")


def _verified_spreadsheet_url(
    value: object,
    spreadsheet_id: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("Google spreadsheet URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "docs.google.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path
        != f"/spreadsheets/d/{spreadsheet_id}/edit"
    ):
        raise ValueError("Google spreadsheet URL is invalid")
    return value


def _request_body(payload: Mapping[str, object]) -> bytes:
    if not isinstance(payload, Mapping) or not payload:
        raise ConnectorRequestError(
            "Google Sheets request payload is invalid"
        )
    encoded = _canonical_json(dict(payload))
    if len(encoded) > MAX_SHEETS_REQUEST_BYTES:
        raise ConnectorRequestError(
            "Google Sheets request exceeds its limit"
        )
    return encoded


def _validate_fixed_endpoint(endpoint: str, method: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConnectorRequestError(
            "Google Sheets endpoint is invalid"
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname
        not in {"www.googleapis.com", "sheets.googleapis.com"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or method not in {"GET", "POST", "PUT"}
    ):
        raise ConnectorRequestError(
            "Google Sheets endpoint is not fixed by policy"
        )
    if parsed.hostname == "www.googleapis.com":
        if parsed.path != "/drive/v3/files" or method not in {"GET", "POST"}:
            raise ConnectorRequestError(
                "Google Drive endpoint is not fixed by policy"
            )
        return
    if (
        not parsed.path.startswith("/v4/spreadsheets/")
        or method not in {"GET", "PUT"}
    ):
        raise ConnectorRequestError(
            "Google Sheets endpoint is not fixed by policy"
        )


def _bounded_http_response(
    response,
    maximum: int,
) -> SheetsHttpResponse:
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ConnectorResponseError(
            "Google Sheets provider response exceeds its limit"
        )
    headers = response.headers
    content_type = headers.get("Content-Type", "")
    retry_after = headers.get("Retry-After")
    retry_seconds = None
    if retry_after is not None:
        try:
            retry_seconds = int(retry_after)
        except ValueError:
            retry_seconds = 0
    request_id = (
        headers.get("X-GUploader-UploadID")
        or headers.get("X-Goog-Request-Id")
        or headers.get("X-Request-Id")
    )
    return SheetsHttpResponse(
        status=int(response.status),
        content_type=content_type,
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


__all__ = [
    "GOOGLE_DRIVE_FILES_ENDPOINT",
    "GOOGLE_SHEETS_API_ROOT",
    "GOOGLE_SHEETS_EXPORT_OPERATION_ID",
    "GOOGLE_SHEETS_MIME_TYPE",
    "FixedGoogleSheetsHttpsTransport",
    "GoogleSheetsExportAdapter",
    "GoogleSheetsExportOutcomeUnknownError",
    "GoogleSheetsExportRequest",
    "GoogleSheetsExportResult",
    "GoogleSheetsExportVerificationError",
    "GoogleSheetsIdempotencyConflictError",
    "SheetsHttpResponse",
    "SheetsHttpTransport",
]
