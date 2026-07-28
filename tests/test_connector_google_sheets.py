"""Create-once Google Sheets export and exact read-back tests."""

from __future__ import annotations

import hashlib
import json
import unittest
import urllib.error
from pathlib import Path

from capability_registry import (
    AccountAuthorization,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorCall,
    ConnectorExecution,
    ConnectorProviderId,
    ConnectorRequestError,
    ConnectorResponseError,
    SecretValue,
)
from connectors.google_sheets import (
    GOOGLE_SHEETS_EXPORT_OPERATION_ID,
    GOOGLE_SHEETS_MIME_TYPE,
    FixedGoogleSheetsHttpsTransport,
    GoogleSheetsExportAdapter,
    GoogleSheetsExportOutcomeUnknownError,
    GoogleSheetsExportRequest,
    GoogleSheetsExportVerificationError,
    GoogleSheetsIdempotencyConflictError,
    SheetsHttpResponse,
)
from sheets_contracts import (
    MAX_SHEETS_PROVIDER_RESPONSE_BYTES,
    SheetsTableValidationError,
    parse_validated_sheet_csv,
)


SOURCE = (
    b"entity,public_url,rationale\r\n"
    b"Alpha,https://alpha.example/,=literal formula text\r\n"
    b"Beta,https://beta.example/,Second\r\n"
)
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()
SPREADSHEET_ID = "spreadsheet_123"


def _table():
    return parse_validated_sheet_csv(
        SOURCE,
        expected_sha256=SOURCE_SHA256,
    )


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.sheets-one",
            connector=ConnectorId.GOOGLE_SHEETS,
            account_reference="google.sheets-one",
            capabilities=frozenset(
                {CapabilityId.SHEETS_VALUES_WRITE}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.SHEETS_VALUES_WRITE}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _request() -> GoogleSheetsExportRequest:
    return GoogleSheetsExportRequest(
        title="Reviewed research",
        table=_table(),
        idempotency_key="task.export-123",
    )


def _call(
    request: GoogleSheetsExportRequest,
    *,
    authorization_id: str = "oauth.sheets-one",
) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-sheets",
        run_id="run-sheets",
        authorization_id=authorization_id,
        connector=ConnectorId.GOOGLE_SHEETS,
        capability=CapabilityId.SHEETS_VALUES_WRITE,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=1024 * 1024,
        idempotency_key=request.idempotency_key,
    )


def _response(
    value: object,
    *,
    request_id: str,
    status: int = 200,
) -> SheetsHttpResponse:
    return SheetsHttpResponse(
        status=status,
        content_type="application/json; charset=UTF-8",
        body=json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        provider_request_id=request_id,
    )


def _file(request: GoogleSheetsExportRequest) -> dict[str, object]:
    return {
        "appProperties": request.app_properties,
        "id": SPREADSHEET_ID,
        "mimeType": GOOGLE_SHEETS_MIME_TYPE,
        "name": request.title,
    }


def _metadata(
    request: GoogleSheetsExportRequest,
    *,
    title: str | None = None,
) -> dict[str, object]:
    return {
        "properties": {"title": title or request.title},
        "sheets": [
            {
                "properties": {
                    "gridProperties": {
                        "columnCount": 26,
                        "rowCount": 1000,
                    },
                    "index": 0,
                    "sheetId": 0,
                    "sheetType": "GRID",
                    "title": "Sheet1",
                }
            }
        ],
        "spreadsheetId": SPREADSHEET_ID,
        "spreadsheetUrl": (
            "https://docs.google.com/spreadsheets/d/"
            f"{SPREADSHEET_ID}/edit"
        ),
    }


def _update(request: GoogleSheetsExportRequest) -> dict[str, object]:
    return {
        "spreadsheetId": SPREADSHEET_ID,
        "updatedCells": (
            request.table.provider_row_count
            * request.table.column_count
        ),
        "updatedColumns": request.table.column_count,
        "updatedRange": f"Sheet1!{request.table.a1_range}",
        "updatedRows": request.table.provider_row_count,
    }


def _values(request: GoogleSheetsExportRequest) -> dict[str, object]:
    return {
        "majorDimension": "ROWS",
        "range": f"Sheet1!{request.table.a1_range}",
        "values": [list(row) for row in request.table.values],
    }


class _FakeTransport:
    def __init__(self, responses: dict[str, list[SheetsHttpResponse]]) -> None:
        self.responses = {
            name: list(values) for name, values in responses.items()
        }
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _next(self, name: str, **kwargs):
        self.calls.append((name, kwargs))
        return self.responses[name].pop(0)

    def list_exports(self, **kwargs):
        return self._next("list", **kwargs)

    def create_spreadsheet(self, **kwargs):
        return self._next("create", **kwargs)

    def update_values(self, **kwargs):
        return self._next("update", **kwargs)

    def get_spreadsheet(self, **kwargs):
        return self._next("metadata", **kwargs)

    def get_values(self, **kwargs):
        return self._next("values", **kwargs)


class SheetsTableContractTests(unittest.TestCase):
    def test_revalidates_exact_digest_rectangular_shape_and_a1_range(self):
        table = _table()

        self.assertEqual(
            table.columns,
            ("entity", "public_url", "rationale"),
        )
        self.assertEqual(table.data_row_count, 2)
        self.assertEqual(table.a1_range, "A1:C3")
        self.assertEqual(
            table.rows[0][2],
            "=literal formula text",
        )
        with self.assertRaisesRegex(
            SheetsTableValidationError,
            "identity",
        ):
            parse_validated_sheet_csv(
                SOURCE,
                expected_sha256="0" * 64,
            )
        malformed = b"a,b\r\nonly-one\r\n"
        with self.assertRaisesRegex(
            SheetsTableValidationError,
            "rows",
        ):
            parse_validated_sheet_csv(
                malformed,
                expected_sha256=hashlib.sha256(malformed).hexdigest(),
            )

    def test_preview_has_account_title_rows_columns_and_no_raw_key(self):
        preview = json.loads(
            _table().preview_bytes(
                authorization_id="oauth.sheets-one",
                title="Reviewed research",
                idempotency_key="private-operation-key",
            )
        )

        self.assertEqual(
            preview["destination_account_authorization_id"],
            "oauth.sheets-one",
        )
        self.assertEqual(preview["title"], "Reviewed research")
        self.assertEqual(preview["row_count"], 2)
        self.assertEqual(
            preview["columns"],
            ["entity", "public_url", "rationale"],
        )
        self.assertNotIn(
            "private-operation-key",
            json.dumps(preview),
        )

    def test_provider_response_ceiling_covers_bounded_source_readback(self):
        response = SheetsHttpResponse(
            status=200,
            content_type="application/json",
            body=b"x" * MAX_SHEETS_PROVIDER_RESPONSE_BYTES,
        )

        self.assertEqual(
            len(response.body),
            MAX_SHEETS_PROVIDER_RESPONSE_BYTES,
        )
        with self.assertRaisesRegex(ValueError, "body"):
            SheetsHttpResponse(
                status=200,
                content_type="application/json",
                body=b"x" * (MAX_SHEETS_PROVIDER_RESPONSE_BYTES + 1),
            )


class GoogleSheetsExportAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_creates_once_with_raw_values_and_exact_read_back(self):
        request = _request()
        transport = _FakeTransport(
            {
                "list": [
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    )
                ],
                "create": [
                    _response(_file(request), request_id="drive-create")
                ],
                "update": [
                    _response(_update(request), request_id="sheets-update")
                ],
                "metadata": [
                    _response(
                        _metadata(request),
                        request_id="sheets-metadata",
                    )
                ],
                "values": [
                    _response(_values(request), request_id="sheets-values")
                ],
            }
        )
        adapter = GoogleSheetsExportAdapter(_account(), transport)
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(request),
            request,
            token,
        )

        self.assertIsInstance(execution, ConnectorExecution)
        self.assertEqual(
            [name for name, _kwargs in transport.calls],
            ["list", "create", "update", "metadata", "values"],
        )
        create_payload = dict(transport.calls[1][1]["payload"])
        self.assertEqual(
            create_payload["appProperties"],
            request.app_properties,
        )
        update_payload = dict(transport.calls[2][1]["payload"])
        self.assertEqual(update_payload["majorDimension"], "ROWS")
        self.assertEqual(
            update_payload["values"][1][2],
            "=literal formula text",
        )
        self.assertEqual(
            execution.output.idempotency_status,
            "created",
        )
        self.assertEqual(execution.output.row_count, 2)
        self.assertEqual(execution.output.column_count, 3)
        self.assertEqual(
            execution.output.provider_request_ids,
            (
                "drive-list",
                "drive-create",
                "sheets-update",
                "sheets-metadata",
                "sheets-values",
            ),
        )
        self.assertNotIn(SOURCE, execution.output.to_json_bytes())

    async def test_exact_recovery_performs_no_second_write(self):
        request = _request()
        transport = _FakeTransport(
            {
                "list": [
                    _response(
                        {
                            "files": [_file(request)],
                            "incompleteSearch": False,
                        },
                        request_id="drive-list",
                    )
                ],
                "metadata": [
                    _response(
                        _metadata(request),
                        request_id="sheets-metadata",
                    )
                ],
                "values": [
                    _response(_values(request), request_id="sheets-values")
                ],
            }
        )
        adapter = GoogleSheetsExportAdapter(_account(), transport)
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(request),
            request,
            token,
        )

        self.assertEqual(
            [name for name, _kwargs in transport.calls],
            ["list", "metadata", "values"],
        )
        self.assertEqual(
            execution.output.idempotency_status,
            "recovered_verified",
        )

    async def test_empty_ambiguous_create_is_recovered_then_written_once(self):
        request = _request()
        transport = _FakeTransport(
            {
                "list": [
                    _response(
                        {
                            "files": [_file(request)],
                            "incompleteSearch": False,
                        },
                        request_id="drive-list",
                    )
                ],
                "metadata": [
                    _response(
                        _metadata(request),
                        request_id="metadata-before",
                    ),
                    _response(
                        _metadata(request),
                        request_id="metadata-after",
                    ),
                ],
                "values": [
                    _response(
                        {
                            "majorDimension": "ROWS",
                            "range": (
                                f"Sheet1!{request.table.a1_range}"
                            ),
                        },
                        request_id="values-before",
                    ),
                    _response(_values(request), request_id="values-after"),
                ],
                "update": [
                    _response(_update(request), request_id="sheets-update")
                ],
            }
        )
        adapter = GoogleSheetsExportAdapter(_account(), transport)
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(request),
            request,
            token,
        )

        self.assertEqual(
            [name for name, _kwargs in transport.calls],
            [
                "list",
                "metadata",
                "values",
                "update",
                "metadata",
                "values",
            ],
        )
        self.assertEqual(
            execution.output.idempotency_status,
            "recovered_empty",
        )

    async def test_conflict_and_bad_readback_never_claim_success(self):
        request = _request()
        conflict_file = _file(request)
        conflict_file["appProperties"] = {
            **request.app_properties,
            "clickyRequestSha256": "0" * 64,
        }
        conflict_transport = _FakeTransport(
            {
                "list": [
                    _response(
                        {
                            "files": [conflict_file],
                            "incompleteSearch": False,
                        },
                        request_id="drive-list",
                    )
                ]
            }
        )
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)
        with self.assertRaises(GoogleSheetsIdempotencyConflictError):
            await GoogleSheetsExportAdapter(
                _account(),
                conflict_transport,
            ).execute(_call(request), request, token)
        self.assertEqual(
            [name for name, _kwargs in conflict_transport.calls],
            ["list"],
        )

        mismatched = _values(request)
        mismatched["values"][1][0] = "Tampered"
        bad_transport = _FakeTransport(
            {
                "list": [
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    )
                ],
                "create": [
                    _response(_file(request), request_id="drive-create")
                ],
                "update": [
                    _response(_update(request), request_id="sheets-update")
                ],
                "metadata": [
                    _response(
                        _metadata(request),
                        request_id="sheets-metadata",
                    )
                ],
                "values": [
                    _response(mismatched, request_id="sheets-values")
                ],
            }
        )
        with self.assertRaises(GoogleSheetsExportVerificationError):
            await GoogleSheetsExportAdapter(
                _account(),
                bad_transport,
            ).execute(_call(request), request, token)

        unavailable_readback = _FakeTransport(
            {
                "list": [
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    )
                ],
                "create": [
                    _response(_file(request), request_id="drive-create")
                ],
                "update": [
                    _response(_update(request), request_id="sheets-update")
                ],
                "metadata": [
                    _response(
                        {},
                        request_id="metadata-unavailable",
                        status=503,
                    )
                ],
            }
        )
        with self.assertRaises(GoogleSheetsExportVerificationError):
            await GoogleSheetsExportAdapter(
                _account(),
                unavailable_readback,
            ).execute(_call(request), request, token)

    async def test_authority_is_checked_before_provider_io(self):
        request = _request()
        transport = _FakeTransport({})
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)

        with self.assertRaisesRegex(
            Exception,
            "authority",
        ):
            await GoogleSheetsExportAdapter(
                _account(),
                transport,
            ).execute(
                _call(request, authorization_id="oauth.another"),
                request,
                token,
            )
        self.assertEqual(transport.calls, [])


class FixedGoogleSheetsTransportTests(unittest.TestCase):
    def test_transport_uses_fixed_hosts_raw_mode_and_private_creation(self):
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self, _maximum):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, request, timeout):
                self.calls.append((request, timeout))
                return Response()

        opener = Opener()
        transport = FixedGoogleSheetsHttpsTransport(_opener=opener)
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)
        request = _request()

        transport.create_spreadsheet(
            payload=request.create_payload(),
            access_token=token,
            maximum_response_bytes=4096,
        )
        transport.update_values(
            spreadsheet_id=SPREADSHEET_ID,
            a1_range=request.table.a1_range,
            payload=request.values_payload(),
            access_token=token,
            maximum_response_bytes=4096,
        )

        create_url = opener.calls[0][0].full_url
        update_url = opener.calls[1][0].full_url
        self.assertIn("ignoreDefaultVisibility=true", create_url)
        self.assertIn("valueInputOption=RAW", update_url)
        self.assertIn("includeValuesInResponse=false", update_url)
        source = Path("connectors/google_sheets.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("urllib.request.ProxyHandler({})", source)
        self.assertIn("_NoRedirectHandler()", source)
        self.assertNotIn("urllib.request.urlopen", source)
        self.assertNotIn("logging", source)
        self.assertNotIn("requests.", source)

    def test_mutation_network_failure_is_outcome_unknown(self):
        class Opener:
            def open(self, *_args, **_kwargs):
                raise urllib.error.URLError("offline")

        transport = FixedGoogleSheetsHttpsTransport(_opener=Opener())
        token = SecretValue(b"sheets-access-token")
        self.addCleanup(token.close)

        with self.assertRaises(GoogleSheetsExportOutcomeUnknownError):
            transport.create_spreadsheet(
                payload=_request().create_payload(),
                access_token=token,
                maximum_response_bytes=4096,
            )

    def test_request_models_expose_no_arbitrary_endpoint_or_sharing_surface(self):
        source = Path("connectors/google_sheets.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/permissions", source)
        self.assertNotIn("permissions.create", source)
        self.assertNotIn("files.delete", source)
        self.assertNotIn("values.append", source)
        self.assertEqual(
            _request().operation_id,
            GOOGLE_SHEETS_EXPORT_OPERATION_ID,
        )


if __name__ == "__main__":
    unittest.main()
