"""Selected-file Google Drive connector boundary tests."""

from __future__ import annotations

import ast
import hashlib
import json
import unittest
from dataclasses import replace
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
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorProviderId,
    ConnectorRequestError,
    ConnectorResponseError,
    SecretValue,
)
from connectors.google_drive import (
    DRIVE_SELECTED_FILE_OPERATION_ID,
    DriveHttpResponse,
    DriveNativeExportRequiredError,
    DriveSelectedFileRequest,
    DriveUnsupportedMediaTypeError,
    FixedGoogleDriveHttpsTransport,
    GoogleDriveSelectedFileAdapter,
)


_FILE_ID = "1AbCdEfGhIjKlMnOpQrStUvWxYz"


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.drive-one",
            connector=ConnectorId.GOOGLE_DRIVE,
            account_reference="google.drive-one",
            capabilities=frozenset(
                {CapabilityId.DRIVE_SELECTED_FILE_READ}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.DRIVE_SELECTED_FILE_READ}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _call(
    request: DriveSelectedFileRequest,
    *,
    maximum_response_bytes: int = 320 * 1024,
) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-drive",
        run_id="run-drive",
        authorization_id="oauth.drive-one",
        connector=ConnectorId.GOOGLE_DRIVE,
        capability=CapabilityId.DRIVE_SELECTED_FILE_READ,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=maximum_response_bytes,
    )


def _metadata(
    *,
    mime_type: str = "text/plain",
    size: int | None = 13,
    file_id: str = _FILE_ID,
    extra: dict[str, object] | None = None,
) -> bytes:
    value: dict[str, object] = {
        "id": file_id,
        "mimeType": mime_type,
        "modifiedTime": "2026-07-28T10:11:12.123Z",
        "name": "selected.txt",
        "trashed": False,
    }
    if size is not None:
        value["size"] = str(size)
    if extra:
        value.update(extra)
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _FakeTransport:
    def __init__(self, *responses: DriveHttpResponse) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, bytes, int]] = []

    def get(
        self,
        *,
        endpoint,
        access_token,
        maximum_response_bytes,
    ):
        self.calls.append(
            (
                endpoint,
                access_token.reveal(),
                maximum_response_bytes,
            )
        )
        return self.responses.pop(0)


class GoogleDriveSelectedFileTests(unittest.IsolatedAsyncioTestCase):
    def test_request_binds_one_opaque_id_and_has_no_search_surface(self):
        first = DriveSelectedFileRequest(_FILE_ID)
        second = DriveSelectedFileRequest("2AbCdEfGhIjKlMnOpQrStUvWxYz")

        self.assertNotEqual(first.request_digest, second.request_digest)
        self.assertEqual(
            first.operation_id,
            DRIVE_SELECTED_FILE_OPERATION_ID,
        )
        self.assertIn(f"/files/{_FILE_ID}?", first.metadata_endpoint)
        self.assertIn("fields=", first.metadata_endpoint)
        self.assertIn("alt=media", first.content_endpoint)
        for forbidden in ("q=", "pageToken", "/list", "children"):
            self.assertNotIn(forbidden, first.metadata_endpoint)
            self.assertNotIn(forbidden, first.content_endpoint)
        for invalid in (
            "short",
            "../private",
            "file id with spaces",
            f"{_FILE_ID}?alt=media",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                DriveSelectedFileRequest(invalid)

    async def test_reads_only_selected_utf8_text_with_exact_evidence(self):
        content = b"Selected text"
        metadata = _metadata(size=len(content))
        transport = _FakeTransport(
            DriveHttpResponse(
                status=200,
                content_type="application/json; charset=UTF-8",
                body=metadata,
                provider_request_id="drive-metadata-request",
            ),
            DriveHttpResponse(
                status=200,
                content_type="text/plain; charset=UTF-8",
                body=content,
                provider_request_id="drive-content-request",
            ),
        )
        request = DriveSelectedFileRequest(_FILE_ID)
        token = SecretValue(b"drive-access-token")
        self.addCleanup(token.close)

        execution = await GoogleDriveSelectedFileAdapter(
            _account(),
            transport,
        ).execute(_call(request), request, token)

        self.assertEqual(
            [item[0] for item in transport.calls],
            [request.metadata_endpoint, request.content_endpoint],
        )
        self.assertEqual(
            [item[1] for item in transport.calls],
            [b"drive-access-token", b"drive-access-token"],
        )
        self.assertEqual(execution.output.content_text, "Selected text")
        self.assertEqual(
            execution.output.content_sha256,
            hashlib.sha256(content).hexdigest(),
        )
        rendered = json.loads(execution.output.to_json_bytes())
        self.assertTrue(rendered["content_untrusted"])
        self.assertEqual(rendered["file_id"], _FILE_ID)
        self.assertEqual(rendered["content"], "Selected text")
        self.assertEqual(
            execution.result.response_bytes,
            len(metadata) + len(content),
        )
        self.assertEqual(
            execution.result.provider_request_id,
            "drive-metadata-request/drive-content-request",
        )
        self.assertNotIn(
            "drive-access-token",
            repr(execution),
        )

    async def test_native_google_file_requires_separate_export_without_download(
        self,
    ):
        transport = _FakeTransport(
            DriveHttpResponse(
                status=200,
                content_type="application/json",
                body=_metadata(
                    mime_type="application/vnd.google-apps.document",
                    size=None,
                ),
            )
        )
        request = DriveSelectedFileRequest(_FILE_ID)
        token = SecretValue(b"drive-access-token")
        self.addCleanup(token.close)

        with self.assertRaises(DriveNativeExportRequiredError):
            await GoogleDriveSelectedFileAdapter(
                _account(),
                transport,
            ).execute(_call(request), request, token)
        self.assertEqual(len(transport.calls), 1)

    async def test_unsupported_or_oversized_content_stops_before_download(self):
        cases = (
            (
                _metadata(mime_type="application/pdf", size=20),
                DriveUnsupportedMediaTypeError,
            ),
            (
                _metadata(
                    mime_type="application/vnd.google-apps.folder",
                    size=None,
                ),
                DriveUnsupportedMediaTypeError,
            ),
            (
                _metadata(size=257),
                ConnectorResponseError,
            ),
        )
        for metadata, expected in cases:
            with self.subTest(expected=expected.__name__):
                transport = _FakeTransport(
                    DriveHttpResponse(
                        status=200,
                        content_type="application/json",
                        body=metadata,
                    )
                )
                request = DriveSelectedFileRequest(
                    _FILE_ID,
                    maximum_content_bytes=256,
                )
                token = SecretValue(b"drive-access-token")
                self.addCleanup(token.close)
                with self.assertRaises(expected):
                    await GoogleDriveSelectedFileAdapter(
                        _account(),
                        transport,
                    ).execute(_call(request), request, token)
                self.assertEqual(len(transport.calls), 1)

    async def test_metadata_and_download_must_match_exactly(self):
        cases = (
            (
                _metadata(file_id="2AbCdEfGhIjKlMnOpQrStUvWxYz"),
                DriveHttpResponse(200, "text/plain", b"Selected text"),
            ),
            (
                _metadata(size=12),
                DriveHttpResponse(200, "text/plain", b"Selected text"),
            ),
            (
                _metadata(size=13),
                DriveHttpResponse(200, "text/csv", b"Selected text"),
            ),
            (
                _metadata(size=2),
                DriveHttpResponse(200, "text/plain", b"\xff\xfe"),
            ),
        )
        for metadata, content_response in cases:
            with self.subTest(metadata=metadata):
                transport = _FakeTransport(
                    DriveHttpResponse(
                        status=200,
                        content_type="application/json",
                        body=metadata,
                    ),
                    content_response,
                )
                request = DriveSelectedFileRequest(_FILE_ID)
                token = SecretValue(b"drive-access-token")
                self.addCleanup(token.close)
                with self.assertRaises(ConnectorResponseError):
                    await GoogleDriveSelectedFileAdapter(
                        _account(),
                        transport,
                    ).execute(_call(request), request, token)

    async def test_provider_checksums_must_match_downloaded_bytes(self):
        content = b"Selected text"
        valid_checksums = {
            "md5Checksum": hashlib.md5(
                content,
                usedforsecurity=False,
            ).hexdigest(),
            "sha256Checksum": hashlib.sha256(content).hexdigest(),
        }
        for checksums in (
            valid_checksums,
            {**valid_checksums, "md5Checksum": "0" * 32},
            {**valid_checksums, "sha256Checksum": "0" * 64},
        ):
            transport = _FakeTransport(
                DriveHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=_metadata(
                        size=len(content),
                        extra=checksums,
                    ),
                ),
                DriveHttpResponse(200, "text/plain", content),
            )
            request = DriveSelectedFileRequest(_FILE_ID)
            token = SecretValue(b"drive-access-token")
            self.addCleanup(token.close)
            if checksums == valid_checksums:
                await GoogleDriveSelectedFileAdapter(
                    _account(),
                    transport,
                ).execute(_call(request), request, token)
            else:
                with self.assertRaises(ConnectorResponseError):
                    await GoogleDriveSelectedFileAdapter(
                        _account(),
                        transport,
                    ).execute(_call(request), request, token)

    async def test_call_authority_and_request_digest_cannot_be_retargeted(self):
        request = DriveSelectedFileRequest(_FILE_ID)
        transport = _FakeTransport()
        token = SecretValue(b"drive-access-token")
        self.addCleanup(token.close)

        with self.assertRaises(ConnectorAuthorizationError):
            await GoogleDriveSelectedFileAdapter(
                _account(),
                transport,
            ).execute(
                replace(_call(request), request_digest="0" * 64),
                request,
                token,
            )
        self.assertEqual(transport.calls, [])

    def test_fixed_transport_rejects_non_drive_hosts_and_query_expansion(self):
        transport = FixedGoogleDriveHttpsTransport(
            _opener=object(),
        )
        token = SecretValue(b"drive-access-token")
        self.addCleanup(token.close)
        for endpoint in (
            "https://evil.example/drive/v3/files/" + _FILE_ID,
            "http://www.googleapis.com/drive/v3/files/" + _FILE_ID,
            (
                "https://www.googleapis.com/drive/v3/files/"
                + _FILE_ID
                + "?alt=media&q=private"
            ),
            (
                "https://www.googleapis.com/drive/v3/files/"
                + _FILE_ID
                + "/children?alt=media&supportsAllDrives=true"
            ),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(
                ConnectorRequestError
            ):
                transport.get(
                    endpoint=endpoint,
                    access_token=token,
                    maximum_response_bytes=1024,
                )

    def test_source_has_no_search_write_log_or_process_surface(self):
        source = Path("connectors/google_drive.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(
            {
                "aiohttp",
                "httpx",
                "logging",
                "requests",
                "socket",
                "subprocess",
            }.isdisjoint(imported_roots)
        )
        called_attributes = {
            node.func.attr.casefold()
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(
            {"delete", "patch", "post", "put"}.isdisjoint(
                called_attributes
            )
        )
        request_methods = [
            keyword.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Request"
            for keyword in node.keywords
            if keyword.arg == "method"
            and isinstance(keyword.value, ast.Constant)
        ]
        self.assertEqual(request_methods, ["GET"])


if __name__ == "__main__":
    unittest.main()
