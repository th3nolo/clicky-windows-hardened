"""Selected-read and create-once Google Docs connector tests."""

from __future__ import annotations

import json
import unittest
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
    ConnectorProviderId,
    ConnectorRequestError,
    SecretValue,
)
from connectors.google_docs import (
    GOOGLE_DOCS_CREATE_OPERATION_ID,
    GOOGLE_DOCS_READ_OPERATION_ID,
    DocsHttpResponse,
    FixedGoogleDocsHttpsTransport,
    GoogleDocsAdapter,
    GoogleDocsCreateOutcomeUnknownError,
    GoogleDocsCreateRequest,
    GoogleDocsCreateVerificationError,
    GoogleDocsIdempotencyConflictError,
    GoogleDocsSelectedDocumentRequest,
)
from docs_contracts import (
    GOOGLE_DOCS_MIME_TYPE,
    GoogleDocsUnsupportedStructureError,
    parse_google_docs_document,
    verified_google_docs_url,
)


DOCUMENT_ID = "document_123"


def _account(*capabilities: CapabilityId) -> ConnectedAccount:
    scopes = {
        CapabilityId.DOCS_DOCUMENT_READ: (
            OAuthScopeId.DOCS_SELECTED_DOCUMENT_READ
        ),
        CapabilityId.DOCS_DOCUMENT_CREATE: (
            OAuthScopeId.DOCS_DOCUMENT_CREATE
        ),
    }
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.docs-one",
            connector=ConnectorId.GOOGLE_DOCS,
            account_reference="google.docs-one",
            capabilities=frozenset(capabilities),
            oauth_scopes=frozenset(scopes[item] for item in capabilities),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _call(request, capability: CapabilityId) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-docs",
        run_id="run-docs",
        authorization_id="oauth.docs-one",
        connector=ConnectorId.GOOGLE_DOCS,
        capability=capability,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=1024 * 1024,
        idempotency_key=getattr(request, "idempotency_key", None),
    )


def _response(
    value: object,
    *,
    request_id: str,
    status: int = 200,
) -> DocsHttpResponse:
    return DocsHttpResponse(
        status=status,
        content_type="application/json; charset=UTF-8",
        body=json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        provider_request_id=request_id,
    )


def _document(
    title: str,
    text: str,
    *,
    revision_id: str = "revision-1",
    document_id: str = DOCUMENT_ID,
) -> dict[str, object]:
    source = text + "\n"
    return {
        "documentId": document_id,
        "revisionId": revision_id,
        "tabs": [
            {
                "documentTab": {
                    "body": {
                        "content": [
                            {
                                "endIndex": 1,
                                "sectionBreak": {},
                                "startIndex": 0,
                            },
                            {
                                "endIndex": len(source) + 1,
                                "paragraph": {
                                    "elements": [
                                        {
                                            "endIndex": len(source) + 1,
                                            "startIndex": 1,
                                            "textRun": {
                                                "content": source,
                                                "textStyle": {},
                                            },
                                        }
                                    ],
                                    "paragraphStyle": {
                                        "namedStyleType": "NORMAL_TEXT"
                                    },
                                },
                                "startIndex": 1,
                            },
                        ]
                    }
                },
                "tabProperties": {
                    "index": 0,
                    "tabId": "t.0",
                    "title": "Tab 1",
                },
            }
        ],
        "title": title,
    }


def _request() -> GoogleDocsCreateRequest:
    return GoogleDocsCreateRequest(
        title="Reviewed memo",
        body_text="Exact reviewed body\nSecond line",
        idempotency_key="task.docs-create-1",
    )


def _drive_file(
    request: GoogleDocsCreateRequest,
    *,
    include_url: bool,
) -> dict[str, object]:
    value: dict[str, object] = {
        "appProperties": request.app_properties,
        "id": DOCUMENT_ID,
        "mimeType": GOOGLE_DOCS_MIME_TYPE,
        "name": request.title,
        "trashed": False,
    }
    if include_url:
        value["webViewLink"] = (
            f"https://docs.google.com/document/d/{DOCUMENT_ID}/edit"
        )
    return value


class _ScriptedTransport:
    def __init__(self, script) -> None:
        self.script = list(script)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _next(self, name: str, values: dict[str, object]):
        self.calls.append((name, values))
        expected, result = self.script.pop(0)
        if expected != name:
            raise AssertionError(f"expected {expected}, got {name}")
        if isinstance(result, BaseException):
            raise result
        return result

    def list_creations(self, **values):
        return self._next("list", values)

    def create_document_file(self, **values):
        values["payload"] = dict(values["payload"])
        return self._next("create", values)

    def get_file_metadata(self, **values):
        return self._next("metadata", values)

    def get_document(self, **values):
        return self._next("document", values)

    def insert_text(self, **values):
        values["payload"] = dict(values["payload"])
        return self._next("insert", values)


class GoogleDocsContractTests(unittest.TestCase):
    def test_selected_request_binds_exact_id_without_search(self):
        request = GoogleDocsSelectedDocumentRequest(DOCUMENT_ID)
        other = GoogleDocsSelectedDocumentRequest("document_456")

        self.assertEqual(
            request.operation_id,
            GOOGLE_DOCS_READ_OPERATION_ID,
        )
        self.assertNotEqual(request.request_digest, other.request_digest)
        self.assertFalse(hasattr(request, "query"))
        for invalid in ("../doc", "doc id", "doc?fields=*", ""):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                GoogleDocsSelectedDocumentRequest(invalid)

    def test_create_request_is_exact_and_has_no_arbitrary_edit_surface(self):
        request = _request()
        payload = request.batch_payload(required_revision_id="revision-1")
        encoded = json.dumps(payload, sort_keys=True)

        self.assertEqual(
            request.operation_id,
            GOOGLE_DOCS_CREATE_OPERATION_ID,
        )
        self.assertEqual(
            payload,
            {
                "requests": [
                    {
                        "insertText": {
                            "endOfSegmentLocation": {},
                            "text": request.body_text,
                        }
                    }
                ],
                "writeControl": {
                    "requiredRevisionId": "revision-1"
                },
            },
        )
        for forbidden in (
            "replaceAllText",
            "deleteContentRange",
            "updateTextStyle",
            "createNamedRange",
            "deleteNamedRange",
            "suggest",
            "share",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(
            json.loads(request.preview_bytes()),
            {
                "body_text": request.body_text,
                "title": request.title,
            },
        )

    def test_parser_preserves_bounded_plain_text_and_tab_structure(self):
        payload = _document("Selected memo", "First\nSecond")
        document = parse_google_docs_document(
            json.dumps(payload).encode("utf-8"),
            expected_document_id=DOCUMENT_ID,
        )
        output = json.loads(document.to_json_bytes())

        self.assertTrue(output["content_untrusted"])
        self.assertEqual(output["title"], "Selected memo")
        self.assertEqual(output["tabs"][0]["tab_id"], "t.0")
        self.assertEqual(output["tabs"][0]["content"], "First\nSecond")
        self.assertNotIn("revision", output)

    def test_parser_rejects_tables_suggestions_and_embedded_objects(self):
        table = _document("Selected memo", "")
        content = table["tabs"][0]["documentTab"]["body"]["content"]
        content[1] = {
            "endIndex": 2,
            "startIndex": 1,
            "table": {},
        }
        suggested = _document("Selected memo", "text")
        suggested["suggestions"] = {"s1": {}}
        embedded = _document("Selected memo", "text")
        element = (
            embedded["tabs"][0]["documentTab"]["body"]["content"][1]
            ["paragraph"]["elements"][0]
        )
        element.pop("textRun")
        element["inlineObjectElement"] = {"inlineObjectId": "object-1"}

        for payload in (table, suggested, embedded):
            with self.subTest(payload=payload), self.assertRaises(
                GoogleDocsUnsupportedStructureError
            ):
                parse_google_docs_document(
                    json.dumps(payload).encode("utf-8"),
                    expected_document_id=DOCUMENT_ID,
                )

    def test_parser_rejects_duplicate_json_and_urls_are_exact(self):
        with self.assertRaises(ValueError):
            parse_google_docs_document(
                (
                    b'{"documentId":"document_123",'
                    b'"documentId":"document_123",'
                    b'"tabs":[],"title":"Memo"}'
                ),
                expected_document_id=DOCUMENT_ID,
            )
        accepted = (
            f"https://docs.google.com/document/d/{DOCUMENT_ID}/edit"
            "?usp=drivesdk"
        )
        self.assertEqual(
            verified_google_docs_url(accepted, DOCUMENT_ID),
            accepted,
        )
        for invalid in (
            f"https://docs.google.com/document/d/{DOCUMENT_ID}/copy",
            (
                f"https://docs.google.com/document/d/{DOCUMENT_ID}/edit"
                "?token=secret"
            ),
            f"https://evil.example/document/d/{DOCUMENT_ID}/edit",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                verified_google_docs_url(invalid, DOCUMENT_ID)


class GoogleDocsAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_only_one_selected_document(self):
        request = GoogleDocsSelectedDocumentRequest(DOCUMENT_ID)
        transport = _ScriptedTransport(
            [
                (
                    "document",
                    _response(
                        _document("Selected", "Untrusted provider text"),
                        request_id="docs-read",
                    ),
                )
            ]
        )
        token = SecretValue(b"docs-token")
        self.addCleanup(token.close)

        execution = await GoogleDocsAdapter(
            _account(CapabilityId.DOCS_DOCUMENT_READ),
            transport,
        ).execute(
            _call(request, CapabilityId.DOCS_DOCUMENT_READ),
            request,
            token,
        )

        self.assertEqual(
            execution.output.tabs[0].content_text,
            "Untrusted provider text",
        )
        self.assertEqual(
            transport.calls[0][1]["document_id"],
            DOCUMENT_ID,
        )
        self.assertFalse(transport.calls[0][1]["for_update"])
        self.assertFalse(transport.script)

    async def test_create_once_inserts_and_exactly_reads_back(self):
        request = _request()
        transport = _ScriptedTransport(
            [
                (
                    "list",
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    ),
                ),
                (
                    "create",
                    _response(
                        _drive_file(request, include_url=False),
                        request_id="drive-create",
                    ),
                ),
                (
                    "document",
                    _response(
                        _document(request.title, ""),
                        request_id="docs-empty",
                    ),
                ),
                (
                    "insert",
                    _response(
                        {"documentId": DOCUMENT_ID, "replies": [{}]},
                        request_id="docs-insert",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata",
                    ),
                ),
                (
                    "document",
                    _response(
                        _document(request.title, request.body_text),
                        request_id="docs-readback",
                    ),
                ),
            ]
        )
        token = SecretValue(b"docs-token")
        self.addCleanup(token.close)

        execution = await GoogleDocsAdapter(
            _account(CapabilityId.DOCS_DOCUMENT_CREATE),
            transport,
        ).execute(
            _call(request, CapabilityId.DOCS_DOCUMENT_CREATE),
            request,
            token,
        )

        self.assertEqual(execution.output.idempotency_status, "created")
        self.assertTrue(execution.output.verified)
        self.assertEqual(
            [name for name, _values in transport.calls],
            [
                "list",
                "create",
                "document",
                "insert",
                "metadata",
                "document",
            ],
        )
        self.assertEqual(
            transport.calls[1][1]["payload"],
            request.create_payload(),
        )
        self.assertEqual(
            transport.calls[3][1]["payload"],
            request.batch_payload(required_revision_id="revision-1"),
        )
        self.assertFalse(transport.script)

    async def test_exact_existing_document_is_read_only_recovery(self):
        request = _request()
        transport = _ScriptedTransport(
            [
                (
                    "list",
                    _response(
                        {
                            "files": [
                                _drive_file(request, include_url=False)
                            ],
                            "incompleteSearch": False,
                        },
                        request_id="drive-list",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata",
                    ),
                ),
                (
                    "document",
                    _response(
                        _document(request.title, request.body_text),
                        request_id="docs-readback",
                    ),
                ),
            ]
        )
        token = SecretValue(b"docs-token")
        self.addCleanup(token.close)

        execution = await GoogleDocsAdapter(
            _account(CapabilityId.DOCS_DOCUMENT_CREATE),
            transport,
        ).execute(
            _call(request, CapabilityId.DOCS_DOCUMENT_CREATE),
            request,
            token,
        )

        self.assertEqual(
            execution.output.idempotency_status,
            "recovered_verified",
        )
        self.assertEqual(
            [name for name, _values in transport.calls],
            ["list", "metadata", "document"],
        )

    async def test_ambiguous_key_and_wrong_readback_fail_closed(self):
        request = _request()
        duplicate = _drive_file(request, include_url=False)
        duplicate["id"] = "document_456"
        ambiguous = _ScriptedTransport(
            [
                (
                    "list",
                    _response(
                        {
                            "files": [
                                _drive_file(request, include_url=False),
                                duplicate,
                            ]
                        },
                        request_id="drive-list",
                    ),
                )
            ]
        )
        token = SecretValue(b"docs-token")
        self.addCleanup(token.close)
        with self.assertRaises(GoogleDocsIdempotencyConflictError):
            await GoogleDocsAdapter(
                _account(CapabilityId.DOCS_DOCUMENT_CREATE),
                ambiguous,
            ).execute(
                _call(request, CapabilityId.DOCS_DOCUMENT_CREATE),
                request,
                token,
            )

        wrong = _ScriptedTransport(
            [
                (
                    "list",
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    ),
                ),
                (
                    "create",
                    _response(
                        _drive_file(request, include_url=False),
                        request_id="drive-create",
                    ),
                ),
                (
                    "document",
                    _response(
                        _document(request.title, ""),
                        request_id="docs-empty",
                    ),
                ),
                (
                    "insert",
                    _response(
                        {"documentId": DOCUMENT_ID, "replies": [{}]},
                        request_id="docs-insert",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata",
                    ),
                ),
                (
                    "document",
                    _response(
                        _document(request.title, "changed"),
                        request_id="docs-readback",
                    ),
                ),
            ]
        )
        with self.assertRaises(GoogleDocsCreateVerificationError):
            await GoogleDocsAdapter(
                _account(CapabilityId.DOCS_DOCUMENT_CREATE),
                wrong,
            ).execute(
                _call(request, CapabilityId.DOCS_DOCUMENT_CREATE),
                request,
                SecretValue(b"other-token"),
            )

    async def test_unknown_mutation_outcome_is_not_retried(self):
        request = _request()
        transport = _ScriptedTransport(
            [
                (
                    "list",
                    _response(
                        {"files": [], "incompleteSearch": False},
                        request_id="drive-list",
                    ),
                ),
                (
                    "create",
                    GoogleDocsCreateOutcomeUnknownError("unknown"),
                ),
            ]
        )
        with self.assertRaises(GoogleDocsCreateOutcomeUnknownError):
            await GoogleDocsAdapter(
                _account(CapabilityId.DOCS_DOCUMENT_CREATE),
                transport,
            ).execute(
                _call(request, CapabilityId.DOCS_DOCUMENT_CREATE),
                request,
                SecretValue(b"docs-token"),
            )
        self.assertEqual(
            [name for name, _values in transport.calls],
            ["list", "create"],
        )

    def test_transport_has_fixed_hosts_and_no_proxy_or_redirect_following(self):
        source = Path("connectors/google_docs.py").read_text(
            encoding="utf-8"
        )

        self.assertIn('urllib.request.ProxyHandler({})', source)
        self.assertIn("_NoRedirectHandler()", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("urlopen(", source)
        with self.assertRaises(ConnectorRequestError):
            FixedGoogleDocsHttpsTransport(
                _opener=object()
            )._request(
                endpoint="https://evil.example/v1/documents/x",
                method="GET",
                body=None,
                access_token=SecretValue(b"token"),
                maximum_response_bytes=1024,
                mutation=False,
            )


if __name__ == "__main__":
    unittest.main()
