"""Bounded Google Slides create-once and exact read-back tests."""

from __future__ import annotations

import hashlib
import json
import unittest
from collections.abc import Mapping

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
    SecretValue,
)
from connectors.google_slides import (
    GOOGLE_SLIDES_EXPORT_OPERATION_ID,
    GOOGLE_SLIDES_MIME_TYPE,
    FixedGoogleSlidesHttpsTransport,
    GoogleSlidesExportAdapter,
    GoogleSlidesExportOutcomeUnknownError,
    GoogleSlidesExportRequest,
    GoogleSlidesExportVerificationError,
    GoogleSlidesIdempotencyConflictError,
    SlidesHttpResponse,
)
from slides_contracts import (
    MAX_SLIDES_SOURCE_BYTES,
    SlideSpecificationValidationError,
    parse_validated_slide_specification,
)


SOURCE = (
    b'{"schema_version":1,"slides":['
    b'{"text":"First body","title":"First"},'
    b'{"text":"Second body","title":"Second"}'
    b'],"title":"Reviewed deck"}'
)
SOURCE_SHA256 = hashlib.sha256(SOURCE).hexdigest()
PRESENTATION_ID = "presentation_123"


def _specification():
    return parse_validated_slide_specification(
        SOURCE,
        expected_sha256=SOURCE_SHA256,
    )


def _request() -> GoogleSlidesExportRequest:
    return GoogleSlidesExportRequest(
        specification=_specification(),
        idempotency_key="task.slides-export-1",
    )


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.slides-one",
            connector=ConnectorId.GOOGLE_SLIDES,
            account_reference="google.slides-one",
            capabilities=frozenset(
                {CapabilityId.SLIDES_PRESENTATION_WRITE}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.SLIDES_PRESENTATIONS_WRITE}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _call(request: GoogleSlidesExportRequest) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-slides",
        run_id="run-slides",
        authorization_id="oauth.slides-one",
        connector=ConnectorId.GOOGLE_SLIDES,
        capability=CapabilityId.SLIDES_PRESENTATION_WRITE,
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
) -> SlidesHttpResponse:
    return SlidesHttpResponse(
        status=status,
        content_type="application/json; charset=UTF-8",
        body=json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        provider_request_id=request_id,
    )


def _drive_file(
    request: GoogleSlidesExportRequest,
    *,
    include_url: bool,
) -> dict[str, object]:
    value: dict[str, object] = {
        "appProperties": request.app_properties,
        "id": PRESENTATION_ID,
        "mimeType": GOOGLE_SLIDES_MIME_TYPE,
        "name": request.specification.title,
        "trashed": False,
    }
    if include_url:
        value["webViewLink"] = (
            "https://docs.google.com/presentation/d/"
            f"{PRESENTATION_ID}/edit"
        )
    return value


def _presentation(
    request: GoogleSlidesExportRequest,
    *,
    populated: bool,
) -> dict[str, object]:
    value: dict[str, object] = {
        "presentationId": PRESENTATION_ID,
        "title": request.specification.title,
    }
    if populated:
        slides = []
        for index, slide in enumerate(
            request.specification.slides,
            start=1,
        ):
            slides.append(
                {
                    "objectId": f"clicky_slide_{index:02d}",
                    "pageElements": [
                        _text_element(
                            f"clicky_title_{index:02d}",
                            slide.title,
                        ),
                        _text_element(
                            f"clicky_body_{index:02d}",
                            slide.text,
                        ),
                    ],
                }
            )
        value["slides"] = slides
    else:
        value["slides"] = []
    return value


def _text_element(object_id: str, text: str) -> dict[str, object]:
    return {
        "objectId": object_id,
        "shape": {
            "shapeType": "TEXT_BOX",
            "text": {
                "textElements": [
                    {"textRun": {"content": text + "\n"}}
                ]
            },
        },
    }


def _batch_response(
    request: GoogleSlidesExportRequest,
    *,
    deleted_initial_slide: bool,
) -> dict[str, object]:
    replies: list[dict[str, object]] = []
    if deleted_initial_slide:
        replies.append({})
    for index in range(1, request.specification.slide_count + 1):
        replies.extend(
            [
                {"createSlide": {"objectId": f"clicky_slide_{index:02d}"}},
                {"createShape": {"objectId": f"clicky_title_{index:02d}"}},
                {},
                {"createShape": {"objectId": f"clicky_body_{index:02d}"}},
                {},
            ]
        )
    return {
        "presentationId": PRESENTATION_ID,
        "replies": replies,
    }


class _ScriptedTransport:
    def __init__(
        self,
        script: list[tuple[str, SlidesHttpResponse | BaseException]],
    ) -> None:
        self.script = list(script)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def _next(self, name: str, values: dict[str, object]):
        self.calls.append((name, values))
        if not self.script:
            raise AssertionError("unexpected provider request")
        expected, result = self.script.pop(0)
        if expected != name:
            raise AssertionError(
                f"expected provider request {expected}, got {name}"
            )
        if isinstance(result, BaseException):
            raise result
        return result

    def list_exports(self, **values):
        return self._next("list", values)

    def create_presentation_file(self, **values):
        values["payload"] = dict(values["payload"])
        return self._next("create", values)

    def get_file_metadata(self, **values):
        return self._next("metadata", values)

    def get_presentation(self, **values):
        return self._next("presentation", values)

    def batch_update(self, **values):
        values["payload"] = dict(values["payload"])
        return self._next("batch", values)


def _listed(
    request: GoogleSlidesExportRequest,
) -> SlidesHttpResponse:
    return _response(
        {
            "files": [_drive_file(request, include_url=False)],
            "incompleteSearch": False,
        },
        request_id="drive-list",
    )


class SlideContractTests(unittest.TestCase):
    def test_strict_specification_and_full_approval_preview(self):
        specification = _specification()
        preview = json.loads(
            specification.preview_text(
                authorization_id="oauth.slides-one",
                idempotency_key="task.slides-export-1",
            )
        )

        self.assertEqual(preview["title"], "Reviewed deck")
        self.assertEqual(
            preview["slides"],
            [
                {"text": "First body", "title": "First"},
                {"text": "Second body", "title": "Second"},
            ],
        )
        self.assertNotIn("task.slides-export-1", json.dumps(preview))
        self.assertEqual(preview["source_sha256"], SOURCE_SHA256)

    def test_rejects_duplicate_extra_multiline_and_oversized_sources(self):
        invalid = (
            b'{"schema_version":1,"schema_version":1,'
            b'"slides":[{"text":"body","title":"title"}],'
            b'"title":"deck"}'
        )
        cases = [
            invalid,
            (
                b'{"extra":true,"schema_version":1,'
                b'"slides":[{"text":"body","title":"title"}],'
                b'"title":"deck"}'
            ),
            (
                b'{"schema_version":1,"slides":['
                b'{"text":"line\\nline","title":"title"}],'
                b'"title":"deck"}'
            ),
            b" " * (MAX_SLIDES_SOURCE_BYTES + 1),
        ]
        for content in cases:
            with self.subTest(content_length=len(content)):
                with self.assertRaises(
                    SlideSpecificationValidationError
                ):
                    parse_validated_slide_specification(
                        content,
                        expected_sha256=hashlib.sha256(
                            content
                        ).hexdigest(),
                    )

    def test_batch_is_text_only_bounded_and_deterministic(self):
        request = _request()
        payload = request.batch_payload(
            initial_slide_ids=("initial_slide_123",)
        )
        encoded = json.dumps(payload, sort_keys=True)

        self.assertEqual(len(payload["requests"]), 11)
        self.assertIn("deleteObject", encoded)
        self.assertIn("createSlide", encoded)
        self.assertIn("createShape", encoded)
        self.assertIn("insertText", encoded)
        self.assertNotIn("createImage", encoded)
        self.assertNotIn("createVideo", encoded)
        self.assertNotIn("createSheetsChart", encoded)
        self.assertNotIn("updateTextStyle", encoded)
        self.assertNotIn("link", encoded.casefold())
        self.assertEqual(
            payload["requests"][1]["createSlide"]["objectId"],
            "clicky_slide_01",
        )


class GoogleSlidesAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_create_once_populates_and_exactly_reads_back(self):
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
                    "presentation",
                    _response(
                        {
                            "presentationId": PRESENTATION_ID,
                            "slides": [
                                {
                                    "objectId": "initial_slide_123",
                                    "pageElements": [],
                                }
                            ],
                            "title": request.specification.title,
                        },
                        request_id="slides-initial",
                    ),
                ),
                (
                    "batch",
                    _response(
                        _batch_response(
                            request,
                            deleted_initial_slide=True,
                        ),
                        request_id="slides-batch",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-readback",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        _presentation(request, populated=True),
                        request_id="slides-readback",
                    ),
                ),
            ]
        )
        execution = await GoogleSlidesExportAdapter(
            _account(),
            transport,
        ).execute(
            _call(request),
            request,
            SecretValue(b"slides-token"),
        )

        self.assertEqual(execution.output.idempotency_status, "created")
        self.assertEqual(
            execution.output.slide_titles,
            ("First", "Second"),
        )
        self.assertTrue(execution.output.verified)
        self.assertEqual(len(transport.calls), 6)
        self.assertFalse(transport.script)
        create_payload = transport.calls[1][1]["payload"]
        self.assertEqual(
            create_payload,
            {
                "appProperties": request.app_properties,
                "mimeType": GOOGLE_SLIDES_MIME_TYPE,
                "name": request.specification.title,
            },
        )
        batch_payload = transport.calls[3][1]["payload"]
        self.assertEqual(
            batch_payload["requests"][0],
            {"deleteObject": {"objectId": "initial_slide_123"}},
        )

    async def test_exact_existing_export_is_read_only_recovery(self):
        request = _request()
        transport = _ScriptedTransport(
            [
                ("list", _listed(request)),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        _presentation(request, populated=True),
                        request_id="slides-readback",
                    ),
                ),
            ]
        )
        execution = await GoogleSlidesExportAdapter(
            _account(),
            transport,
        ).execute(
            _call(request),
            request,
            SecretValue(b"slides-token"),
        )

        self.assertEqual(
            execution.output.idempotency_status,
            "recovered_verified",
        )
        self.assertEqual(
            [name for name, _ in transport.calls],
            ["list", "metadata", "presentation"],
        )

    async def test_empty_existing_export_is_populated_once(self):
        request = _request()
        transport = _ScriptedTransport(
            [
                ("list", _listed(request)),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata-1",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        _presentation(request, populated=False),
                        request_id="slides-empty",
                    ),
                ),
                (
                    "batch",
                    _response(
                        _batch_response(
                            request,
                            deleted_initial_slide=False,
                        ),
                        request_id="slides-batch",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata-2",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        _presentation(request, populated=True),
                        request_id="slides-readback",
                    ),
                ),
            ]
        )
        execution = await GoogleSlidesExportAdapter(
            _account(),
            transport,
        ).execute(
            _call(request),
            request,
            SecretValue(b"slides-token"),
        )

        self.assertEqual(
            execution.output.idempotency_status,
            "recovered_empty",
        )
        self.assertEqual(len(transport.calls), 6)

    async def test_existing_different_content_fails_without_mutation(self):
        request = _request()
        different = _presentation(request, populated=True)
        different["slides"][0]["pageElements"][1]["shape"]["text"][
            "textElements"
        ][0]["textRun"]["content"] = "changed"
        transport = _ScriptedTransport(
            [
                ("list", _listed(request)),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-metadata",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        different,
                        request_id="slides-different",
                    ),
                ),
            ]
        )

        with self.assertRaises(GoogleSlidesIdempotencyConflictError):
            await GoogleSlidesExportAdapter(
                _account(),
                transport,
            ).execute(
                _call(request),
                request,
                SecretValue(b"slides-token"),
            )
        self.assertEqual(
            [name for name, _ in transport.calls],
            ["list", "metadata", "presentation"],
        )

    async def test_bad_final_readback_is_not_reported_as_success(self):
        request = _request()
        wrong = _presentation(request, populated=True)
        wrong["slides"][1]["objectId"] = "wrong_slide_02"
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
                    "presentation",
                    _response(
                        _presentation(request, populated=False),
                        request_id="slides-initial",
                    ),
                ),
                (
                    "batch",
                    _response(
                        _batch_response(
                            request,
                            deleted_initial_slide=False,
                        ),
                        request_id="slides-batch",
                    ),
                ),
                (
                    "metadata",
                    _response(
                        _drive_file(request, include_url=True),
                        request_id="drive-readback",
                    ),
                ),
                (
                    "presentation",
                    _response(
                        wrong,
                        request_id="slides-readback",
                    ),
                ),
            ]
        )

        with self.assertRaises(GoogleSlidesExportVerificationError):
            await GoogleSlidesExportAdapter(
                _account(),
                transport,
            ).execute(
                _call(request),
                request,
                SecretValue(b"slides-token"),
            )

    async def test_mutation_transport_uncertainty_propagates(self):
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
                    GoogleSlidesExportOutcomeUnknownError(
                        "mutation outcome unknown"
                    ),
                ),
            ]
        )

        with self.assertRaises(GoogleSlidesExportOutcomeUnknownError):
            await GoogleSlidesExportAdapter(
                _account(),
                transport,
            ).execute(
                _call(request),
                request,
                SecretValue(b"slides-token"),
            )


class _HttpResponse:
    status = 200
    headers = {
        "Content-Type": "application/json",
        "X-Goog-Request-Id": "request-1",
    }

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, _maximum: int) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class _CapturingOpener:
    def __init__(self) -> None:
        self.requests = []

    def open(self, request, *, timeout):
        self.requests.append((request, timeout))
        return _HttpResponse(b"{}")


class GoogleSlidesTransportTests(unittest.TestCase):
    def test_drive_create_is_fixed_private_and_does_not_leak_token(self):
        opener = _CapturingOpener()
        transport = FixedGoogleSlidesHttpsTransport(_opener=opener)
        token = SecretValue(b"secret-slides-token")
        request = _request()

        transport.create_presentation_file(
            payload=request.create_payload(),
            access_token=token,
            maximum_response_bytes=1024,
        )

        captured, _timeout = opener.requests[0]
        self.assertEqual(captured.get_method(), "POST")
        self.assertEqual(
            captured.full_url,
            "https://www.googleapis.com/drive/v3/files?"
            "fields=id%2Cname%2CmimeType%2CappProperties%2Ctrashed"
            "&ignoreDefaultVisibility=true",
        )
        self.assertEqual(
            captured.headers["Authorization"],
            "Bearer secret-slides-token",
        )
        self.assertNotIn(
            b"secret-slides-token",
            captured.data or b"",
        )
        self.assertEqual(
            json.loads(captured.data),
            request.create_payload(),
        )


if __name__ == "__main__":
    unittest.main()
