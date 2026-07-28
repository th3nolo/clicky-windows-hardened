"""Gmail exact selected-thread read and verified unsent-draft tests."""

from __future__ import annotations

import base64
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
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorTokenExpiredError,
    SecretValue,
)
from connectors.gmail import (
    GMAIL_API_ROOT,
    FixedGmailHttpsTransport,
    GmailDraftOutcomeUnknownError,
    GmailDraftRequest,
    GmailDraftResult,
    GmailDraftVerificationError,
    GmailHttpResponse,
    GmailSelectedThreadRequest,
    GmailSelectedThreadResult,
    GoogleGmailAdapter,
)


def _encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.gmail-one",
            connector=ConnectorId.GMAIL,
            account_reference="google.gmail-one",
            capabilities=frozenset(
                {
                    CapabilityId.GMAIL_MESSAGE_READ,
                    CapabilityId.GMAIL_DRAFT_WRITE,
                }
            ),
            oauth_scopes=frozenset(
                {
                    OAuthScopeId.GMAIL_MESSAGES_READ,
                    OAuthScopeId.GMAIL_DRAFTS_WRITE,
                }
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _call(request, *, capability: CapabilityId) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-gmail",
        run_id="run-gmail",
        authorization_id="oauth.gmail-one",
        connector=ConnectorId.GMAIL,
        capability=capability,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=1024 * 1024,
    )


def _thread_body() -> bytes:
    return json.dumps(
        {
            "id": "thread-123",
            "historyId": "70",
            "messages": [
                {
                    "id": "message-1",
                    "threadId": "thread-123",
                    "internalDate": "1785100000000",
                    "labelIds": ["INBOX"],
                    "snippet": "private redundant snippet",
                    "payload": {
                        "partId": "",
                        "mimeType": "multipart/mixed",
                        "filename": "",
                        "headers": [
                            {
                                "name": "From",
                                "value": "sender@example.com",
                            },
                            {
                                "name": "Subject",
                                "value": "Selected subject",
                            },
                            {
                                "name": "X-Private-Trace",
                                "value": "must-not-be-exported",
                            },
                        ],
                        "body": {"size": 0},
                        "parts": [
                            {
                                "partId": "0",
                                "mimeType": "text/plain",
                                "filename": "",
                                "headers": [],
                                "body": {
                                    "size": 19,
                                    "data": _encoded(
                                        b"Selected body text"
                                    ),
                                },
                            },
                            {
                                "partId": "1",
                                "mimeType": "application/pdf",
                                "filename": "private.pdf",
                                "headers": [],
                                "body": {
                                    "attachmentId": "attachment-1",
                                    "size": 500,
                                },
                            },
                        ],
                    },
                    "sizeEstimate": 1000,
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _FakeTransport:
    def __init__(self, *, gets=(), posts=()) -> None:
        self.gets = list(gets)
        self.posts = list(posts)
        self.calls = []

    def get_json(
        self,
        *,
        endpoint,
        access_token,
        maximum_response_bytes,
    ):
        self.calls.append(
            (
                "GET",
                endpoint,
                access_token.reveal(),
                maximum_response_bytes,
            )
        )
        return self.gets.pop(0)

    def post_json(
        self,
        *,
        endpoint,
        payload,
        access_token,
        maximum_response_bytes,
    ):
        self.calls.append(
            (
                "POST",
                endpoint,
                dict(payload),
                access_token.reveal(),
                maximum_response_bytes,
            )
        )
        return self.posts.pop(0)


class GmailSelectedThreadTests(unittest.IsolatedAsyncioTestCase):
    def test_request_is_exact_bounded_and_has_no_search_surface(self):
        first = GmailSelectedThreadRequest("thread-123")
        second = GmailSelectedThreadRequest("thread-456")

        self.assertNotEqual(first.request_digest, second.request_digest)
        self.assertNotIn("q=", first.endpoint)
        self.assertNotIn("list", first.operation_id)
        with self.assertRaises(ValueError):
            GmailSelectedThreadRequest("thread/escape")

    async def test_reads_only_exact_selected_thread_and_omits_attachments(self):
        body = _thread_body()
        transport = _FakeTransport(
            gets=[
                GmailHttpResponse(
                    status=200,
                    content_type="application/json; charset=UTF-8",
                    body=body,
                    provider_request_id="gmail-read-request",
                )
            ]
        )
        adapter = GoogleGmailAdapter(_account(), transport)
        request = GmailSelectedThreadRequest("thread-123")
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(
                request,
                capability=CapabilityId.GMAIL_MESSAGE_READ,
            ),
            request,
            token,
        )

        self.assertIsInstance(execution, ConnectorExecution)
        self.assertIsInstance(execution.output, GmailSelectedThreadResult)
        self.assertEqual(execution.output.thread_id, "thread-123")
        self.assertEqual(
            execution.output.messages[0].body_text,
            "Selected body text",
        )
        exported = execution.output.to_json_bytes()
        self.assertNotIn(b"private.pdf", exported)
        self.assertNotIn(b"attachment-1", exported)
        self.assertNotIn(b"must-not-be-exported", exported)
        self.assertEqual(
            execution.result.response_digest,
            hashlib.sha256(body).hexdigest(),
        )
        self.assertEqual(
            transport.calls[0][1],
            f"{GMAIL_API_ROOT}/threads/thread-123?format=full",
        )
        self.assertNotIn("query", request.__dict__ if hasattr(request, "__dict__") else {})

    async def test_rejects_provider_thread_identity_mismatch(self):
        payload = json.loads(_thread_body())
        payload["id"] = "another-thread"
        adapter = GoogleGmailAdapter(
            _account(),
            _FakeTransport(
                gets=[
                    GmailHttpResponse(
                        status=200,
                        content_type="application/json",
                        body=json.dumps(payload).encode("utf-8"),
                    )
                ]
            ),
        )
        request = GmailSelectedThreadRequest("thread-123")
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        with self.assertRaisesRegex(
            ConnectorResponseError,
            "selected-thread response shape",
        ):
            await adapter.execute(
                _call(
                    request,
                    capability=CapabilityId.GMAIL_MESSAGE_READ,
                ),
                request,
                token,
            )

    async def test_expired_and_rate_limited_reads_are_explicit(self):
        request = GmailSelectedThreadRequest("thread-123")
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)
        expired = GoogleGmailAdapter(
            _account(),
            _FakeTransport(
                gets=[
                    GmailHttpResponse(
                        status=401,
                        content_type="application/json",
                        body=b'{"error":{"code":401}}',
                    )
                ]
            ),
        )
        with self.assertRaises(ConnectorTokenExpiredError):
            await expired.execute(
                _call(
                    request,
                    capability=CapabilityId.GMAIL_MESSAGE_READ,
                ),
                request,
                token,
            )

        limited = GoogleGmailAdapter(
            _account(),
            _FakeTransport(
                gets=[
                    GmailHttpResponse(
                        status=429,
                        content_type="application/json",
                        body=b'{"error":{"code":429}}',
                        retry_after_seconds=17,
                    )
                ]
            ),
        )
        with self.assertRaises(ConnectorRateLimitError) as raised:
            await limited.execute(
                _call(
                    request,
                    capability=CapabilityId.GMAIL_MESSAGE_READ,
                ),
                request,
                token,
            )
        self.assertEqual(raised.exception.retry_after_seconds, 17)


class GmailDraftTests(unittest.IsolatedAsyncioTestCase):
    def test_request_rejects_header_injection_and_binds_exact_preview(self):
        request = GmailDraftRequest(
            to=("recipient@example.com",),
            subject="Reviewed subject",
            body_text="Reviewed body",
        )
        changed = GmailDraftRequest(
            to=("recipient@example.com",),
            subject="Reviewed subject",
            body_text="Changed body",
        )

        self.assertNotEqual(request.request_digest, changed.request_digest)
        representation = repr(request)
        self.assertNotIn("recipient@example.com", representation)
        self.assertNotIn("Reviewed subject", representation)
        self.assertNotIn("Reviewed body", representation)
        with self.assertRaises(ValueError):
            GmailDraftRequest(
                to=("recipient@example.com\r\nBcc: attacker@example.com",),
                subject="Reviewed subject",
                body_text="Reviewed body",
            )
        with self.assertRaises(ValueError):
            GmailDraftRequest(
                to=("recipient@example.com",),
                subject="Reviewed\r\nBcc: attacker@example.com",
                body_text="Reviewed body",
            )
        with self.assertRaises(ValueError):
            GmailDraftRequest(
                to=("recipient@example.com",),
                cc=("RECIPIENT@example.com",),
                subject="Reviewed subject",
                body_text="Reviewed body",
            )

    async def test_creates_unsent_draft_and_verifies_exact_read_back(self):
        request = GmailDraftRequest(
            to=("recipient@example.com",),
            cc=("copy@example.com",),
            bcc=(),
            subject="Reviewed subject",
            body_text="Reviewed body",
        )
        created = json.dumps(
            {
                "id": "draft-123",
                "message": {
                    "id": "message-123",
                    "threadId": "thread-123",
                    "labelIds": ["DRAFT"],
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        verified = json.dumps(
            {
                "id": "draft-123",
                "message": {
                    "id": "message-123",
                    "threadId": "thread-123",
                    "labelIds": ["DRAFT"],
                    "raw": _encoded(request.raw_message()),
                },
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        transport = _FakeTransport(
            posts=[
                GmailHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=created,
                    provider_request_id="gmail-create-request",
                )
            ],
            gets=[
                GmailHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=verified,
                    provider_request_id="gmail-verify-request",
                )
            ],
        )
        adapter = GoogleGmailAdapter(_account(), transport)
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(
                request,
                capability=CapabilityId.GMAIL_DRAFT_WRITE,
            ),
            request,
            token,
        )

        self.assertIsInstance(execution.output, GmailDraftResult)
        self.assertTrue(execution.output.verified)
        self.assertEqual(
            [item[0] for item in transport.calls],
            ["POST", "GET"],
        )
        self.assertEqual(
            transport.calls[0][1],
            f"{GMAIL_API_ROOT}/drafts",
        )
        self.assertEqual(
            transport.calls[1][1],
            f"{GMAIL_API_ROOT}/drafts/draft-123?format=raw",
        )
        self.assertEqual(
            execution.result.response_digest,
            hashlib.sha256(created + b"\x00" + verified).hexdigest(),
        )
        self.assertNotIn("send", transport.calls[0][1])

    async def test_mismatched_read_back_fails_closed(self):
        request = GmailDraftRequest(
            to=("recipient@example.com",),
            subject="Reviewed subject",
            body_text="Reviewed body",
        )
        other = GmailDraftRequest(
            to=("attacker@example.com",),
            subject="Reviewed subject",
            body_text="Reviewed body",
        )
        created = b'{"id":"draft-123","message":{"id":"message-123","threadId":"thread-123"}}'
        verified = json.dumps(
            {
                "id": "draft-123",
                "message": {
                    "id": "message-123",
                    "threadId": "thread-123",
                    "raw": _encoded(other.raw_message()),
                },
            }
        ).encode("utf-8")
        adapter = GoogleGmailAdapter(
            _account(),
            _FakeTransport(
                posts=[
                    GmailHttpResponse(
                        status=200,
                        content_type="application/json",
                        body=created,
                    )
                ],
                gets=[
                    GmailHttpResponse(
                        status=200,
                        content_type="application/json",
                        body=verified,
                    )
                ],
            ),
        )
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        with self.assertRaisesRegex(
            GmailDraftVerificationError,
            "does not match",
        ):
            await adapter.execute(
                _call(
                    request,
                    capability=CapabilityId.GMAIL_DRAFT_WRITE,
                ),
                request,
                token,
            )


class FixedGmailTransportTests(unittest.TestCase):
    def test_transport_rejects_endpoint_variation_before_token_or_io(self):
        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("unexpected network request")

        opener = Opener()
        transport = FixedGmailHttpsTransport(_opener=opener)
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        for endpoint in (
            f"{GMAIL_API_ROOT}/threads/thread-1?format=full&q=all",
            f"{GMAIL_API_ROOT}/threads/thread%2Fescape?format=full",
            "https://example.com/gmail/v1/users/me/threads/thread-1?format=full",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ConnectorRequestError):
                    transport.get_json(
                        endpoint=endpoint,
                        access_token=token,
                        maximum_response_bytes=4096,
                    )
        self.assertEqual(opener.calls, [])

    def test_write_transport_does_not_retry_unknown_outcome(self):
        class Opener:
            def __init__(self):
                self.calls = 0

            def open(self, *_args, **_kwargs):
                self.calls += 1
                raise urllib.error.URLError("ambiguous timeout")

        opener = Opener()
        transport = FixedGmailHttpsTransport(_opener=opener)
        token = SecretValue(b"gmail-access-token")
        self.addCleanup(token.close)

        with self.assertRaises(GmailDraftOutcomeUnknownError):
            transport.post_json(
                endpoint=f"{GMAIL_API_ROOT}/drafts",
                payload={"message": {"raw": "abc"}},
                access_token=token,
                maximum_response_bytes=4096,
            )

        self.assertEqual(opener.calls, 1)

    def test_source_uses_fixed_https_without_proxy_redirect_or_send(self):
        source = Path("connectors/gmail.py").read_text(encoding="utf-8")
        self.assertIn("urllib.request.ProxyHandler({})", source)
        self.assertIn("_NoRedirectHandler()", source)
        self.assertNotIn("urllib.request.urlopen", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("aiohttp", source)
        self.assertNotIn("/messages/send", source)
        self.assertNotIn("/drafts/send", source)


if __name__ == "__main__":
    unittest.main()
