"""Notion selected-page read and inert local-draft tests."""

from __future__ import annotations

import hashlib
import json
import unittest
import uuid

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
from connectors.notion import (
    MAX_NOTION_PROVIDER_REQUESTS,
    NOTION_API_ROOT,
    NOTION_API_VERSION,
    FixedNotionHttpsTransport,
    NotionHttpResponse,
    NotionSelectedPageAdapter,
    NotionSelectedPageRequest,
    NotionSelectedPageResult,
    render_notion_local_draft,
)


PAGE_ID = "11111111-1111-4111-8111-111111111111"
BLOCK_ONE = "22222222-2222-4222-8222-222222222222"
BLOCK_TWO = "33333333-3333-4333-8333-333333333333"
BLOCK_THREE = "44444444-4444-4444-8444-444444444444"


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.NOTION,
        authorization=AccountAuthorization(
            authorization_id="oauth.notion-one",
            connector=ConnectorId.NOTION,
            account_reference="notion.workspace-one",
            capabilities=frozenset({CapabilityId.NOTION_PAGE_READ}),
            oauth_scopes=frozenset({OAuthScopeId.NOTION_PAGES_READ}),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _call(request: NotionSelectedPageRequest) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-notion",
        run_id="run-notion",
        authorization_id="oauth.notion-one",
        connector=ConnectorId.NOTION,
        capability=CapabilityId.NOTION_PAGE_READ,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=1024 * 1024,
    )


def _response(value: object, *, request_id: str | None = None):
    return NotionHttpResponse(
        status=200,
        content_type="application/json; charset=utf-8",
        body=json.dumps(
            value,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8"),
        provider_request_id=request_id,
    )


def _page() -> dict[str, object]:
    return {
        "object": "page",
        "id": PAGE_ID,
        "archived": False,
        "in_trash": False,
        "properties": {
            "Name": {
                "id": "title",
                "type": "title",
                "title": [
                    {
                        "type": "text",
                        "plain_text": "Selected project",
                        "text": {
                            "content": "Selected project",
                            "link": None,
                        },
                    }
                ],
            },
            "Private owner": {
                "id": "owner",
                "type": "people",
                "people": [
                    {
                        "name": "Must not be exported",
                        "person": {"email": "private@example.com"},
                    }
                ],
            },
        },
        "url": "https://www.notion.so/private-provider-url",
        "public_url": None,
    }


def _children(
    results: list[object],
    *,
    has_more: bool = False,
    next_cursor: str | None = None,
) -> dict[str, object]:
    return {
        "object": "list",
        "type": "block",
        "block": {},
        "results": results,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }


class _FakeTransport:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls = []

    def get_json(
        self,
        *,
        endpoint,
        access_token,
        maximum_response_bytes,
    ):
        self.calls.append(
            (endpoint, access_token.reveal(), maximum_response_bytes)
        )
        return self.responses.pop(0)


class NotionSelectedPageTests(unittest.IsolatedAsyncioTestCase):
    def test_request_is_exact_versioned_and_has_no_search_or_write_surface(self):
        request = NotionSelectedPageRequest(PAGE_ID.upper())

        self.assertEqual(request.selected_page_id, PAGE_ID)
        self.assertEqual(
            request.page_endpoint,
            f"{NOTION_API_ROOT}/pages/{PAGE_ID}",
        )
        self.assertEqual(NOTION_API_VERSION, "2026-03-11")
        expected_digest = hashlib.sha256(
            json.dumps(
                {
                    "api_version": NOTION_API_VERSION,
                    "maximum_provider_requests": (
                        MAX_NOTION_PROVIDER_REQUESTS
                    ),
                    "selected_page_id": PAGE_ID,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(request.request_digest, expected_digest)
        self.assertNotIn("search", request.page_endpoint)
        self.assertFalse(
            hasattr(FixedNotionHttpsTransport, "post_json")
        )
        with self.assertRaises(ValueError):
            NotionSelectedPageRequest("../search")

    async def test_reads_selected_page_recursively_and_omits_private_metadata(self):
        page_response = _response(_page(), request_id="notion-page-request")
        root_response = _response(
            _children(
                [
                    {
                        "object": "block",
                        "id": BLOCK_ONE,
                        "type": "paragraph",
                        "paragraph": {
                            "rich_text": [
                                {
                                    "type": "text",
                                    "plain_text": "Root text",
                                    "href": "https://private.example/root",
                                }
                            ],
                            "color": "default",
                        },
                        "has_children": True,
                        "archived": False,
                        "in_trash": False,
                    },
                    {
                        "object": "block",
                        "id": BLOCK_TWO,
                        "type": "image",
                        "image": {
                            "type": "external",
                            "external": {
                                "url": "https://private.example/image"
                            },
                        },
                        "has_children": False,
                        "archived": False,
                        "in_trash": False,
                    },
                ]
            )
        )
        nested_response = _response(
            _children(
                [
                    {
                        "object": "block",
                        "id": BLOCK_THREE,
                        "type": "to_do",
                        "to_do": {
                            "rich_text": [
                                {
                                    "type": "text",
                                    "plain_text": "Nested task",
                                }
                            ],
                            "checked": True,
                            "color": "default",
                        },
                        "has_children": False,
                        "archived": False,
                        "in_trash": False,
                    }
                ]
            )
        )
        transport = _FakeTransport(
            [page_response, root_response, nested_response]
        )
        adapter = NotionSelectedPageAdapter(_account(), transport)
        request = NotionSelectedPageRequest(PAGE_ID)
        token = SecretValue(b"notion-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(_call(request), request, token)

        self.assertIsInstance(execution, ConnectorExecution)
        self.assertIsInstance(execution.output, NotionSelectedPageResult)
        self.assertEqual(execution.output.title, "Selected project")
        self.assertEqual(
            [block.text for block in execution.output.blocks],
            ["Root text", "", "Nested task"],
        )
        self.assertEqual(execution.output.blocks[-1].depth, 1)
        self.assertTrue(execution.output.blocks[-1].checked)
        self.assertEqual(execution.output.provider_requests, 3)
        self.assertFalse(execution.output.content_truncated)
        exported = execution.output.to_json_bytes()
        self.assertNotIn(b"private@example.com", exported)
        self.assertNotIn(b"private-provider-url", exported)
        self.assertNotIn(b"private.example/root", exported)
        self.assertNotIn(b"private.example/image", exported)
        evidence = (
            page_response.body
            + b"\x00"
            + root_response.body
            + b"\x00"
            + nested_response.body
        )
        self.assertEqual(
            execution.result.response_digest,
            hashlib.sha256(evidence).hexdigest(),
        )
        self.assertEqual(
            transport.calls[1][0],
            (
                f"{NOTION_API_ROOT}/blocks/{PAGE_ID}/children"
                "?page_size=100"
            ),
        )

    async def test_fixed_request_ceiling_reports_truncation(self):
        responses = [_response(_page())]
        for index in range(MAX_NOTION_PROVIDER_REQUESTS - 1):
            block_id = str(
                uuid.UUID(int=index + 10)
            )
            responses.append(
                _response(
                    _children(
                        [
                            {
                                "object": "block",
                                "id": block_id,
                                "type": "paragraph",
                                "paragraph": {"rich_text": []},
                                "has_children": False,
                            }
                        ],
                        has_more=True,
                        next_cursor=f"opaque-cursor-{index}",
                    )
                )
            )
        adapter = NotionSelectedPageAdapter(
            _account(),
            _FakeTransport(responses),
        )
        request = NotionSelectedPageRequest(PAGE_ID)
        token = SecretValue(b"notion-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(_call(request), request, token)

        self.assertEqual(
            execution.output.provider_requests,
            MAX_NOTION_PROVIDER_REQUESTS,
        )
        self.assertTrue(execution.output.content_truncated)

    async def test_oversized_visible_block_text_is_explicitly_truncated(self):
        long_text = "x" * (16 * 1024 + 1)
        adapter = NotionSelectedPageAdapter(
            _account(),
            _FakeTransport(
                [
                    _response(_page()),
                    _response(
                        _children(
                            [
                                {
                                    "object": "block",
                                    "id": BLOCK_ONE,
                                    "type": "paragraph",
                                    "paragraph": {
                                        "rich_text": [
                                            {
                                                "type": "text",
                                                "plain_text": long_text,
                                            }
                                        ]
                                    },
                                    "has_children": False,
                                }
                            ]
                        )
                    ),
                ]
            ),
        )
        request = NotionSelectedPageRequest(PAGE_ID)
        token = SecretValue(b"notion-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(_call(request), request, token)

        self.assertTrue(execution.output.content_truncated)
        self.assertEqual(len(execution.output.blocks[0].text), 16 * 1024)

    async def test_identity_mismatch_and_provider_errors_fail_closed(self):
        wrong = _page()
        wrong["id"] = BLOCK_ONE
        request = NotionSelectedPageRequest(PAGE_ID)
        token = SecretValue(b"notion-access-token")
        self.addCleanup(token.close)
        adapter = NotionSelectedPageAdapter(
            _account(),
            _FakeTransport([_response(wrong)]),
        )
        with self.assertRaises(ConnectorResponseError):
            await adapter.execute(_call(request), request, token)

        for status, error in (
            (401, ConnectorTokenExpiredError),
            (429, ConnectorRateLimitError),
        ):
            adapter = NotionSelectedPageAdapter(
                _account(),
                _FakeTransport(
                    [
                        NotionHttpResponse(
                            status=status,
                            content_type="application/json",
                            body=b'{"object":"error"}',
                            retry_after_seconds=7 if status == 429 else None,
                        )
                    ]
                ),
            )
            with self.assertRaises(error):
                await adapter.execute(_call(request), request, token)


class NotionLocalDraftTests(unittest.TestCase):
    def test_renders_bounded_unpublished_draft_without_provider_authority(self):
        draft = render_notion_local_draft(
            title="Reviewed notes",
            intended_parent_page_id=PAGE_ID,
            blocks_json=json.dumps(
                [
                    {"type": "heading_1", "text": "Summary"},
                    {
                        "type": "to_do",
                        "text": "Review before publishing",
                        "checked": False,
                    },
                    {
                        "type": "code",
                        "text": "print('safe')",
                        "language": "python",
                    },
                ]
            ),
        )

        payload = json.loads(draft.to_json_bytes())
        self.assertEqual(payload["state"], "local_unpublished")
        self.assertFalse(payload["publication_authorized"])
        self.assertEqual(payload["intended_parent_page_id"], PAGE_ID)
        self.assertNotIn("endpoint", payload)
        self.assertNotIn("authorization_id", payload)

    def test_rejects_urls_extra_fields_and_unsupported_blocks(self):
        with self.assertRaises(ValueError):
            render_notion_local_draft(
                title="Draft",
                blocks_json=json.dumps(
                    [
                        {
                            "type": "paragraph",
                            "text": "Text",
                            "url": "https://unreviewed.example",
                        }
                    ]
                ),
            )
        with self.assertRaises(ValueError):
            render_notion_local_draft(
                title="Draft",
                blocks_json=json.dumps(
                    [{"type": "image", "text": "remote"}]
                ),
            )


class FixedNotionTransportTests(unittest.TestCase):
    def test_rejects_endpoint_variation_before_token_or_io(self):
        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("network must not run")

        opener = Opener()
        transport = FixedNotionHttpsTransport(_opener=opener)
        token = SecretValue(b"notion-access-token")
        self.addCleanup(token.close)
        for endpoint in (
            "https://api.notion.com/v1/search",
            f"https://evil.example/v1/pages/{PAGE_ID}",
            f"{NOTION_API_ROOT}/pages/{PAGE_ID}?extra=true",
            (
                f"{NOTION_API_ROOT}/blocks/{PAGE_ID}/children"
                "?page_size=100&unknown=true"
            ),
        ):
            with self.assertRaises(ConnectorRequestError):
                transport.get_json(
                    endpoint=endpoint,
                    access_token=token,
                    maximum_response_bytes=1024,
                )
        self.assertEqual(opener.calls, [])


if __name__ == "__main__":
    unittest.main()
