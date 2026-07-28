"""Selected-page Notion reads and inert local draft construction.

Notion page reads are limited to one explicitly selected page and a bounded
recursive traversal of its block children. File URLs, comments, people,
database properties, and search results are never represented in the output.

Notion does not expose an unpublished provider-side draft state. This module
therefore validates and renders a local JSON draft only. It deliberately
contains no create, append, update, archive, or publish endpoint.
"""

from __future__ import annotations

import hashlib
import json
import math
import ssl
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from capability_registry import CapabilityId, ConnectorId
from connectors.base import (
    ConnectedAccount,
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorCallResult,
    ConnectorExecution,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorRevocationError,
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenExpiredError,
    SecretValue,
    validate_connector_authority,
)
from notion_contracts import (
    MAX_NOTION_PROVIDER_REQUESTS,
    MAX_NOTION_TITLE_CHARS,
    NotionDraftBlock,
    NotionLocalDraft,
    bounded_notion_text as _bounded_text,
    canonical_notion_id as _notion_id,
    render_notion_local_draft,
)


NOTION_API_ROOT = "https://api.notion.com/v1"
NOTION_API_VERSION = "2026-03-11"
NOTION_SELECTED_PAGE_OPERATION_ID = "notion.read_selected_page"
MAX_NOTION_RESPONSE_BYTES = 1024 * 1024
MAX_NOTION_BLOCKS = 1_000
MAX_NOTION_BLOCK_DEPTH = 16
MAX_NOTION_BLOCK_TEXT_CHARS = 16 * 1024
MAX_NOTION_PAGE_TEXT_CHARS = 256 * 1024
MAX_NOTION_CURSOR_CHARS = 2_048
_PAGE_SIZE = 100
_PAGE_KEYS = frozenset(
    {
        "archived",
        "cover",
        "created_by",
        "created_time",
        "icon",
        "id",
        "in_trash",
        "is_archived",
        "is_locked",
        "last_edited_by",
        "last_edited_time",
        "object",
        "parent",
        "properties",
        "public_url",
        "url",
    }
)
_BLOCK_KEYS = frozenset(
    {
        "archived",
        "created_by",
        "created_time",
        "has_children",
        "id",
        "in_trash",
        "is_archived",
        "is_locked",
        "last_edited_by",
        "last_edited_time",
        "object",
        "parent",
        "type",
    }
)
_TEXT_BLOCK_TYPES = frozenset(
    {
        "bookmark",
        "breadcrumb",
        "bulleted_list_item",
        "callout",
        "child_database",
        "child_page",
        "code",
        "equation",
        "heading_1",
        "heading_2",
        "heading_3",
        "heading_4",
        "numbered_list_item",
        "paragraph",
        "quote",
        "table_row",
        "template",
        "to_do",
        "toggle",
    }
)
_SAFE_BLOCK_TYPES = _TEXT_BLOCK_TYPES | frozenset(
    {
        "audio",
        "column",
        "column_list",
        "divider",
        "embed",
        "file",
        "image",
        "link_preview",
        "meeting_notes",
        "pdf",
        "synced_block",
        "tab",
        "table",
        "table_of_contents",
        "unsupported",
        "video",
    }
)


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
        raise ValueError("Notion value is not canonical JSON") from exc


def _cursor(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_NOTION_CURSOR_CHARS
        or value.strip() != value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ConnectorResponseError("Notion pagination cursor is invalid")
    return value


@dataclass(frozen=True, slots=True)
class NotionSelectedPageRequest:
    """One exact selected page and a fixed recursive provider-request budget."""

    selected_page_id: str = field(repr=False)
    connector: ConnectorId = field(default=ConnectorId.NOTION, init=False)
    capability: CapabilityId = field(
        default=CapabilityId.NOTION_PAGE_READ,
        init=False,
    )
    operation_id: str = field(
        default=NOTION_SELECTED_PAGE_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        canonical_id = _notion_id(
            self.selected_page_id,
            "Selected Notion page ID",
        )
        object.__setattr__(self, "selected_page_id", canonical_id)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "api_version": NOTION_API_VERSION,
                        "maximum_provider_requests": (
                            MAX_NOTION_PROVIDER_REQUESTS
                        ),
                        "selected_page_id": canonical_id,
                    }
                )
            ).hexdigest(),
        )

    @property
    def page_endpoint(self) -> str:
        return f"{NOTION_API_ROOT}/pages/{self.selected_page_id}"

    @staticmethod
    def children_endpoint(
        block_id: str,
        *,
        start_cursor: str | None,
    ) -> str:
        canonical_id = _notion_id(block_id, "Notion parent block ID")
        query: list[tuple[str, str]] = [
            ("page_size", str(_PAGE_SIZE)),
        ]
        if start_cursor is not None:
            query.append(("start_cursor", _cursor(start_cursor)))
        return (
            f"{NOTION_API_ROOT}/blocks/{canonical_id}/children?"
            + urllib.parse.urlencode(query)
        )


@dataclass(frozen=True, slots=True)
class NotionPageBlock:
    block_id: str
    parent_block_id: str
    depth: int
    block_type: str
    text: str = field(repr=False)
    has_children: bool
    checked: bool | None = None
    language: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "block_id",
            _notion_id(self.block_id, "Notion block ID"),
        )
        object.__setattr__(
            self,
            "parent_block_id",
            _notion_id(self.parent_block_id, "Notion parent block ID"),
        )
        if (
            type(self.depth) is not int
            or not 0 <= self.depth < MAX_NOTION_BLOCK_DEPTH
        ):
            raise ValueError("Notion block depth is invalid")
        if self.block_type not in _SAFE_BLOCK_TYPES:
            raise ValueError("Notion block type is invalid")
        _bounded_text(
            self.text,
            MAX_NOTION_BLOCK_TEXT_CHARS,
            "Notion block text",
        )
        if type(self.has_children) is not bool:
            raise TypeError("Notion child-block evidence is invalid")
        if self.checked is not None and type(self.checked) is not bool:
            raise TypeError("Notion to-do state is invalid")
        if self.checked is not None and self.block_type != "to_do":
            raise ValueError("Notion checked state belongs only to a to-do")
        if self.language is not None:
            _bounded_text(
                self.language,
                128,
                "Notion code language",
                allow_empty=False,
            )
            if self.block_type != "code":
                raise ValueError(
                    "Notion code language belongs only to a code block"
                )

    def json_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "block_id": self.block_id,
            "depth": self.depth,
            "has_children": self.has_children,
            "parent_block_id": self.parent_block_id,
            "text": self.text,
            "type": self.block_type,
        }
        if self.checked is not None:
            value["checked"] = self.checked
        if self.language is not None:
            value["language"] = self.language
        return value


@dataclass(frozen=True, slots=True)
class NotionSelectedPageResult:
    page_id: str
    title: str = field(repr=False)
    blocks: tuple[NotionPageBlock, ...] = field(repr=False)
    content_truncated: bool
    provider_requests: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "page_id",
            _notion_id(self.page_id, "Notion page ID"),
        )
        _bounded_text(self.title, MAX_NOTION_TITLE_CHARS, "Notion page title")
        if (
            not isinstance(self.blocks, tuple)
            or len(self.blocks) > MAX_NOTION_BLOCKS
            or any(not isinstance(item, NotionPageBlock) for item in self.blocks)
        ):
            raise TypeError("Notion page blocks are invalid")
        if len({item.block_id for item in self.blocks}) != len(self.blocks):
            raise ValueError("Notion page block identities must be unique")
        if sum(len(item.text) for item in self.blocks) > (
            MAX_NOTION_PAGE_TEXT_CHARS
        ):
            raise ValueError("Notion page text exceeds its limit")
        if type(self.content_truncated) is not bool:
            raise TypeError("Notion truncation evidence is invalid")
        if (
            type(self.provider_requests) is not int
            or not 1
            <= self.provider_requests
            <= MAX_NOTION_PROVIDER_REQUESTS
        ):
            raise ValueError("Notion provider-request evidence is invalid")

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "blocks": [item.json_value() for item in self.blocks],
                "content_truncated": self.content_truncated,
                "page_id": self.page_id,
                "provider_requests": self.provider_requests,
                "title": self.title,
            }
        )


@dataclass(frozen=True, slots=True)
class NotionHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Notion HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Notion content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_NOTION_RESPONSE_BYTES
        ):
            raise ValueError("Notion response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Notion retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("Notion provider request ID is invalid")


class NotionHttpTransport(Protocol):
    def get_json(
        self,
        *,
        endpoint: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> NotionHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedNotionHttpsTransport:
    """Fixed-host/version bounded HTTPS transport without proxies/redirects."""

    def __init__(self, *, timeout_seconds: float = 15.0, _opener=None) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0.01 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("Notion request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get_json(
        self,
        *,
        endpoint: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> NotionHttpResponse:
        _validate_endpoint(endpoint)
        if not isinstance(access_token, SecretValue):
            raise TypeError("Notion access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_NOTION_RESPONSE_BYTES
        ):
            raise ValueError("Notion response limit is invalid")
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Notion access token encoding is invalid"
                ) from exc
            request = urllib.request.Request(
                endpoint,
                method="GET",
                headers={
                    "Accept": "application/json",
                    "Authorization": authorization,
                    "Cache-Control": "no-store",
                    "Notion-Version": NOTION_API_VERSION,
                    "User-Agent": "Clicky-Windows-Notion/1",
                },
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
                raise ConnectorRequestError(
                    "Notion provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class NotionSelectedPageAdapter:
    """Notion adapter sealed to one selected page and bounded child reads."""

    provider = ConnectorProviderId.NOTION
    connector = ConnectorId.NOTION

    def __init__(
        self,
        account: ConnectedAccount,
        transport: NotionHttpTransport | None = None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Notion adapter requires a connected account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Notion adapter account is invalid")
        candidate = transport or FixedNotionHttpsTransport()
        if not callable(getattr(candidate, "get_json", None)):
            raise TypeError("Notion adapter transport is invalid")
        self._account = account
        self._transport = candidate

    async def execute(
        self,
        call: ConnectorCall,
        request: NotionSelectedPageRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[NotionSelectedPageResult]:
        if not isinstance(request, NotionSelectedPageRequest):
            raise TypeError("Notion adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Notion adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(call.maximum_response_bytes, MAX_NOTION_RESPONSE_BYTES)
        responses: list[NotionHttpResponse] = []

        page_response = self._transport.get_json(
            endpoint=request.page_endpoint,
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        _raise_for_status(page_response)
        responses.append(page_response)
        title, truncated = _parse_page(
            page_response,
            request.selected_page_id,
        )

        queue: deque[tuple[str, int, str | None]] = deque(
            [(request.selected_page_id, 0, None)]
        )
        blocks: list[NotionPageBlock] = []
        seen: set[str] = set()
        total_text = 0

        while queue and len(responses) < MAX_NOTION_PROVIDER_REQUESTS:
            parent_id, depth, start_cursor = queue.popleft()
            remaining = maximum - sum(len(item.body) for item in responses)
            if remaining <= 0:
                raise ConnectorResponseError(
                    "Notion provider responses exceed the declared limit"
                )
            response = self._transport.get_json(
                endpoint=request.children_endpoint(
                    parent_id,
                    start_cursor=start_cursor,
                ),
                access_token=access_token,
                maximum_response_bytes=remaining,
            )
            _raise_for_status(response)
            responses.append(response)
            raw_blocks, next_cursor = _parse_children_page(response)
            capacity_exhausted = False
            for raw_block in raw_blocks:
                block, block_truncated = _parse_block(
                    raw_block,
                    parent_id=parent_id,
                    depth=depth,
                )
                truncated = truncated or block_truncated
                if block.block_id in seen:
                    raise ConnectorResponseError(
                        "Notion returned a duplicate block identity"
                    )
                seen.add(block.block_id)
                if (
                    len(blocks) >= MAX_NOTION_BLOCKS
                    or total_text + len(block.text)
                    > MAX_NOTION_PAGE_TEXT_CHARS
                ):
                    truncated = True
                    capacity_exhausted = True
                    queue.clear()
                    break
                blocks.append(block)
                total_text += len(block.text)
                if block.has_children:
                    if depth + 1 >= MAX_NOTION_BLOCK_DEPTH:
                        truncated = True
                    else:
                        queue.append((block.block_id, depth + 1, None))
            if capacity_exhausted:
                break
            if next_cursor is not None:
                queue.append((parent_id, depth, next_cursor))
        if queue:
            truncated = True

        evidence = b"\x00".join(item.body for item in responses)
        if len(evidence) > maximum:
            raise ConnectorResponseError(
                "Notion provider responses exceed the declared limit"
            )
        output = NotionSelectedPageResult(
            page_id=request.selected_page_id,
            title=title,
            blocks=tuple(blocks),
            content_truncated=truncated,
            provider_requests=len(responses),
        )
        if len(output.to_json_bytes()) > call.maximum_response_bytes:
            raise ConnectorResponseError(
                "Notion selected-page output exceeds the declared limit"
            )
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=call.operation_id,
                http_status=page_response.status,
                response_digest=hashlib.sha256(evidence).hexdigest(),
                response_bytes=len(evidence),
                provider_request_id=next(
                    (
                        item.provider_request_id
                        for item in responses
                        if item.provider_request_id is not None
                    ),
                    None,
                ),
            ),
            output=output,
        )

    async def revoke(
        self,
        _request: ConnectorRevocationRequest,
        _refresh_token: SecretValue,
    ) -> ConnectorRevocationResult:
        raise ConnectorRevocationError(
            "Notion revocation requires the confidential OAuth broker"
        )


def _validate_endpoint(endpoint: str) -> None:
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "api.notion.com"
        or parsed.fragment
    ):
        raise ConnectorRequestError(
            "Notion request endpoint is not fixed by policy"
        )
    page_prefix = "/v1/pages/"
    children_prefix = "/v1/blocks/"
    if parsed.path.startswith(page_prefix):
        if parsed.query:
            raise ConnectorRequestError(
                "Notion page endpoint is not fixed by policy"
            )
        candidate = parsed.path[len(page_prefix) :]
    elif (
        parsed.path.startswith(children_prefix)
        and parsed.path.endswith("/children")
    ):
        candidate = parsed.path[
            len(children_prefix) : -len("/children")
        ]
        pairs = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
        if (
            not 1 <= len(pairs) <= 2
            or pairs[0] != ("page_size", str(_PAGE_SIZE))
            or (
                len(pairs) == 2
                and (
                    pairs[1][0] != "start_cursor"
                    or pairs[1][1] != _cursor(pairs[1][1])
                )
            )
        ):
            raise ConnectorRequestError(
                "Notion children endpoint is not fixed by policy"
            )
    else:
        raise ConnectorRequestError(
            "Notion request endpoint is not fixed by policy"
        )
    try:
        canonical = _notion_id(candidate, "Notion endpoint resource ID")
    except ValueError as exc:
        raise ConnectorRequestError(
            "Notion request endpoint is not fixed by policy"
        ) from exc
    if candidate != canonical:
        raise ConnectorRequestError(
            "Notion request endpoint is not canonical"
        )


def _bounded_http_response(response, maximum: int) -> NotionHttpResponse:
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ConnectorResponseError(
            "Notion provider response exceeds its limit"
        )
    headers = response.headers
    retry_seconds = None
    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            candidate = int(retry_after, 10)
        except ValueError:
            candidate = -1
        if 0 <= candidate <= 24 * 60 * 60:
            retry_seconds = candidate
    return NotionHttpResponse(
        status=response.status,
        content_type=headers.get("Content-Type", ""),
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=(
            headers.get("X-Request-Id") or headers.get("Request-Id")
        ),
    )


def _raise_for_status(response: NotionHttpResponse) -> None:
    if 200 <= response.status <= 299:
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Notion access token expired or is invalid"
        )
    if response.status in {429, 503}:
        raise ConnectorRateLimitError(response.retry_after_seconds or 0)
    if response.status == 403:
        raise ConnectorAuthorizationError(
            "Notion denied access to the selected page"
        )
    if response.status in {400, 409}:
        raise ConnectorRequestError("Notion rejected the selected-page request")
    if response.status == 404:
        raise ConnectorResponseError(
            "Selected Notion page or block is unavailable"
        )
    raise ConnectorResponseError("Notion provider returned an error")


def _json_payload(response: NotionHttpResponse) -> dict[str, object]:
    media_type = response.content_type.partition(";")[0].strip().casefold()
    if media_type != "application/json":
        raise ConnectorResponseError("Notion provider response is not JSON")
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorResponseError(
            "Notion provider response is invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ConnectorResponseError(
            "Notion provider response shape is invalid"
        )
    return payload


def _parse_page(
    response: NotionHttpResponse,
    selected_page_id: str,
) -> tuple[str, bool]:
    payload = _json_payload(response)
    if (
        not set(payload).issubset(_PAGE_KEYS)
        or payload.get("object") != "page"
        or _provider_id(payload.get("id"), "Notion page ID")
        != selected_page_id
        or not isinstance(payload.get("properties"), dict)
        or len(payload["properties"]) > 200
    ):
        raise ConnectorResponseError("Notion page response shape is invalid")
    titles: list[tuple[str, bool]] = []
    for value in payload["properties"].values():
        if not isinstance(value, dict):
            raise ConnectorResponseError("Notion page property is invalid")
        if value.get("type") == "title":
            titles.append(
                _rich_text_plain(
                    value.get("title"),
                    maximum=MAX_NOTION_TITLE_CHARS,
                )
            )
    if len(titles) > 1:
        raise ConnectorResponseError("Notion page has ambiguous title fields")
    return titles[0] if titles else ("", False)


def _parse_children_page(
    response: NotionHttpResponse,
) -> tuple[list[object], str | None]:
    payload = _json_payload(response)
    if (
        not set(payload).issubset(
            {"block", "has_more", "next_cursor", "object", "results", "type"}
        )
        or payload.get("object") != "list"
        or not isinstance(payload.get("has_more"), bool)
        or not isinstance(payload.get("results"), list)
        or len(payload["results"]) > _PAGE_SIZE
    ):
        raise ConnectorResponseError(
            "Notion block-children response shape is invalid"
        )
    has_more = payload["has_more"]
    next_cursor = payload.get("next_cursor")
    if has_more:
        next_cursor = _cursor(next_cursor)
    elif next_cursor is not None:
        raise ConnectorResponseError(
            "Notion pagination completion is inconsistent"
        )
    return payload["results"], next_cursor


def _parse_block(
    raw: object,
    *,
    parent_id: str,
    depth: int,
) -> tuple[NotionPageBlock, bool]:
    if (
        not isinstance(raw, dict)
        or raw.get("object") != "block"
        or not isinstance(raw.get("type"), str)
        or not isinstance(raw.get("has_children"), bool)
    ):
        raise ConnectorResponseError("Notion block shape is invalid")
    block_type = raw["type"]
    allowed_keys = _BLOCK_KEYS | {block_type}
    if not set(raw).issubset(allowed_keys):
        raise ConnectorResponseError("Notion block fields are invalid")
    safe_type = block_type if block_type in _SAFE_BLOCK_TYPES else "unsupported"
    payload = raw.get(block_type)
    text = ""
    text_truncated = False
    checked = None
    language = None
    if safe_type in _TEXT_BLOCK_TYPES:
        if not isinstance(payload, dict):
            raise ConnectorResponseError("Notion text block is invalid")
        if safe_type in {"child_page", "child_database"}:
            text, text_truncated = _provider_text(
                payload.get("title", ""),
                MAX_NOTION_BLOCK_TEXT_CHARS,
                "Notion child title",
            )
        elif safe_type == "equation":
            text, text_truncated = _provider_text(
                payload.get("expression", ""),
                MAX_NOTION_BLOCK_TEXT_CHARS,
                "Notion equation",
            )
        elif safe_type == "table_row":
            cells = payload.get("cells")
            if not isinstance(cells, list) or len(cells) > 100:
                raise ConnectorResponseError("Notion table row is invalid")
            cell_values = [
                _rich_text_plain(
                    cell,
                    maximum=MAX_NOTION_BLOCK_TEXT_CHARS,
                )
                for cell in cells
            ]
            combined = "\t".join(item[0] for item in cell_values)
            text = combined[:MAX_NOTION_BLOCK_TEXT_CHARS]
            text_truncated = (
                any(item[1] for item in cell_values)
                or len(combined) > MAX_NOTION_BLOCK_TEXT_CHARS
            )
        elif safe_type == "bookmark":
            caption = payload.get("caption", [])
            text, text_truncated = _rich_text_plain(
                caption,
                maximum=MAX_NOTION_BLOCK_TEXT_CHARS,
            )
        else:
            text, text_truncated = _rich_text_plain(
                payload.get("rich_text", []),
                maximum=MAX_NOTION_BLOCK_TEXT_CHARS,
            )
        if safe_type == "to_do":
            candidate = payload.get("checked")
            if type(candidate) is not bool:
                raise ConnectorResponseError(
                    "Notion to-do state is invalid"
                )
            checked = candidate
        if safe_type == "code":
            language = _bounded_text(
                payload.get("language", "plain text"),
                128,
                "Notion code language",
                allow_empty=False,
            )
    return (
        NotionPageBlock(
            block_id=_provider_id(raw.get("id"), "Notion block ID"),
            parent_block_id=parent_id,
            depth=depth,
            block_type=safe_type,
            text=text,
            has_children=raw["has_children"],
            checked=checked,
            language=language,
        ),
        text_truncated,
    )


def _rich_text_plain(
    raw: object,
    *,
    maximum: int,
) -> tuple[str, bool]:
    if not isinstance(raw, list) or len(raw) > 100:
        raise ConnectorResponseError("Notion rich text is invalid")
    parts: list[str] = []
    total = 0
    truncated = False
    for item in raw:
        if not isinstance(item, dict):
            raise ConnectorResponseError("Notion rich-text item is invalid")
        value = item.get("plain_text")
        if not isinstance(value, str) or "\x00" in value:
            raise ConnectorResponseError(
                "Notion rich-text plain text is invalid"
            )
        remaining = maximum - total
        if remaining > 0:
            parts.append(value[:remaining])
        if len(value) > remaining:
            truncated = True
        total += min(len(value), max(remaining, 0))
    return "".join(parts), truncated


def _provider_text(
    value: object,
    maximum: int,
    label: str,
) -> tuple[str, bool]:
    if not isinstance(value, str) or "\x00" in value:
        raise ConnectorResponseError(f"{label} is invalid")
    return value[:maximum], len(value) > maximum


def _provider_id(value: object, label: str) -> str:
    try:
        return _notion_id(value, label)
    except ValueError as exc:
        raise ConnectorResponseError(f"{label} is invalid") from exc


__all__ = [
    "MAX_NOTION_PROVIDER_REQUESTS",
    "NOTION_API_ROOT",
    "NOTION_API_VERSION",
    "NOTION_SELECTED_PAGE_OPERATION_ID",
    "FixedNotionHttpsTransport",
    "NotionDraftBlock",
    "NotionHttpResponse",
    "NotionLocalDraft",
    "NotionPageBlock",
    "NotionSelectedPageAdapter",
    "NotionSelectedPageRequest",
    "NotionSelectedPageResult",
    "render_notion_local_draft",
]
