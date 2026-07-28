"""Least-privilege Gmail selected-thread and draft adapters.

The read operation accepts one exact thread ID and returns bounded message
headers plus text bodies, never mailbox search results or attachments.  The
write operation creates an unsent plain-text draft and immediately reads it
back in raw form to verify the exact recipients, subject, and body.  There is
intentionally no send operation in this module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email import policy
from email.headerregistry import Address
from email.message import EmailMessage, Message
from email.parser import BytesParser
from html.parser import HTMLParser
from types import MappingProxyType
from typing import Mapping, Protocol

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
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenExpiredError,
    SecretValue,
    validate_connector_authority,
)


GMAIL_API_ROOT = "https://gmail.googleapis.com/gmail/v1/users/me"
GMAIL_SELECTED_THREAD_OPERATION_ID = "gmail.read_selected_thread"
GMAIL_CREATE_DRAFT_OPERATION_ID = "gmail.create_draft"
MAX_GMAIL_RESPONSE_BYTES = 1024 * 1024
MAX_GMAIL_REQUEST_BYTES = 64 * 1024
MAX_GMAIL_MESSAGES = 100
MAX_GMAIL_MIME_PARTS = 256
MAX_GMAIL_MIME_DEPTH = 12
MAX_GMAIL_BODY_CHARS = 64 * 1024
MAX_GMAIL_THREAD_OUTPUT_BYTES = 768 * 1024
MAX_GMAIL_DRAFT_BODY_CHARS = 16 * 1024
MAX_GMAIL_RECIPIENTS = 50
MAX_GMAIL_SUBJECT_CHARS = 500
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_ALLOWED_MESSAGE_KEYS = frozenset(
    {
        "historyId",
        "id",
        "internalDate",
        "labelIds",
        "payload",
        "sizeEstimate",
        "snippet",
        "threadId",
    }
)
_ALLOWED_PAYLOAD_KEYS = frozenset(
    {"body", "filename", "headers", "mimeType", "partId", "parts"}
)
_ALLOWED_BODY_KEYS = frozenset({"attachmentId", "data", "size"})
_ALLOWED_HEADER_KEYS = frozenset({"name", "value"})
_EXPORTED_HEADERS = frozenset(
    {"from", "to", "cc", "bcc", "subject", "date", "message-id"}
)


class GmailDraftOutcomeUnknownError(ConnectorRequestError):
    """The create request may have reached Gmail; automatic retry is unsafe."""


class GmailDraftVerificationError(ConnectorResponseError):
    """Gmail created a draft, but the exact read-back could not be verified."""


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
        raise ValueError("Gmail value is not canonical JSON") from exc


def _opaque_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or value.strip() != value
        or _OPAQUE_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _address(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 320
        or value.strip() != value
        or "\r" in value
        or "\n" in value
        or "\x00" in value
    ):
        raise ValueError("Gmail recipient address is invalid")
    try:
        parsed = Address(addr_spec=value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Gmail recipient address is invalid") from exc
    if parsed.addr_spec.casefold() != value.casefold():
        raise ValueError("Gmail recipient must be one exact email address")
    return value


def _recipients(value: object, label: str, *, required: bool) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise TypeError(f"{label} recipients must be a tuple")
    if (required and not value) or len(value) > MAX_GMAIL_RECIPIENTS:
        raise ValueError(f"{label} recipient count is invalid")
    normalized = tuple(_address(item) for item in value)
    if len({item.casefold() for item in normalized}) != len(normalized):
        raise ValueError(f"{label} recipients must be unique")
    return normalized


def _base64url_decode(value: object, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) > (MAX_GMAIL_RESPONSE_BYTES * 2)
        or re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", value) is None
    ):
        raise ConnectorResponseError(f"{label} is invalid")
    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ConnectorResponseError(f"{label} is invalid") from exc
    if len(decoded) > MAX_GMAIL_RESPONSE_BYTES:
        raise ConnectorResponseError(f"{label} exceeds its limit")
    return decoded


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class GmailSelectedThreadRequest:
    """One explicitly selected Gmail thread; no query or mailbox search."""

    selected_thread_id: str = field(repr=False)
    connector: ConnectorId = field(default=ConnectorId.GMAIL, init=False)
    capability: CapabilityId = field(
        default=CapabilityId.GMAIL_MESSAGE_READ,
        init=False,
    )
    operation_id: str = field(
        default=GMAIL_SELECTED_THREAD_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _opaque_id(self.selected_thread_id, "Selected Gmail thread ID")
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "format": "full",
                        "selected_thread_id": self.selected_thread_id,
                    }
                )
            ).hexdigest(),
        )

    @property
    def endpoint(self) -> str:
        quoted = urllib.parse.quote(self.selected_thread_id, safe="")
        return f"{GMAIL_API_ROOT}/threads/{quoted}?format=full"


@dataclass(frozen=True, slots=True)
class GmailMessageResult:
    message_id: str
    thread_id: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body_text: str = field(repr=False)
    body_truncated: bool
    internal_date_ms: str | None = None

    def __post_init__(self) -> None:
        _opaque_id(self.message_id, "Gmail message ID")
        _opaque_id(self.thread_id, "Gmail thread ID")
        if (
            not isinstance(self.headers, tuple)
            or len(self.headers) > 64
            or any(
                not isinstance(item, tuple)
                or len(item) != 2
                or item[0].casefold() not in _EXPORTED_HEADERS
                or not isinstance(item[1], str)
                or len(item[1]) > 8_192
                or "\x00" in item[1]
                for item in self.headers
            )
        ):
            raise ValueError("Gmail message headers are invalid")
        if (
            not isinstance(self.body_text, str)
            or len(self.body_text) > MAX_GMAIL_BODY_CHARS
            or "\x00" in self.body_text
        ):
            raise ValueError("Gmail message body is invalid")
        if type(self.body_truncated) is not bool:
            raise TypeError("Gmail body truncation evidence is invalid")
        if self.internal_date_ms is not None and (
            not isinstance(self.internal_date_ms, str)
            or not self.internal_date_ms.isdecimal()
            or len(self.internal_date_ms) > 20
        ):
            raise ValueError("Gmail internal date is invalid")


@dataclass(frozen=True, slots=True)
class GmailSelectedThreadResult:
    thread_id: str
    messages: tuple[GmailMessageResult, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _opaque_id(self.thread_id, "Gmail thread ID")
        if (
            not isinstance(self.messages, tuple)
            or not self.messages
            or len(self.messages) > MAX_GMAIL_MESSAGES
            or any(
                not isinstance(message, GmailMessageResult)
                or message.thread_id != self.thread_id
                for message in self.messages
            )
        ):
            raise ValueError("Gmail selected-thread result is invalid")
        if len({message.message_id for message in self.messages}) != len(
            self.messages
        ):
            raise ValueError("Gmail selected-thread messages are duplicated")

    def to_json_bytes(self) -> bytes:
        output = _canonical_json(
            {
                "messages": [
                    {
                        "body_text": message.body_text,
                        "body_truncated": message.body_truncated,
                        "headers": [
                            {"name": name, "value": value}
                            for name, value in message.headers
                        ],
                        "internal_date_ms": message.internal_date_ms,
                        "message_id": message.message_id,
                        "thread_id": message.thread_id,
                    }
                    for message in self.messages
                ],
                "thread_id": self.thread_id,
            }
        )
        if len(output) > MAX_GMAIL_THREAD_OUTPUT_BYTES:
            raise ConnectorResponseError(
                "Selected Gmail thread output exceeds its limit"
            )
        return output


@dataclass(frozen=True, slots=True)
class GmailDraftRequest:
    """Exact, plain-text unsent draft bound to an action approval."""

    to: tuple[str, ...] = field(repr=False)
    cc: tuple[str, ...] = field(default=(), repr=False)
    bcc: tuple[str, ...] = field(default=(), repr=False)
    subject: str = field(default="", repr=False)
    body_text: str = field(default="", repr=False)
    connector: ConnectorId = field(default=ConnectorId.GMAIL, init=False)
    capability: CapabilityId = field(
        default=CapabilityId.GMAIL_DRAFT_WRITE,
        init=False,
    )
    operation_id: str = field(
        default=GMAIL_CREATE_DRAFT_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _recipients(self.to, "To", required=True)
        _recipients(self.cc, "Cc", required=False)
        _recipients(self.bcc, "Bcc", required=False)
        all_addresses = self.to + self.cc + self.bcc
        if len({item.casefold() for item in all_addresses}) != len(
            all_addresses
        ):
            raise ValueError("Gmail recipients must be unique across headers")
        if (
            not isinstance(self.subject, str)
            or not self.subject
            or len(self.subject) > MAX_GMAIL_SUBJECT_CHARS
            or "\r" in self.subject
            or "\n" in self.subject
            or "\x00" in self.subject
        ):
            raise ValueError("Gmail draft subject is invalid")
        if (
            not isinstance(self.body_text, str)
            or not self.body_text
            or len(self.body_text) > MAX_GMAIL_DRAFT_BODY_CHARS
            or "\x00" in self.body_text
        ):
            raise ValueError("Gmail draft body is invalid")
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(self.preview_bytes()).hexdigest(),
        )

    def preview_bytes(self) -> bytes:
        return _canonical_json(
            {
                "bcc": list(self.bcc),
                "body_text": self.body_text,
                "cc": list(self.cc),
                "subject": self.subject,
                "to": list(self.to),
            }
        )

    def raw_message(self) -> bytes:
        message = EmailMessage(policy=policy.SMTP)
        message["To"] = ", ".join(self.to)
        if self.cc:
            message["Cc"] = ", ".join(self.cc)
        if self.bcc:
            message["Bcc"] = ", ".join(self.bcc)
        message["Subject"] = self.subject
        message.set_content(self.body_text, subtype="plain", charset="utf-8")
        raw = message.as_bytes(policy=policy.SMTP)
        if len(raw) > MAX_GMAIL_REQUEST_BYTES:
            raise ValueError("Gmail draft MIME message exceeds its limit")
        return raw

    def provider_payload(self) -> dict[str, object]:
        return {"message": {"raw": _base64url_encode(self.raw_message())}}


@dataclass(frozen=True, slots=True)
class GmailDraftResult:
    draft_id: str
    message_id: str
    thread_id: str
    verified: bool = True

    def __post_init__(self) -> None:
        _opaque_id(self.draft_id, "Gmail draft ID")
        _opaque_id(self.message_id, "Gmail draft message ID")
        _opaque_id(self.thread_id, "Gmail draft thread ID")
        if self.verified is not True:
            raise ValueError("Gmail draft must have read-back verification")

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "draft_id": self.draft_id,
                "message_id": self.message_id,
                "thread_id": self.thread_id,
                "verified": True,
            }
        )


@dataclass(frozen=True, slots=True)
class GmailHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Gmail HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Gmail response content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_GMAIL_RESPONSE_BYTES
        ):
            raise ValueError("Gmail response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Gmail retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("Gmail provider request ID is invalid")


class GmailHttpTransport(Protocol):
    def get_json(
        self,
        *,
        endpoint: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> GmailHttpResponse: ...

    def post_json(
        self,
        *,
        endpoint: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> GmailHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGmailHttpsTransport:
    """Fixed-host bounded HTTPS transport with no proxies or redirects."""

    def __init__(self, *, timeout_seconds: float = 15.0, _opener=None) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not math.isfinite(float(timeout_seconds))
            or not 0.01 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("Gmail request timeout is invalid")
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
    ) -> GmailHttpResponse:
        self._validate_endpoint(endpoint, method="GET")
        return self._request(
            endpoint=endpoint,
            method="GET",
            body=None,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            write_outcome_unknown=False,
        )

    def post_json(
        self,
        *,
        endpoint: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> GmailHttpResponse:
        self._validate_endpoint(endpoint, method="POST")
        if not isinstance(payload, Mapping) or not payload:
            raise ConnectorRequestError("Gmail request payload is invalid")
        encoded = _canonical_json(dict(payload))
        if len(encoded) > MAX_GMAIL_REQUEST_BYTES * 2:
            raise ConnectorRequestError("Gmail request exceeds its limit")
        return self._request(
            endpoint=endpoint,
            method="POST",
            body=encoded,
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            write_outcome_unknown=True,
        )

    @staticmethod
    def _validate_endpoint(endpoint: str, *, method: str) -> None:
        parsed = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.netloc != "gmail.googleapis.com"
            or parsed.fragment
            or not parsed.path.startswith("/gmail/v1/users/me/")
        ):
            raise ConnectorRequestError(
                "Gmail request endpoint is not fixed by policy"
            )
        if method == "POST":
            if endpoint != f"{GMAIL_API_ROOT}/drafts":
                raise ConnectorRequestError(
                    "Gmail write endpoint is not fixed by policy"
                )
        else:
            expected_query = None
            prefix = None
            if parsed.path.startswith("/gmail/v1/users/me/threads/"):
                prefix = "/gmail/v1/users/me/threads/"
                expected_query = "format=full"
            elif parsed.path.startswith("/gmail/v1/users/me/drafts/"):
                prefix = "/gmail/v1/users/me/drafts/"
                expected_query = "format=raw"
            encoded_id = parsed.path[len(prefix) :] if prefix else ""
            decoded_id = urllib.parse.unquote(encoded_id)
            if (
                prefix is None
                or parsed.query != expected_query
                or _OPAQUE_ID.fullmatch(decoded_id) is None
                or urllib.parse.quote(decoded_id, safe="") != encoded_id
            ):
                raise ConnectorRequestError(
                    "Gmail read endpoint is not fixed by policy"
                )

    def _request(
        self,
        *,
        endpoint: str,
        method: str,
        body: bytes | None,
        access_token: SecretValue,
        maximum_response_bytes: int,
        write_outcome_unknown: bool,
    ) -> GmailHttpResponse:
        if not isinstance(access_token, SecretValue):
            raise TypeError("Gmail access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_GMAIL_RESPONSE_BYTES
        ):
            raise ValueError("Gmail response limit is invalid")
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Gmail access token encoding is invalid"
                ) from exc
            headers = {
                "Accept": "application/json",
                "Authorization": authorization,
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Gmail/1",
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
                    GmailDraftOutcomeUnknownError
                    if write_outcome_unknown
                    else ConnectorRequestError
                )
                raise error_type("Gmail provider request failed") from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleGmailAdapter:
    """Google adapter sealed to selected-thread read and unsent draft create."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GMAIL

    def __init__(
        self,
        account: ConnectedAccount,
        transport: GmailHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Gmail adapter requires a connected account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Gmail adapter account is invalid")
        candidate = transport or FixedGmailHttpsTransport()
        if not (
            callable(getattr(candidate, "get_json", None))
            and callable(getattr(candidate, "post_json", None))
        ):
            raise TypeError("Gmail adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Gmail revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: GmailSelectedThreadRequest | GmailDraftRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[GmailSelectedThreadResult | GmailDraftResult]:
        if not isinstance(
            request,
            (GmailSelectedThreadRequest, GmailDraftRequest),
        ):
            raise TypeError("Gmail adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Gmail adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(call.maximum_response_bytes, MAX_GMAIL_RESPONSE_BYTES)
        if isinstance(request, GmailSelectedThreadRequest):
            response = self._transport.get_json(
                endpoint=request.endpoint,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            _raise_for_status(response, write=False)
            output = _parse_selected_thread(response, request)
            evidence_body = response.body
            status = response.status
            request_id = response.provider_request_id
        else:
            create_response = self._transport.post_json(
                endpoint=f"{GMAIL_API_ROOT}/drafts",
                payload=MappingProxyType(request.provider_payload()),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            _raise_for_status(create_response, write=True)
            draft_id, message_id, thread_id = _parse_created_draft(
                create_response
            )
            verify_response = self._transport.get_json(
                endpoint=(
                    f"{GMAIL_API_ROOT}/drafts/"
                    f"{urllib.parse.quote(draft_id, safe='')}?format=raw"
                ),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            try:
                _raise_for_status(verify_response, write=False)
                _verify_created_draft(
                    verify_response,
                    request,
                    draft_id=draft_id,
                    message_id=message_id,
                    thread_id=thread_id,
                )
            except Exception as exc:
                if isinstance(exc, GmailDraftVerificationError):
                    raise
                raise GmailDraftVerificationError(
                    "Gmail draft read-back verification failed"
                ) from exc
            output = GmailDraftResult(
                draft_id=draft_id,
                message_id=message_id,
                thread_id=thread_id,
            )
            evidence_body = (
                create_response.body + b"\x00" + verify_response.body
            )
            status = create_response.status
            request_id = create_response.provider_request_id
        if len(evidence_body) > (MAX_GMAIL_RESPONSE_BYTES * 2 + 1):
            raise ConnectorResponseError(
                "Gmail provider evidence exceeds its limit"
            )
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=call.operation_id,
                http_status=status,
                response_digest=hashlib.sha256(evidence_body).hexdigest(),
                response_bytes=len(evidence_body),
                provider_request_id=request_id,
            ),
            output=output,
        )

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
            raise TypeError("Gmail revocation evidence is invalid")
        return result


def _bounded_http_response(response, maximum: int) -> GmailHttpResponse:
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ConnectorResponseError("Gmail provider response exceeds its limit")
    headers = response.headers
    request_id = next(
        (
            value
            for name in (
                "X-Request-Id",
                "X-Goog-Request-Id",
                "X-GUploader-UploadID",
            )
            for value in (headers.get(name),)
            if value
        ),
        None,
    )
    retry_seconds = None
    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            candidate = int(retry_after, 10)
        except ValueError:
            candidate = -1
        if 0 <= candidate <= 24 * 60 * 60:
            retry_seconds = candidate
    return GmailHttpResponse(
        status=response.status,
        content_type=headers.get("Content-Type", ""),
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


def _raise_for_status(response: GmailHttpResponse, *, write: bool) -> None:
    if 200 <= response.status <= 299:
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Gmail access token expired or is invalid"
        )
    if response.status in {429, 503}:
        raise ConnectorRateLimitError(response.retry_after_seconds or 0)
    if response.status == 403:
        reasons = _provider_error_reasons(response.body)
        if reasons.intersection(
            {
                "dailyLimitExceeded",
                "quotaExceeded",
                "rateLimitExceeded",
                "userRateLimitExceeded",
            }
        ):
            raise ConnectorRateLimitError(response.retry_after_seconds or 0)
        raise ConnectorAuthorizationError(
            "Gmail provider denied the requested scope"
        )
    if response.status == 400:
        raise ConnectorRequestError("Gmail provider rejected the request")
    if response.status == 404:
        if write:
            raise GmailDraftVerificationError(
                "Created Gmail draft could not be verified"
            )
        raise ConnectorResponseError("Selected Gmail resource is unavailable")
    raise ConnectorResponseError("Gmail provider returned an error")


def _provider_error_reasons(body: bytes) -> frozenset[str]:
    if not body or len(body) > MAX_GMAIL_RESPONSE_BYTES:
        return frozenset()
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return frozenset()
    if not isinstance(payload, dict) or set(payload) != {"error"}:
        return frozenset()
    error = payload["error"]
    if not isinstance(error, dict):
        return frozenset()
    errors = error.get("errors", [])
    if not isinstance(errors, list) or len(errors) > 32:
        return frozenset()
    return frozenset(
        item["reason"]
        for item in errors
        if isinstance(item, dict)
        and isinstance(item.get("reason"), str)
        and 0 < len(item["reason"]) <= 128
        and item["reason"].isprintable()
    )


def _json_payload(response: GmailHttpResponse) -> dict[str, object]:
    media_type = response.content_type.partition(";")[0].strip().casefold()
    if media_type != "application/json":
        raise ConnectorResponseError("Gmail provider response is not JSON")
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorResponseError(
            "Gmail provider response is invalid"
        ) from exc
    if not isinstance(payload, dict):
        raise ConnectorResponseError(
            "Gmail provider response shape is invalid"
        )
    return payload


def _parse_selected_thread(
    response: GmailHttpResponse,
    request: GmailSelectedThreadRequest,
) -> GmailSelectedThreadResult:
    payload = _json_payload(response)
    if (
        not set(payload).issubset({"historyId", "id", "messages", "snippet"})
        or payload.get("id") != request.selected_thread_id
        or not isinstance(payload.get("messages"), list)
        or not 1 <= len(payload["messages"]) <= MAX_GMAIL_MESSAGES
    ):
        raise ConnectorResponseError(
            "Gmail selected-thread response shape is invalid"
        )
    messages = tuple(
        _parse_message(item, request.selected_thread_id)
        for item in payload["messages"]
    )
    return GmailSelectedThreadResult(
        thread_id=request.selected_thread_id,
        messages=messages,
    )


def _parse_message(raw: object, selected_thread_id: str) -> GmailMessageResult:
    if (
        not isinstance(raw, dict)
        or not set(raw).issubset(_ALLOWED_MESSAGE_KEYS)
        or raw.get("threadId") != selected_thread_id
    ):
        raise ConnectorResponseError("Gmail message shape is invalid")
    try:
        message_id = _opaque_id(raw["id"], "Gmail message ID")
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectorResponseError("Gmail message identity is invalid") from exc
    payload = raw.get("payload")
    if not isinstance(payload, dict):
        raise ConnectorResponseError("Gmail message payload is missing")
    headers = _parse_headers(payload.get("headers"))
    plain_parts: list[str] = []
    html_parts: list[str] = []
    state = {"parts": 0, "truncated": False}
    _collect_mime_text(
        payload,
        depth=0,
        state=state,
        plain=plain_parts,
        html=html_parts,
    )
    body = "\n".join(plain_parts)
    if not body and html_parts:
        body = "\n".join(_html_to_text(item) for item in html_parts)
    if len(body) > MAX_GMAIL_BODY_CHARS:
        body = body[:MAX_GMAIL_BODY_CHARS]
        state["truncated"] = True
    return GmailMessageResult(
        message_id=message_id,
        thread_id=selected_thread_id,
        headers=headers,
        body_text=body,
        body_truncated=bool(state["truncated"]),
        internal_date_ms=raw.get("internalDate"),
    )


def _parse_headers(raw: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(raw, list) or len(raw) > 256:
        raise ConnectorResponseError("Gmail message headers are invalid")
    output: list[tuple[str, str]] = []
    for item in raw:
        if (
            not isinstance(item, dict)
            or set(item) != _ALLOWED_HEADER_KEYS
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("value"), str)
        ):
            raise ConnectorResponseError("Gmail message header shape is invalid")
        name = item["name"].casefold()
        value = item["value"]
        if name in _EXPORTED_HEADERS:
            if len(value) > 8_192 or "\x00" in value:
                raise ConnectorResponseError(
                    "Gmail message header exceeds its limit"
                )
            output.append((name, value))
    return tuple(output)


def _collect_mime_text(
    payload: object,
    *,
    depth: int,
    state: dict[str, int | bool],
    plain: list[str],
    html: list[str],
) -> None:
    if (
        not isinstance(payload, dict)
        or not set(payload).issubset(_ALLOWED_PAYLOAD_KEYS)
        or depth > MAX_GMAIL_MIME_DEPTH
    ):
        raise ConnectorResponseError("Gmail MIME payload is invalid")
    state["parts"] = int(state["parts"]) + 1
    if int(state["parts"]) > MAX_GMAIL_MIME_PARTS:
        raise ConnectorResponseError("Gmail MIME part count exceeds its limit")
    filename = payload.get("filename", "")
    if not isinstance(filename, str) or len(filename) > 1_024:
        raise ConnectorResponseError("Gmail MIME filename is invalid")
    mime_type = payload.get("mimeType", "")
    if not isinstance(mime_type, str) or len(mime_type) > 256:
        raise ConnectorResponseError("Gmail MIME type is invalid")
    body = payload.get("body", {})
    if not isinstance(body, dict) or not set(body).issubset(_ALLOWED_BODY_KEYS):
        raise ConnectorResponseError("Gmail MIME body is invalid")
    data = body.get("data")
    attachment_id = body.get("attachmentId")
    if attachment_id is not None and (
        not isinstance(attachment_id, str) or len(attachment_id) > 256
    ):
        raise ConnectorResponseError("Gmail attachment identity is invalid")
    if not filename and attachment_id is None and data:
        decoded = _base64url_decode(data, "Gmail MIME body")
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            text = decoded.decode("utf-8", errors="replace")
        target = plain if mime_type.casefold() == "text/plain" else html
        if mime_type.casefold() in {"text/plain", "text/html"}:
            used = sum(len(item) for item in plain) + sum(
                len(item) for item in html
            )
            remaining = MAX_GMAIL_BODY_CHARS - used
            if remaining > 0:
                target.append(text[:remaining])
            if len(text) > remaining:
                state["truncated"] = True
    parts = payload.get("parts", [])
    if not isinstance(parts, list) or len(parts) > MAX_GMAIL_MIME_PARTS:
        raise ConnectorResponseError("Gmail MIME child parts are invalid")
    for part in parts:
        _collect_mime_text(
            part,
            depth=depth + 1,
            state=state,
            plain=plain,
            html=html,
        )


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._hidden = 0

    def handle_starttag(self, tag: str, _attrs) -> None:
        if tag.casefold() in {"script", "style"}:
            self._hidden += 1
        elif not self._hidden and tag.casefold() in {"br", "p", "div", "li"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() in {"script", "style"} and self._hidden:
            self._hidden -= 1
        elif not self._hidden and tag.casefold() in {"p", "div", "li"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._hidden:
            self.parts.append(data)


def _html_to_text(value: str) -> str:
    parser = _TextExtractor()
    try:
        parser.feed(value)
        parser.close()
    except Exception as exc:
        raise ConnectorResponseError("Gmail HTML body is invalid") from exc
    return "".join(parser.parts)


def _parse_created_draft(
    response: GmailHttpResponse,
) -> tuple[str, str, str]:
    payload = _json_payload(response)
    if set(payload) != {"id", "message"} or not isinstance(
        payload["message"], dict
    ):
        raise ConnectorResponseError("Gmail draft response shape is invalid")
    message = payload["message"]
    if not set(message).issubset({"id", "threadId", "labelIds"}):
        raise ConnectorResponseError("Gmail draft message shape is invalid")
    try:
        return (
            _opaque_id(payload["id"], "Gmail draft ID"),
            _opaque_id(message["id"], "Gmail draft message ID"),
            _opaque_id(message["threadId"], "Gmail draft thread ID"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectorResponseError("Gmail draft identity is invalid") from exc


def _verify_created_draft(
    response: GmailHttpResponse,
    request: GmailDraftRequest,
    *,
    draft_id: str,
    message_id: str,
    thread_id: str,
) -> None:
    payload = _json_payload(response)
    if (
        set(payload) != {"id", "message"}
        or payload.get("id") != draft_id
        or not isinstance(payload.get("message"), dict)
    ):
        raise GmailDraftVerificationError(
            "Gmail draft read-back identity is invalid"
        )
    message = payload["message"]
    if (
        not set(message).issubset(_ALLOWED_MESSAGE_KEYS | {"raw"})
        or message.get("id") != message_id
        or message.get("threadId") != thread_id
        or not isinstance(message.get("raw"), str)
    ):
        raise GmailDraftVerificationError(
            "Gmail draft read-back message is invalid"
        )
    raw = _base64url_decode(message["raw"], "Gmail draft raw message")
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise GmailDraftVerificationError(
            "Gmail draft MIME read-back is invalid"
        ) from exc
    if not isinstance(parsed, Message):
        raise GmailDraftVerificationError(
            "Gmail draft MIME read-back is invalid"
        )
    try:
        expected = BytesParser(policy=policy.default).parsebytes(
            request.raw_message()
        )
    except Exception as exc:
        raise GmailDraftVerificationError(
            "Approved Gmail draft MIME is invalid"
        ) from exc
    actual_to = _parsed_header_addresses(parsed, "to")
    actual_cc = _parsed_header_addresses(parsed, "cc")
    actual_bcc = _parsed_header_addresses(parsed, "bcc")
    actual_subject = str(parsed.get("subject", ""))
    actual_body = _message_plain_body(parsed)
    if (
        actual_to != _parsed_header_addresses(expected, "to")
        or actual_cc != _parsed_header_addresses(expected, "cc")
        or actual_bcc != _parsed_header_addresses(expected, "bcc")
        or actual_subject != str(expected.get("subject", ""))
        or actual_body != _message_plain_body(expected)
    ):
        raise GmailDraftVerificationError(
            "Gmail draft read-back does not match the approved content"
        )


def _parsed_header_addresses(
    message: Message,
    header_name: str,
) -> tuple[str, ...]:
    header = message.get(header_name)
    if header is None:
        return ()
    addresses = getattr(header, "addresses", None)
    if addresses is None:
        raise GmailDraftVerificationError(
            "Gmail draft recipient header is invalid"
        )
    try:
        return tuple(_address(item.addr_spec) for item in addresses)
    except (AttributeError, TypeError, ValueError) as exc:
        raise GmailDraftVerificationError(
            "Gmail draft recipient header is invalid"
        ) from exc


def _message_plain_body(message: Message) -> str:
    if message.is_multipart():
        parts = [
            part
            for part in message.walk()
            if part.get_content_type() == "text/plain"
            and part.get_content_disposition() != "attachment"
        ]
        if len(parts) != 1:
            raise GmailDraftVerificationError(
                "Gmail draft read-back body is ambiguous"
            )
        body = parts[0].get_content()
    else:
        if message.get_content_type() != "text/plain":
            raise GmailDraftVerificationError(
                "Gmail draft read-back body is not plain text"
            )
        body = message.get_content()
    if not isinstance(body, str):
        raise GmailDraftVerificationError(
            "Gmail draft read-back body is invalid"
        )
    return body


__all__ = [
    "GMAIL_API_ROOT",
    "GMAIL_CREATE_DRAFT_OPERATION_ID",
    "GMAIL_SELECTED_THREAD_OPERATION_ID",
    "FixedGmailHttpsTransport",
    "GmailDraftOutcomeUnknownError",
    "GmailDraftRequest",
    "GmailDraftResult",
    "GmailDraftVerificationError",
    "GmailHttpResponse",
    "GmailMessageResult",
    "GmailSelectedThreadRequest",
    "GmailSelectedThreadResult",
    "GoogleGmailAdapter",
]
