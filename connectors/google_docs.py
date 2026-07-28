"""Least-privilege selected read and create-once Google Docs access.

The adapter reads only one caller-selected document ID.  Its only mutation is
creating one private document from an exact reviewed title/body pair, guarded
by a create-once key and exact Drive/Docs read-back.  Search, sharing,
replace-all editing, deletion, comments, suggestions, and arbitrary batch
requests are intentionally absent.
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
from docs_contracts import (
    GOOGLE_DOCS_MIME_TYPE,
    GoogleDocsDocument,
    MAX_DOCS_PROVIDER_EVIDENCE_BYTES,
    MAX_DOCS_PROVIDER_REQUESTS,
    MAX_DOCS_RESPONSE_BYTES,
    parse_google_docs_document,
    validate_docs_body,
    validate_docs_document_id,
    validate_docs_idempotency_key,
    validate_docs_title,
    verified_google_docs_url,
)


GOOGLE_DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
GOOGLE_DOCS_API_ROOT = "https://docs.googleapis.com/v1/documents"
GOOGLE_DOCS_READ_OPERATION_ID = "google_docs.read_selected_document"
GOOGLE_DOCS_CREATE_OPERATION_ID = "google_docs.create_reviewed_document"
MAX_DOCS_REQUEST_BYTES = 128 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_APP_PROPERTY_KEYS = frozenset(
    {
        "clickyDocsBodySha256",
        "clickyDocsCreateId",
        "clickyDocsRequestSha256",
    }
)


class GoogleDocsCreateOutcomeUnknownError(ConnectorRequestError):
    """A provider mutation might have succeeded and must not be retried."""


class GoogleDocsCreateVerificationError(ConnectorResponseError):
    """A create mutation did not pass exact Drive and Docs read-back."""


class GoogleDocsIdempotencyConflictError(ConnectorResponseError):
    """A create-once key names ambiguous or different document content."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Google Docs value is not canonical JSON") from exc


@dataclass(frozen=True, slots=True)
class GoogleDocsSelectedDocumentRequest:
    """One exact selected Google Docs document; never a search query."""

    selected_document_id: str = field(repr=False)
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_DOCS,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.DOCS_DOCUMENT_READ,
        init=False,
    )
    operation_id: str = field(
        default=GOOGLE_DOCS_READ_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        validate_docs_document_id(self.selected_document_id)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "include_tabs_content": True,
                        "selected_document_id": self.selected_document_id,
                        "suggestions_view_mode": (
                            "PREVIEW_WITHOUT_SUGGESTIONS"
                        ),
                    }
                )
            ).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class GoogleDocsCreateRequest:
    """One exact reviewed title/body bound to a recoverable create-once key."""

    title: str
    body_text: str = field(repr=False)
    idempotency_key: str = field(repr=False)
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_DOCS,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.DOCS_DOCUMENT_CREATE,
        init=False,
    )
    operation_id: str = field(
        default=GOOGLE_DOCS_CREATE_OPERATION_ID,
        init=False,
    )
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        validate_docs_title(self.title)
        validate_docs_body(self.body_text)
        validate_docs_idempotency_key(self.idempotency_key)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "body_bytes": len(self.body_text.encode("utf-8")),
                        "body_sha256": self.body_sha256,
                        "create_id": self.create_id,
                        "title": self.title,
                    }
                )
            ).hexdigest(),
        )

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body_text.encode("utf-8")).hexdigest()

    @property
    def create_id(self) -> str:
        return hashlib.sha256(
            self.idempotency_key.encode("utf-8")
        ).hexdigest()

    @property
    def app_properties(self) -> dict[str, str]:
        return {
            "clickyDocsBodySha256": self.body_sha256,
            "clickyDocsCreateId": self.create_id,
            "clickyDocsRequestSha256": self.request_digest,
        }

    def create_payload(self) -> dict[str, object]:
        return {
            "appProperties": self.app_properties,
            "mimeType": GOOGLE_DOCS_MIME_TYPE,
            "name": self.title,
        }

    def batch_payload(self, *, required_revision_id: str) -> dict[str, object]:
        if (
            not isinstance(required_revision_id, str)
            or not required_revision_id
            or len(required_revision_id) > 1_024
            or "\x00" in required_revision_id
            or not required_revision_id.isprintable()
        ):
            raise ValueError("Google Docs required revision ID is invalid")
        return {
            "requests": [
                {
                    "insertText": {
                        "endOfSegmentLocation": {},
                        "text": self.body_text,
                    }
                }
            ],
            "writeControl": {
                "requiredRevisionId": required_revision_id,
            },
        }

    def preview_bytes(self) -> bytes:
        return _canonical_json(
            {
                "body_text": self.body_text,
                "title": self.title,
            }
        )


@dataclass(frozen=True, slots=True)
class GoogleDocsCreateResult:
    document_id: str
    document_url: str
    title: str
    body_bytes: int
    body_sha256: str
    idempotency_status: str
    provider_request_ids: tuple[str, ...] = ()
    verified: bool = True

    def __post_init__(self) -> None:
        validate_docs_document_id(self.document_id)
        verified_google_docs_url(self.document_url, self.document_id)
        validate_docs_title(self.title)
        if type(self.body_bytes) is not int or not 1 <= self.body_bytes <= (
            64 * 1024
        ):
            raise ValueError("Google Docs result body size is invalid")
        if (
            not isinstance(self.body_sha256, str)
            or _SHA256.fullmatch(self.body_sha256) is None
        ):
            raise ValueError("Google Docs result body digest is invalid")
        if self.idempotency_status not in {
            "created",
            "recovered_empty",
            "recovered_verified",
        }:
            raise ValueError("Google Docs idempotency status is invalid")
        if (
            not isinstance(self.provider_request_ids, tuple)
            or len(self.provider_request_ids) > MAX_DOCS_PROVIDER_REQUESTS
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 256
                or "\x00" in item
                or not item.isprintable()
                for item in self.provider_request_ids
            )
        ):
            raise ValueError("Google Docs provider request evidence is invalid")
        if self.verified is not True:
            raise ValueError("Google Docs create requires read-back verification")

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "body_bytes": self.body_bytes,
                "body_sha256": self.body_sha256,
                "document_id": self.document_id,
                "document_url": self.document_url,
                "idempotency_status": self.idempotency_status,
                "provider_request_ids": list(self.provider_request_ids),
                "title": self.title,
                "verified": True,
            }
        )


@dataclass(frozen=True, slots=True)
class DocsHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Google Docs HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Google Docs content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_DOCS_RESPONSE_BYTES
        ):
            raise ValueError("Google Docs response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Google Docs retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("Google Docs provider request ID is invalid")


class DocsHttpTransport(Protocol):
    def list_creations(
        self,
        *,
        create_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse: ...

    def create_document_file(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse: ...

    def get_file_metadata(
        self,
        *,
        document_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse: ...

    def get_document(
        self,
        *,
        document_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
        for_update: bool,
    ) -> DocsHttpResponse: ...

    def insert_text(
        self,
        *,
        document_id: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleDocsHttpsTransport:
    """Fixed Drive/Docs hosts, bounded bodies, no proxies or redirects."""

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
            raise ValueError("Google Docs request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def list_creations(
        self,
        *,
        create_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse:
        if not isinstance(create_id, str) or _SHA256.fullmatch(
            create_id
        ) is None:
            raise ValueError("Google Docs create lookup ID is invalid")
        query = (
            "appProperties has { key='clickyDocsCreateId' and "
            f"value='{create_id}' }} and "
            f"mimeType = '{GOOGLE_DOCS_MIME_TYPE}' and trashed = false"
        )
        endpoint = GOOGLE_DRIVE_FILES_ENDPOINT + "?" + urllib.parse.urlencode(
            {
                "corpora": "user",
                "fields": (
                    "files(id,name,mimeType,appProperties,trashed),"
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

    def create_document_file(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse:
        endpoint = GOOGLE_DRIVE_FILES_ENDPOINT + "?" + urllib.parse.urlencode(
            {
                "fields": "id,name,mimeType,appProperties,trashed",
                "ignoreDefaultVisibility": "true",
            }
        )
        return self._request(
            endpoint=endpoint,
            method="POST",
            body=_request_body(payload),
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=True,
        )

    def get_file_metadata(
        self,
        *,
        document_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse:
        document_id = validate_docs_document_id(document_id)
        encoded = urllib.parse.quote(document_id, safe="")
        endpoint = (
            f"{GOOGLE_DRIVE_FILES_ENDPOINT}/{encoded}?"
            + urllib.parse.urlencode(
                {
                    "fields": (
                        "id,name,mimeType,appProperties,trashed,webViewLink"
                    )
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

    def get_document(
        self,
        *,
        document_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
        for_update: bool,
    ) -> DocsHttpResponse:
        document_id = validate_docs_document_id(document_id)
        encoded = urllib.parse.quote(document_id, safe="")
        endpoint = (
            f"{GOOGLE_DOCS_API_ROOT}/{encoded}?"
            + urllib.parse.urlencode(
                {
                    "includeTabsContent": "true",
                    "suggestionsViewMode": (
                        "SUGGESTIONS_INLINE"
                        if for_update
                        else "PREVIEW_WITHOUT_SUGGESTIONS"
                    ),
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

    def insert_text(
        self,
        *,
        document_id: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DocsHttpResponse:
        document_id = validate_docs_document_id(document_id)
        encoded = urllib.parse.quote(document_id, safe="")
        endpoint = f"{GOOGLE_DOCS_API_ROOT}/{encoded}:batchUpdate"
        return self._request(
            endpoint=endpoint,
            method="POST",
            body=_request_body(payload),
            access_token=access_token,
            maximum_response_bytes=maximum_response_bytes,
            mutation=True,
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
    ) -> DocsHttpResponse:
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Docs access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_DOCS_RESPONSE_BYTES
        ):
            raise ValueError("Google Docs response limit is invalid")
        _validate_fixed_endpoint(endpoint, method)
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Google Docs access token encoding is invalid"
                ) from exc
            headers = {
                "Accept": "application/json",
                "Authorization": authorization,
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Docs/1",
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
                    GoogleDocsCreateOutcomeUnknownError
                    if mutation
                    else ConnectorRequestError
                )
                raise error_type(
                    "Google Docs provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleDocsAdapter:
    """Read one selection or create once and verify exact document text."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_DOCS

    def __init__(
        self,
        account: ConnectedAccount,
        transport: DocsHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Google Docs adapter requires a connected account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Google Docs adapter account is invalid")
        candidate = transport or FixedGoogleDocsHttpsTransport()
        required = (
            "list_creations",
            "create_document_file",
            "get_file_metadata",
            "get_document",
            "insert_text",
        )
        if any(
            not callable(getattr(candidate, name, None))
            for name in required
        ):
            raise TypeError("Google Docs adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Google Docs revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: (
            GoogleDocsSelectedDocumentRequest
            | GoogleDocsCreateRequest
        ),
        access_token: SecretValue,
    ) -> ConnectorExecution[GoogleDocsDocument | GoogleDocsCreateResult]:
        if not isinstance(
            request,
            (GoogleDocsSelectedDocumentRequest, GoogleDocsCreateRequest),
        ):
            raise TypeError("Google Docs adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Docs adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_DOCS_RESPONSE_BYTES,
        )
        if isinstance(request, GoogleDocsSelectedDocumentRequest):
            return self._read_selected(
                call,
                request,
                access_token,
                maximum,
            )
        return self._create_reviewed(
            call,
            request,
            access_token,
            maximum,
        )

    def _read_selected(
        self,
        call: ConnectorCall,
        request: GoogleDocsSelectedDocumentRequest,
        access_token: SecretValue,
        maximum: int,
    ) -> ConnectorExecution[GoogleDocsDocument]:
        response = self._transport.get_document(
            document_id=request.selected_document_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
            for_update=False,
        )
        _raise_for_status(response, mutation=False)
        try:
            document = parse_google_docs_document(
                response.body,
                expected_document_id=request.selected_document_id,
            )
            document.to_json_bytes()
        except ValueError as exc:
            raise ConnectorResponseError(
                "Selected Google document response is invalid"
            ) from exc
        return ConnectorExecution(
            result=_call_result(call, response),
            output=document,
        )

    def _create_reviewed(
        self,
        call: ConnectorCall,
        request: GoogleDocsCreateRequest,
        access_token: SecretValue,
        maximum: int,
    ) -> ConnectorExecution[GoogleDocsCreateResult]:
        responses: list[DocsHttpResponse] = []
        lookup = self._transport.list_creations(
            create_id=request.create_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(lookup)
        _raise_for_status(lookup, mutation=False)
        matches = _parse_creation_matches(lookup, request)

        if not matches:
            create = self._transport.create_document_file(
                payload=MappingProxyType(request.create_payload()),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(create)
            try:
                _raise_for_status(create, mutation=True)
                document_id = _parse_created_file(create, request)
            except GoogleDocsCreateOutcomeUnknownError:
                raise
            except ConnectorResponseError as exc:
                raise GoogleDocsCreateVerificationError(
                    "Created Google document could not be verified"
                ) from exc
            current_response = self._transport.get_document(
                document_id=document_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
                for_update=True,
            )
            responses.append(current_response)
            _raise_for_status(current_response, mutation=False)
            current = _parse_document(
                current_response,
                document_id,
                verification=True,
            )
            _require_blank_document(current)
            status = "created"
        else:
            document_id = matches[0]
            metadata_response = self._transport.get_file_metadata(
                document_id=document_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(metadata_response)
            _raise_for_status(metadata_response, mutation=False)
            metadata = _parse_file_metadata(
                metadata_response,
                request,
                document_id,
            )
            current_response = self._transport.get_document(
                document_id=document_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
                for_update=True,
            )
            responses.append(current_response)
            _raise_for_status(current_response, mutation=False)
            current = _parse_document(
                current_response,
                document_id,
                verification=True,
            )
            if _document_matches(current, request):
                return _create_execution(
                    call,
                    request,
                    document_id,
                    metadata.document_url,
                    "recovered_verified",
                    responses,
                )
            _require_blank_document(current)
            status = "recovered_empty"

        if current.revision_id is None:
            raise GoogleDocsCreateVerificationError(
                "Google document revision is unavailable"
            )
        batch = self._transport.insert_text(
            document_id=document_id,
            payload=MappingProxyType(
                request.batch_payload(
                    required_revision_id=current.revision_id,
                )
            ),
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(batch)
        try:
            _raise_for_status(batch, mutation=True)
            _verify_batch_update(batch, document_id)
        except GoogleDocsCreateOutcomeUnknownError:
            raise
        except ConnectorResponseError as exc:
            raise GoogleDocsCreateVerificationError(
                "Google Docs insert response could not be verified"
            ) from exc

        metadata_response = self._transport.get_file_metadata(
            document_id=document_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(metadata_response)
        _raise_for_status(metadata_response, mutation=False)
        metadata = _parse_file_metadata(
            metadata_response,
            request,
            document_id,
        )
        final_response = self._transport.get_document(
            document_id=document_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
            for_update=False,
        )
        responses.append(final_response)
        _raise_for_status(final_response, mutation=False)
        final = _parse_document(
            final_response,
            document_id,
            verification=True,
        )
        if not _document_matches(final, request):
            raise GoogleDocsCreateVerificationError(
                "Google document failed exact read-back"
            )
        return _create_execution(
            call,
            request,
            document_id,
            metadata.document_url,
            status,
            responses,
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
            raise TypeError("Google Docs revocation evidence is invalid")
        return result


@dataclass(frozen=True, slots=True)
class _DriveDocumentMetadata:
    document_url: str


def _create_execution(
    call: ConnectorCall,
    request: GoogleDocsCreateRequest,
    document_id: str,
    document_url: str,
    idempotency_status: str,
    responses: list[DocsHttpResponse],
) -> ConnectorExecution[GoogleDocsCreateResult]:
    if not 1 <= len(responses) <= MAX_DOCS_PROVIDER_REQUESTS:
        raise ConnectorResponseError(
            "Google Docs provider request count is invalid"
        )
    evidence = b"\x00".join(response.body for response in responses)
    if len(evidence) > MAX_DOCS_PROVIDER_EVIDENCE_BYTES:
        raise ConnectorResponseError(
            "Google Docs provider evidence exceeds its limit"
        )
    output = GoogleDocsCreateResult(
        document_id=document_id,
        document_url=document_url,
        title=request.title,
        body_bytes=len(request.body_text.encode("utf-8")),
        body_sha256=request.body_sha256,
        idempotency_status=idempotency_status,
        provider_request_ids=tuple(
            response.provider_request_id
            for response in responses
            if response.provider_request_id is not None
        ),
    )
    return ConnectorExecution(
        result=ConnectorCallResult(
            call_id=call.call_id,
            run_id=call.run_id,
            operation_id=call.operation_id,
            http_status=responses[-1].status,
            response_digest=hashlib.sha256(evidence).hexdigest(),
            response_bytes=len(evidence),
            provider_request_id=responses[-1].provider_request_id,
        ),
        output=output,
    )


def _call_result(
    call: ConnectorCall,
    response: DocsHttpResponse,
) -> ConnectorCallResult:
    return ConnectorCallResult(
        call_id=call.call_id,
        run_id=call.run_id,
        operation_id=call.operation_id,
        http_status=response.status,
        response_digest=hashlib.sha256(response.body).hexdigest(),
        response_bytes=len(response.body),
        provider_request_id=response.provider_request_id,
    )


def _parse_creation_matches(
    response: DocsHttpResponse,
    request: GoogleDocsCreateRequest,
) -> tuple[str, ...]:
    payload = _json_object(response, "Google Drive document lookup")
    if not set(payload).issubset(
        {"files", "incompleteSearch", "nextPageToken"}
    ):
        raise ConnectorResponseError(
            "Google Drive document lookup shape is invalid"
        )
    if payload.get("incompleteSearch") is True or payload.get(
        "nextPageToken"
    ):
        raise GoogleDocsIdempotencyConflictError(
            "Google Drive document lookup is incomplete"
        )
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > 1:
        raise GoogleDocsIdempotencyConflictError(
            "Google Docs idempotency key is ambiguous"
        )
    matches: list[str] = []
    for raw in files:
        document_id, properties = _parse_drive_file(
            raw,
            request,
            include_url=False,
        )
        if properties != request.app_properties:
            raise GoogleDocsIdempotencyConflictError(
                "Google Docs idempotency key names another document"
            )
        matches.append(document_id)
    return tuple(matches)


def _parse_created_file(
    response: DocsHttpResponse,
    request: GoogleDocsCreateRequest,
) -> str:
    payload = _json_object(response, "Google Drive document create")
    document_id, properties = _parse_drive_file(
        payload,
        request,
        include_url=False,
    )
    if properties != request.app_properties:
        raise GoogleDocsCreateVerificationError(
            "Created Google document metadata does not match"
        )
    return document_id


def _parse_file_metadata(
    response: DocsHttpResponse,
    request: GoogleDocsCreateRequest,
    document_id: str,
) -> _DriveDocumentMetadata:
    payload = _json_object(response, "Google Drive document metadata")
    actual_id, properties = _parse_drive_file(
        payload,
        request,
        include_url=True,
    )
    if actual_id != document_id or properties != request.app_properties:
        raise GoogleDocsCreateVerificationError(
            "Google document Drive identity does not match"
        )
    try:
        document_url = verified_google_docs_url(
            payload["webViewLink"],
            document_id,
        )
    except (KeyError, ValueError) as exc:
        raise GoogleDocsCreateVerificationError(
            "Google document URL is invalid"
        ) from exc
    return _DriveDocumentMetadata(document_url=document_url)


def _parse_drive_file(
    raw: object,
    request: GoogleDocsCreateRequest,
    *,
    include_url: bool,
) -> tuple[str, dict[str, str]]:
    fields = {
        "appProperties",
        "id",
        "mimeType",
        "name",
        "trashed",
    }
    if include_url:
        fields.add("webViewLink")
    if (
        not isinstance(raw, dict)
        or set(raw) != fields
        or raw.get("mimeType") != GOOGLE_DOCS_MIME_TYPE
        or raw.get("name") != request.title
        or raw.get("trashed") is not False
        or not isinstance(raw.get("appProperties"), dict)
        or set(raw["appProperties"]) != _APP_PROPERTY_KEYS
        or any(
            not isinstance(value, str)
            for value in raw["appProperties"].values()
        )
        or (include_url and not isinstance(raw.get("webViewLink"), str))
    ):
        raise ConnectorResponseError(
            "Google Drive document metadata is invalid"
        )
    try:
        document_id = validate_docs_document_id(raw["id"])
    except (KeyError, ValueError) as exc:
        raise ConnectorResponseError(
            "Google document ID is invalid"
        ) from exc
    return document_id, dict(raw["appProperties"])


def _parse_document(
    response: DocsHttpResponse,
    document_id: str,
    *,
    verification: bool,
) -> GoogleDocsDocument:
    try:
        return parse_google_docs_document(
            response.body,
            expected_document_id=document_id,
        )
    except ValueError as exc:
        error_type = (
            GoogleDocsCreateVerificationError
            if verification
            else ConnectorResponseError
        )
        raise error_type("Google Docs document response is invalid") from exc


def _require_blank_document(document: GoogleDocsDocument) -> None:
    if (
        len(document.tabs) != 1
        or document.tabs[0].parent_tab_id is not None
        or document.tabs[0].content_text != ""
    ):
        raise GoogleDocsIdempotencyConflictError(
            "Recovered Google document is not an empty create target"
        )


def _document_matches(
    document: GoogleDocsDocument,
    request: GoogleDocsCreateRequest,
) -> bool:
    return (
        document.title == request.title
        and len(document.tabs) == 1
        and document.tabs[0].parent_tab_id is None
        and document.tabs[0].content_text == request.body_text
        and document.tabs[0].content_sha256 == request.body_sha256
    )


def _verify_batch_update(
    response: DocsHttpResponse,
    document_id: str,
) -> None:
    payload = _json_object(response, "Google Docs batch update")
    if (
        not set(payload).issubset(
            {"documentId", "replies", "writeControl"}
        )
        or payload.get("documentId") != document_id
        or payload.get("replies") != [{}]
    ):
        raise GoogleDocsCreateVerificationError(
            "Google Docs batch response shape is invalid"
        )
    write_control = payload.get("writeControl")
    if write_control is not None and (
        not isinstance(write_control, dict)
        or not set(write_control).issubset({"requiredRevisionId"})
        or (
            "requiredRevisionId" in write_control
            and (
                not isinstance(
                    write_control["requiredRevisionId"],
                    str,
                )
                or not write_control["requiredRevisionId"]
                or len(write_control["requiredRevisionId"]) > 1_024
            )
        )
    ):
        raise GoogleDocsCreateVerificationError(
            "Google Docs write control evidence is invalid"
        )


def _raise_for_status(
    response: DocsHttpResponse,
    *,
    mutation: bool,
) -> None:
    if not isinstance(response, DocsHttpResponse):
        raise TypeError("Google Docs transport response is invalid")
    if 200 <= response.status <= 299:
        media_type = (
            response.content_type.casefold().split(";", 1)[0].strip()
        )
        if media_type != "application/json":
            raise ConnectorResponseError(
                "Google Docs response content type is invalid"
            )
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Google Docs access token expired or is invalid"
        )
    if response.status in {429, 503}:
        if mutation:
            raise GoogleDocsCreateOutcomeUnknownError(
                "Google Docs mutation outcome is unknown"
            )
        raise ConnectorRateLimitError(response.retry_after_seconds or 0)
    if mutation and (
        response.status in {408, 425}
        or 500 <= response.status <= 599
    ):
        raise GoogleDocsCreateOutcomeUnknownError(
            "Google Docs mutation outcome is unknown"
        )
    raise ConnectorRequestError("Google Docs provider request failed")


def _json_object(
    response: DocsHttpResponse,
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
            raise ValueError("Duplicate Google Docs JSON field")
        output[key] = value
    return output


def _reject_json_constant(_value: str):
    raise ValueError("Google Docs JSON constants are invalid")


def _request_body(payload: Mapping[str, object]) -> bytes:
    if not isinstance(payload, Mapping) or not payload:
        raise ConnectorRequestError(
            "Google Docs request payload is invalid"
        )
    encoded = _canonical_json(dict(payload))
    if len(encoded) > MAX_DOCS_REQUEST_BYTES:
        raise ConnectorRequestError(
            "Google Docs request exceeds its limit"
        )
    return encoded


def _validate_fixed_endpoint(endpoint: str, method: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConnectorRequestError(
            "Google Docs endpoint is invalid"
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname
        not in {"www.googleapis.com", "docs.googleapis.com"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or method not in {"GET", "POST"}
    ):
        raise ConnectorRequestError(
            "Google Docs endpoint is not fixed by policy"
        )
    if parsed.hostname == "www.googleapis.com":
        if method == "POST":
            valid = parsed.path == "/drive/v3/files"
        else:
            valid = (
                parsed.path == "/drive/v3/files"
                or re.fullmatch(
                    r"/drive/v3/files/[A-Za-z0-9_-]{1,256}",
                    parsed.path,
                )
                is not None
            )
        if not valid:
            raise ConnectorRequestError(
                "Google Drive endpoint is not fixed by policy"
            )
        return
    if method == "GET":
        valid = (
            re.fullmatch(
                r"/v1/documents/[A-Za-z0-9_-]{1,256}",
                parsed.path,
            )
            is not None
        )
    else:
        valid = (
            re.fullmatch(
                r"/v1/documents/[A-Za-z0-9_-]{1,256}:batchUpdate",
                parsed.path,
            )
            is not None
        )
    if not valid:
        raise ConnectorRequestError(
            "Google Docs endpoint is not fixed by policy"
        )


def _bounded_http_response(
    response,
    maximum: int,
) -> DocsHttpResponse:
    content_length = response.headers.get("Content-Length")
    if content_length is not None and (
        not content_length.isascii()
        or not content_length.isdigit()
        or int(content_length) > maximum
    ):
        raise ConnectorResponseError(
            "Google Docs provider response exceeds its limit"
        )
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ConnectorResponseError(
            "Google Docs provider response exceeds its limit"
        )
    request_id = next(
        (
            value
            for name in (
                "X-Request-Id",
                "X-Goog-Request-Id",
                "X-GUploader-UploadID",
            )
            for value in (response.headers.get(name),)
            if value
        ),
        None,
    )
    retry_after = response.headers.get("Retry-After")
    retry_seconds = None
    if retry_after is not None:
        try:
            candidate = int(retry_after, 10)
        except ValueError:
            candidate = -1
        if 0 <= candidate <= 24 * 60 * 60:
            retry_seconds = candidate
    return DocsHttpResponse(
        status=response.status,
        content_type=response.headers.get("Content-Type", ""),
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


__all__ = [
    "DocsHttpResponse",
    "DocsHttpTransport",
    "FixedGoogleDocsHttpsTransport",
    "GOOGLE_DOCS_CREATE_OPERATION_ID",
    "GOOGLE_DOCS_READ_OPERATION_ID",
    "GoogleDocsAdapter",
    "GoogleDocsCreateOutcomeUnknownError",
    "GoogleDocsCreateRequest",
    "GoogleDocsCreateResult",
    "GoogleDocsCreateVerificationError",
    "GoogleDocsIdempotencyConflictError",
    "GoogleDocsSelectedDocumentRequest",
    "MAX_DOCS_PROVIDER_EVIDENCE_BYTES",
    "MAX_DOCS_PROVIDER_REQUESTS",
    "MAX_DOCS_RESPONSE_BYTES",
]
