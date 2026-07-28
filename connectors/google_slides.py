"""Least-privilege export of one verified local specification to Google Slides.

The adapter can create one private presentation, populate only deterministic
blank slides with title/body text boxes, and read the resulting file and
presentation back.  It exposes no arbitrary presentation, file search, share,
image, video, chart, link, comment, speaker-note, or delete surface.
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
from slides_contracts import (
    MAX_SLIDES,
    MAX_SLIDES_PROVIDER_REQUESTS,
    ValidatedSlideSpecification,
    validate_slides_idempotency_key,
)


GOOGLE_DRIVE_FILES_ENDPOINT = "https://www.googleapis.com/drive/v3/files"
GOOGLE_SLIDES_API_ROOT = "https://slides.googleapis.com/v1/presentations"
GOOGLE_SLIDES_MIME_TYPE = "application/vnd.google-apps.presentation"
GOOGLE_SLIDES_EXPORT_OPERATION_ID = (
    "google_slides.export_validated_presentation"
)
MAX_SLIDES_RESPONSE_BYTES = 1024 * 1024
MAX_SLIDES_REQUEST_BYTES = 128 * 1024
MAX_SLIDES_PROVIDER_EVIDENCE_BYTES = (
    MAX_SLIDES_PROVIDER_REQUESTS * MAX_SLIDES_RESPONSE_BYTES
    + MAX_SLIDES_PROVIDER_REQUESTS
    - 1
)
MAX_INITIAL_SLIDES = 1
MAX_BATCH_REQUESTS = MAX_INITIAL_SLIDES + MAX_SLIDES * 5
_PROVIDER_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_OBJECT_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_:-]{4,49}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_APP_PROPERTY_KEYS = frozenset(
    {
        "clickySlidesExportId",
        "clickySlidesRequestSha256",
        "clickySlidesSourceSha256",
    }
)


class GoogleSlidesExportOutcomeUnknownError(ConnectorRequestError):
    """A provider mutation might have succeeded and must not be retried."""


class GoogleSlidesExportVerificationError(ConnectorResponseError):
    """The mutation did not pass exact Drive and Slides read-back."""


class GoogleSlidesIdempotencyConflictError(ConnectorResponseError):
    """An operation key names ambiguous or different presentation content."""


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
        raise ValueError("Google Slides value is not canonical JSON") from exc


def _provider_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or _PROVIDER_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _slide_id(index: int) -> str:
    return f"clicky_slide_{index:02d}"


def _title_id(index: int) -> str:
    return f"clicky_title_{index:02d}"


def _body_id(index: int) -> str:
    return f"clicky_body_{index:02d}"


@dataclass(frozen=True, slots=True)
class GoogleSlidesExportRequest:
    """One exact presentation bound to a recoverable create-once key."""

    specification: ValidatedSlideSpecification = field(repr=False)
    idempotency_key: str = field(repr=False)
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_SLIDES,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.SLIDES_PRESENTATION_WRITE,
        init=False,
    )
    operation_id: str = field(
        default=GOOGLE_SLIDES_EXPORT_OPERATION_ID,
        init=False,
    )
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(
            self.specification,
            ValidatedSlideSpecification,
        ):
            raise TypeError("Google Slides specification is invalid")
        validate_slides_idempotency_key(self.idempotency_key)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "idempotency_key_sha256": self.export_id,
                        "schema_version": self.specification.schema_version,
                        "slide_count": self.specification.slide_count,
                        "slide_titles": list(
                            self.specification.slide_titles
                        ),
                        "source_bytes": self.specification.source_bytes,
                        "source_sha256": (
                            self.specification.source_sha256
                        ),
                        "title": self.specification.title,
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
            "clickySlidesExportId": self.export_id,
            "clickySlidesRequestSha256": self.request_digest,
            "clickySlidesSourceSha256": (
                self.specification.source_sha256
            ),
        }

    def create_payload(self) -> dict[str, object]:
        return {
            "appProperties": self.app_properties,
            "mimeType": GOOGLE_SLIDES_MIME_TYPE,
            "name": self.specification.title,
        }

    def batch_payload(
        self,
        *,
        initial_slide_ids: tuple[str, ...],
    ) -> dict[str, object]:
        if (
            not isinstance(initial_slide_ids, tuple)
            or len(initial_slide_ids) > MAX_INITIAL_SLIDES
            or any(
                not isinstance(item, str)
                or _OBJECT_ID.fullmatch(item) is None
                for item in initial_slide_ids
            )
        ):
            raise ValueError(
                "Google Slides initial page identity is invalid"
            )
        requests: list[dict[str, object]] = [
            {"deleteObject": {"objectId": object_id}}
            for object_id in initial_slide_ids
        ]
        for offset, slide in enumerate(
            self.specification.slides,
            start=1,
        ):
            slide_id = _slide_id(offset)
            title_id = _title_id(offset)
            body_id = _body_id(offset)
            requests.extend(
                [
                    {
                        "createSlide": {
                            "insertionIndex": offset - 1,
                            "objectId": slide_id,
                            "slideLayoutReference": {
                                "predefinedLayout": "BLANK"
                            },
                        }
                    },
                    {
                        "createShape": {
                            "elementProperties": _element_properties(
                                slide_id,
                                width=640,
                                height=52,
                                x=40,
                                y=28,
                            ),
                            "objectId": title_id,
                            "shapeType": "TEXT_BOX",
                        }
                    },
                    {
                        "insertText": {
                            "insertionIndex": 0,
                            "objectId": title_id,
                            "text": slide.title,
                        }
                    },
                    {
                        "createShape": {
                            "elementProperties": _element_properties(
                                slide_id,
                                width=640,
                                height=270,
                                x=40,
                                y=104,
                            ),
                            "objectId": body_id,
                            "shapeType": "TEXT_BOX",
                        }
                    },
                    {
                        "insertText": {
                            "insertionIndex": 0,
                            "objectId": body_id,
                            "text": slide.text,
                        }
                    },
                ]
            )
        if not 1 <= len(requests) <= MAX_BATCH_REQUESTS:
            raise ValueError("Google Slides batch request count is invalid")
        return {"requests": requests}


@dataclass(frozen=True, slots=True)
class GoogleSlidesExportResult:
    presentation_id: str
    title: str
    presentation_url: str
    slide_titles: tuple[str, ...]
    source_sha256: str
    idempotency_status: str
    provider_request_ids: tuple[str, ...] = ()
    verified: bool = True

    def __post_init__(self) -> None:
        _provider_id(self.presentation_id, "Google presentation ID")
        if (
            not isinstance(self.title, str)
            or not self.title
            or len(self.title) > 200
            or "\x00" in self.title
            or not self.title.isprintable()
            or not isinstance(self.slide_titles, tuple)
            or not 1 <= len(self.slide_titles) <= MAX_SLIDES
            or any(
                not isinstance(item, str)
                or not item
                or len(item) > 160
                or "\x00" in item
                or not item.isprintable()
                for item in self.slide_titles
            )
        ):
            raise ValueError("Google Slides result content is invalid")
        _verified_presentation_url(
            self.presentation_url,
            self.presentation_id,
        )
        if (
            not isinstance(self.source_sha256, str)
            or _SHA256.fullmatch(self.source_sha256) is None
        ):
            raise ValueError(
                "Google Slides result source digest is invalid"
            )
        if self.idempotency_status not in {
            "created",
            "recovered_empty",
            "recovered_verified",
        }:
            raise ValueError(
                "Google Slides idempotency status is invalid"
            )
        if (
            not isinstance(self.provider_request_ids, tuple)
            or len(self.provider_request_ids)
            > MAX_SLIDES_PROVIDER_REQUESTS
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
                "Google Slides provider request evidence is invalid"
            )
        if self.verified is not True:
            raise ValueError(
                "Google Slides export requires read-back verification"
            )

    @property
    def slide_count(self) -> int:
        return len(self.slide_titles)

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "idempotency_status": self.idempotency_status,
                "presentation_id": self.presentation_id,
                "presentation_url": self.presentation_url,
                "provider_request_ids": list(self.provider_request_ids),
                "slide_count": self.slide_count,
                "slide_titles": list(self.slide_titles),
                "source_sha256": self.source_sha256,
                "title": self.title,
                "verified": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SlidesHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Google Slides HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Google Slides content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_SLIDES_RESPONSE_BYTES
        ):
            raise ValueError("Google Slides response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Google Slides retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError(
                "Google Slides provider request ID is invalid"
            )


class SlidesHttpTransport(Protocol):
    def list_exports(
        self,
        *,
        export_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse: ...

    def create_presentation_file(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse: ...

    def get_file_metadata(
        self,
        *,
        presentation_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse: ...

    def get_presentation(
        self,
        *,
        presentation_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse: ...

    def batch_update(
        self,
        *,
        presentation_id: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleSlidesHttpsTransport:
    """Fixed Drive/Slides hosts, bounded bodies, no proxies or redirects."""

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
            raise ValueError("Google Slides request timeout is invalid")
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
    ) -> SlidesHttpResponse:
        if not isinstance(export_id, str) or _SHA256.fullmatch(
            export_id
        ) is None:
            raise ValueError("Google Slides export lookup ID is invalid")
        query = (
            "appProperties has { key='clickySlidesExportId' and "
            f"value='{export_id}' }} and "
            f"mimeType = '{GOOGLE_SLIDES_MIME_TYPE}' and trashed = false"
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

    def create_presentation_file(
        self,
        *,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse:
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
        presentation_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse:
        presentation_id = _provider_id(
            presentation_id,
            "Google presentation ID",
        )
        encoded_id = urllib.parse.quote(presentation_id, safe="")
        endpoint = (
            f"{GOOGLE_DRIVE_FILES_ENDPOINT}/{encoded_id}?"
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

    def get_presentation(
        self,
        *,
        presentation_id: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse:
        presentation_id = _provider_id(
            presentation_id,
            "Google presentation ID",
        )
        encoded_id = urllib.parse.quote(presentation_id, safe="")
        endpoint = (
            f"{GOOGLE_SLIDES_API_ROOT}/{encoded_id}?"
            + urllib.parse.urlencode(
                {
                    "fields": (
                        "presentationId,title,"
                        "slides(objectId,pageElements("
                        "objectId,shape(shapeType,text("
                        "textElements(textRun(content))))))"
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

    def batch_update(
        self,
        *,
        presentation_id: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> SlidesHttpResponse:
        presentation_id = _provider_id(
            presentation_id,
            "Google presentation ID",
        )
        encoded_id = urllib.parse.quote(presentation_id, safe="")
        endpoint = (
            f"{GOOGLE_SLIDES_API_ROOT}/{encoded_id}:batchUpdate"
        )
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
    ) -> SlidesHttpResponse:
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Slides access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1
            <= maximum_response_bytes
            <= MAX_SLIDES_RESPONSE_BYTES
        ):
            raise ValueError("Google Slides response limit is invalid")
        _validate_fixed_endpoint(endpoint, method)
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Google Slides access token encoding is invalid"
                ) from exc
            headers = {
                "Accept": "application/json",
                "Authorization": authorization,
                "Cache-Control": "no-store",
                "User-Agent": "Clicky-Windows-Slides/1",
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
                    GoogleSlidesExportOutcomeUnknownError
                    if mutation
                    else ConnectorRequestError
                )
                raise error_type(
                    "Google Slides provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleSlidesExportAdapter:
    """Create once, recover by app property, and verify exact slide text."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_SLIDES

    def __init__(
        self,
        account: ConnectedAccount,
        transport: SlidesHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError(
                "Google Slides adapter requires a connected account"
            )
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Google Slides adapter account is invalid")
        candidate = transport or FixedGoogleSlidesHttpsTransport()
        required = (
            "list_exports",
            "create_presentation_file",
            "get_file_metadata",
            "get_presentation",
            "batch_update",
        )
        if any(not callable(getattr(candidate, name, None)) for name in required):
            raise TypeError("Google Slides adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Google Slides revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: GoogleSlidesExportRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[GoogleSlidesExportResult]:
        if not isinstance(request, GoogleSlidesExportRequest):
            raise TypeError("Google Slides adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Google Slides adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_SLIDES_RESPONSE_BYTES,
        )
        responses: list[SlidesHttpResponse] = []

        lookup = self._transport.list_exports(
            export_id=request.export_id,
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(lookup)
        _raise_for_status(lookup, mutation=False)
        matches = _parse_export_matches(lookup, request)

        initial_slide_ids: tuple[str, ...]
        if not matches:
            create = self._transport.create_presentation_file(
                payload=MappingProxyType(request.create_payload()),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(create)
            try:
                _raise_for_status(create, mutation=True)
                presentation_id = _parse_created_file(create, request)
            except GoogleSlidesExportOutcomeUnknownError:
                raise
            except GoogleSlidesExportVerificationError:
                raise
            except ConnectorResponseError as exc:
                raise GoogleSlidesExportVerificationError(
                    "Created Google presentation could not be verified"
                ) from exc
            current = self._transport.get_presentation(
                presentation_id=presentation_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(current)
            try:
                _raise_for_status(current, mutation=False)
                initial_slide_ids = _initial_slide_ids(
                    current,
                    request,
                    presentation_id,
                )
            except ConnectorError as exc:
                raise GoogleSlidesExportVerificationError(
                    "Created Google presentation could not be initialized"
                ) from exc
            idempotency_status = "created"
        else:
            presentation_id = matches[0]
            metadata_response = self._transport.get_file_metadata(
                presentation_id=presentation_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(metadata_response)
            _raise_for_status(metadata_response, mutation=False)
            metadata = _parse_file_metadata(
                metadata_response,
                request,
                presentation_id,
            )
            current = self._transport.get_presentation(
                presentation_id=presentation_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(current)
            _raise_for_status(current, mutation=False)
            if _presentation_matches(
                current,
                request,
                presentation_id,
            ):
                return _execution(
                    call,
                    request,
                    presentation_id,
                    metadata.presentation_url,
                    "recovered_verified",
                    responses,
                )
            if not _presentation_is_empty(
                current,
                request,
                presentation_id,
            ):
                raise GoogleSlidesIdempotencyConflictError(
                    "Recovered Google presentation contains different content"
                )
            initial_slide_ids = ()
            idempotency_status = "recovered_empty"

        batch_payload = request.batch_payload(
            initial_slide_ids=initial_slide_ids
        )
        batch = self._transport.batch_update(
            presentation_id=presentation_id,
            payload=MappingProxyType(batch_payload),
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        responses.append(batch)
        try:
            _raise_for_status(batch, mutation=True)
        except GoogleSlidesExportOutcomeUnknownError:
            raise
        except ConnectorResponseError as exc:
            raise GoogleSlidesExportVerificationError(
                "Google Slides batch response could not be verified"
            ) from exc
        try:
            _verify_batch_update(
                batch,
                request,
                presentation_id,
                initial_slide_ids=initial_slide_ids,
            )
            metadata_response = self._transport.get_file_metadata(
                presentation_id=presentation_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(metadata_response)
            _raise_for_status(metadata_response, mutation=False)
            metadata = _parse_file_metadata(
                metadata_response,
                request,
                presentation_id,
            )
            presentation_response = self._transport.get_presentation(
                presentation_id=presentation_id,
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            responses.append(presentation_response)
            _raise_for_status(presentation_response, mutation=False)
            if not _presentation_matches(
                presentation_response,
                request,
                presentation_id,
            ):
                raise GoogleSlidesExportVerificationError(
                    "Google presentation failed exact read-back"
                )
            return _execution(
                call,
                request,
                presentation_id,
                metadata.presentation_url,
                idempotency_status,
                responses,
            )
        except GoogleSlidesExportVerificationError:
            raise
        except ConnectorError as exc:
            raise GoogleSlidesExportVerificationError(
                "Google presentation write could not be verified"
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
                "Google Slides revocation evidence is invalid"
            )
        return result


@dataclass(frozen=True, slots=True)
class _DrivePresentationMetadata:
    presentation_url: str


def _execution(
    call: ConnectorCall,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
    presentation_url: str,
    idempotency_status: str,
    responses: list[SlidesHttpResponse],
) -> ConnectorExecution[GoogleSlidesExportResult]:
    if not 1 <= len(responses) <= MAX_SLIDES_PROVIDER_REQUESTS:
        raise ConnectorResponseError(
            "Google Slides provider request count is invalid"
        )
    evidence = b"\x00".join(response.body for response in responses)
    if len(evidence) > MAX_SLIDES_PROVIDER_EVIDENCE_BYTES:
        raise ConnectorResponseError(
            "Google Slides provider evidence exceeds its limit"
        )
    request_ids = tuple(
        response.provider_request_id
        for response in responses
        if response.provider_request_id is not None
    )
    output = GoogleSlidesExportResult(
        presentation_id=presentation_id,
        title=request.specification.title,
        presentation_url=presentation_url,
        slide_titles=request.specification.slide_titles,
        source_sha256=request.specification.source_sha256,
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
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
) -> tuple[str, ...]:
    payload = _json_object(response, "Google Drive presentation lookup")
    if not set(payload).issubset(
        {"files", "incompleteSearch", "nextPageToken"}
    ):
        raise ConnectorResponseError(
            "Google Drive presentation lookup shape is invalid"
        )
    if payload.get("incompleteSearch") is True or payload.get(
        "nextPageToken"
    ):
        raise GoogleSlidesIdempotencyConflictError(
            "Google Drive presentation lookup is incomplete"
        )
    files = payload.get("files")
    if not isinstance(files, list) or len(files) > 1:
        raise GoogleSlidesIdempotencyConflictError(
            "Google Slides idempotency key is ambiguous"
        )
    matches: list[str] = []
    for raw in files:
        presentation_id, properties = _parse_drive_file(
            raw,
            request,
            include_url=False,
        )
        if properties != request.app_properties:
            raise GoogleSlidesIdempotencyConflictError(
                "Google Slides idempotency key names another export"
            )
        matches.append(presentation_id)
    return tuple(matches)


def _parse_created_file(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
) -> str:
    payload = _json_object(response, "Google Drive create response")
    presentation_id, properties = _parse_drive_file(
        payload,
        request,
        include_url=False,
    )
    if properties != request.app_properties:
        raise GoogleSlidesExportVerificationError(
            "Created Google presentation metadata does not match"
        )
    return presentation_id


def _parse_file_metadata(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
) -> _DrivePresentationMetadata:
    payload = _json_object(response, "Google Drive presentation metadata")
    actual_id, properties = _parse_drive_file(
        payload,
        request,
        include_url=True,
    )
    if actual_id != presentation_id or properties != request.app_properties:
        raise GoogleSlidesExportVerificationError(
            "Google presentation Drive identity does not match"
        )
    try:
        presentation_url = _verified_presentation_url(
            payload["webViewLink"],
            presentation_id,
        )
    except ValueError as exc:
        raise GoogleSlidesExportVerificationError(
            "Google presentation URL is invalid"
        ) from exc
    return _DrivePresentationMetadata(
        presentation_url=presentation_url,
    )


def _parse_drive_file(
    raw: object,
    request: GoogleSlidesExportRequest,
    *,
    include_url: bool,
) -> tuple[str, dict[str, str]]:
    expected_fields = {
        "appProperties",
        "id",
        "mimeType",
        "name",
        "trashed",
    }
    if include_url:
        expected_fields.add("webViewLink")
    if (
        not isinstance(raw, dict)
        or set(raw) != expected_fields
        or raw.get("mimeType") != GOOGLE_SLIDES_MIME_TYPE
        or raw.get("name") != request.specification.title
        or raw.get("trashed") is not False
        or not isinstance(raw.get("appProperties"), dict)
        or set(raw["appProperties"]) != _APP_PROPERTY_KEYS
        or any(
            not isinstance(value, str)
            for value in raw["appProperties"].values()
        )
        or (
            include_url
            and not isinstance(raw.get("webViewLink"), str)
        )
    ):
        raise ConnectorResponseError(
            "Google Drive presentation metadata is invalid"
        )
    try:
        presentation_id = _provider_id(
            raw["id"],
            "Google presentation ID",
        )
    except ValueError as exc:
        raise ConnectorResponseError(
            "Google presentation ID is invalid"
        ) from exc
    return presentation_id, dict(raw["appProperties"])


def _initial_slide_ids(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
) -> tuple[str, ...]:
    payload = _presentation_envelope(response, request, presentation_id)
    slides = payload.get("slides", [])
    if not isinstance(slides, list) or len(slides) > MAX_INITIAL_SLIDES:
        raise GoogleSlidesExportVerificationError(
            "New Google presentation is not blank"
        )
    output: list[str] = []
    for slide in slides:
        if (
            not isinstance(slide, dict)
            or not set(slide).issubset({"objectId", "pageElements"})
            or "objectId" not in slide
            or not isinstance(slide["objectId"], str)
            or _OBJECT_ID.fullmatch(slide["objectId"]) is None
        ):
            raise GoogleSlidesExportVerificationError(
                "New Google presentation slide identity is invalid"
            )
        output.append(slide["objectId"])
    return tuple(output)


def _presentation_is_empty(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
) -> bool:
    payload = _presentation_envelope(response, request, presentation_id)
    return payload.get("slides", []) == []


def _presentation_matches(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
) -> bool:
    try:
        payload = _presentation_envelope(
            response,
            request,
            presentation_id,
        )
        slides = payload.get("slides")
        if (
            not isinstance(slides, list)
            or len(slides) != request.specification.slide_count
        ):
            return False
        for index, (raw, expected) in enumerate(
            zip(slides, request.specification.slides, strict=True),
            start=1,
        ):
            if (
                not isinstance(raw, dict)
                or set(raw) != {"objectId", "pageElements"}
                or raw.get("objectId") != _slide_id(index)
                or not isinstance(raw.get("pageElements"), list)
                or len(raw["pageElements"]) != 2
            ):
                return False
            elements = {
                item.get("objectId"): item
                for item in raw["pageElements"]
                if isinstance(item, dict)
                and isinstance(item.get("objectId"), str)
            }
            if set(elements) != {_title_id(index), _body_id(index)}:
                return False
            if not _shape_matches(
                elements[_title_id(index)],
                expected.title,
            ) or not _shape_matches(
                elements[_body_id(index)],
                expected.text,
            ):
                return False
        return True
    except (TypeError, ValueError, ConnectorResponseError):
        return False


def _presentation_envelope(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
) -> dict[str, object]:
    payload = _json_object(response, "Google Slides presentation")
    if (
        not set(payload).issubset({"presentationId", "slides", "title"})
        or payload.get("presentationId") != presentation_id
        or payload.get("title") != request.specification.title
        or (
            "slides" in payload
            and not isinstance(payload["slides"], list)
        )
    ):
        raise GoogleSlidesExportVerificationError(
            "Google presentation identity is invalid"
        )
    return payload


def _shape_matches(value: object, expected_text: str) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != {"objectId", "shape"}
        or not isinstance(value.get("shape"), dict)
        or set(value["shape"]) != {"shapeType", "text"}
        or value["shape"].get("shapeType") != "TEXT_BOX"
        or not isinstance(value["shape"].get("text"), dict)
        or set(value["shape"]["text"]) != {"textElements"}
        or not isinstance(
            value["shape"]["text"]["textElements"],
            list,
        )
    ):
        return False
    content: list[str] = []
    for element in value["shape"]["text"]["textElements"]:
        if not isinstance(element, dict) or not set(element).issubset(
            {"textRun"}
        ):
            return False
        if "textRun" not in element:
            continue
        text_run = element["textRun"]
        if (
            not isinstance(text_run, dict)
            or set(text_run) != {"content"}
            or not isinstance(text_run.get("content"), str)
        ):
            return False
        content.append(text_run["content"])
    actual = "".join(content)
    return actual in {expected_text, expected_text + "\n"}


def _verify_batch_update(
    response: SlidesHttpResponse,
    request: GoogleSlidesExportRequest,
    presentation_id: str,
    *,
    initial_slide_ids: tuple[str, ...],
) -> None:
    payload = _json_object(response, "Google Slides batch update")
    if (
        not set(payload).issubset(
            {"presentationId", "replies", "writeControl"}
        )
        or payload.get("presentationId") != presentation_id
        or not isinstance(payload.get("replies"), list)
    ):
        raise GoogleSlidesExportVerificationError(
            "Google Slides batch response shape is invalid"
        )
    expected_count = (
        len(initial_slide_ids)
        + request.specification.slide_count * 5
    )
    if len(payload["replies"]) != expected_count:
        raise GoogleSlidesExportVerificationError(
            "Google Slides batch response count is invalid"
        )
    offset = len(initial_slide_ids)
    if any(reply != {} for reply in payload["replies"][:offset]):
        raise GoogleSlidesExportVerificationError(
            "Google Slides delete response is invalid"
        )
    for index in range(1, request.specification.slide_count + 1):
        base = offset + (index - 1) * 5
        expected = (
            {"createSlide": {"objectId": _slide_id(index)}},
            {"createShape": {"objectId": _title_id(index)}},
            {},
            {"createShape": {"objectId": _body_id(index)}},
            {},
        )
        if tuple(payload["replies"][base : base + 5]) != expected:
            raise GoogleSlidesExportVerificationError(
                "Google Slides batch object evidence is invalid"
            )


def _element_properties(
    page_object_id: str,
    *,
    width: int,
    height: int,
    x: int,
    y: int,
) -> dict[str, object]:
    if _OBJECT_ID.fullmatch(page_object_id) is None:
        raise ValueError("Google Slides page object ID is invalid")
    return {
        "pageObjectId": page_object_id,
        "size": {
            "height": {"magnitude": height, "unit": "PT"},
            "width": {"magnitude": width, "unit": "PT"},
        },
        "transform": {
            "scaleX": 1,
            "scaleY": 1,
            "translateX": x,
            "translateY": y,
            "unit": "PT",
        },
    }


def _raise_for_status(
    response: SlidesHttpResponse,
    *,
    mutation: bool,
) -> None:
    if not isinstance(response, SlidesHttpResponse):
        raise TypeError("Google Slides transport response is invalid")
    if 200 <= response.status <= 299:
        if not response.content_type.casefold().split(";", 1)[0].strip() == (
            "application/json"
        ):
            raise ConnectorResponseError(
                "Google Slides response content type is invalid"
            )
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Google Slides access token was rejected"
        )
    if response.status == 429:
        if mutation:
            raise GoogleSlidesExportOutcomeUnknownError(
                "Google Slides mutation outcome is unknown"
            )
        raise ConnectorRateLimitError(response.retry_after_seconds or 0)
    if mutation and (
        response.status in {408, 425}
        or 500 <= response.status <= 599
    ):
        raise GoogleSlidesExportOutcomeUnknownError(
            "Google Slides mutation outcome is unknown"
        )
    raise ConnectorRequestError("Google Slides provider request failed")


def _json_object(
    response: SlidesHttpResponse,
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
            raise ValueError("Duplicate Google Slides JSON field")
        output[key] = value
    return output


def _reject_json_constant(_value: str):
    raise ValueError("Google Slides JSON constants are invalid")


def _verified_presentation_url(
    value: object,
    presentation_id: str,
) -> str:
    if not isinstance(value, str) or len(value) > 2_048:
        raise ValueError("Google presentation URL is invalid")
    parsed = urllib.parse.urlsplit(value)
    escaped_id = re.escape(presentation_id)
    path_pattern = re.compile(
        rf"^/(?:a/[A-Za-z0-9.-]+/)?presentation/d/{escaped_id}/edit$"
    )
    if (
        parsed.scheme != "https"
        or parsed.netloc != "docs.google.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query not in {"", "usp=drivesdk"}
        or path_pattern.fullmatch(parsed.path) is None
    ):
        raise ValueError("Google presentation URL is invalid")
    return value


def _request_body(payload: Mapping[str, object]) -> bytes:
    if not isinstance(payload, Mapping) or not payload:
        raise ConnectorRequestError(
            "Google Slides request payload is invalid"
        )
    encoded = _canonical_json(dict(payload))
    if len(encoded) > MAX_SLIDES_REQUEST_BYTES:
        raise ConnectorRequestError(
            "Google Slides request exceeds its limit"
        )
    return encoded


def _validate_fixed_endpoint(endpoint: str, method: str) -> None:
    try:
        parsed = urllib.parse.urlsplit(endpoint)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ConnectorRequestError(
            "Google Slides endpoint is invalid"
        ) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname
        not in {"www.googleapis.com", "slides.googleapis.com"}
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or method not in {"GET", "POST"}
    ):
        raise ConnectorRequestError(
            "Google Slides endpoint is not fixed by policy"
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
                r"/v1/presentations/[A-Za-z0-9_-]{1,256}",
                parsed.path,
            )
            is not None
        )
    else:
        valid = (
            re.fullmatch(
                r"/v1/presentations/[A-Za-z0-9_-]{1,256}:batchUpdate",
                parsed.path,
            )
            is not None
        )
    if not valid:
        raise ConnectorRequestError(
            "Google Slides endpoint is not fixed by policy"
        )


def _bounded_http_response(
    response,
    maximum: int,
) -> SlidesHttpResponse:
    body = response.read(maximum + 1)
    if len(body) > maximum:
        raise ConnectorResponseError(
            "Google Slides provider response exceeds its limit"
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
    return SlidesHttpResponse(
        status=int(response.status),
        content_type=content_type,
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


__all__ = [
    "GOOGLE_DRIVE_FILES_ENDPOINT",
    "GOOGLE_SLIDES_API_ROOT",
    "GOOGLE_SLIDES_EXPORT_OPERATION_ID",
    "GOOGLE_SLIDES_MIME_TYPE",
    "FixedGoogleSlidesHttpsTransport",
    "GoogleSlidesExportAdapter",
    "GoogleSlidesExportOutcomeUnknownError",
    "GoogleSlidesExportRequest",
    "GoogleSlidesExportResult",
    "GoogleSlidesExportVerificationError",
    "GoogleSlidesIdempotencyConflictError",
    "SlidesHttpResponse",
    "SlidesHttpTransport",
]
