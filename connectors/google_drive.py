"""Least-privilege Google Drive read for one explicitly selected file.

There is no search, list, folder traversal, shortcut resolution, or account
fallback in this module.  One opaque file ID is bound into the request digest.
The adapter first validates a fixed metadata projection and then downloads
only a small allowlisted UTF-8 text type.  Google-native files require the
separate reviewed export operation.
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
from datetime import datetime
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
    ConnectorRevocationRequest,
    ConnectorRevocationResult,
    ConnectorTokenExpiredError,
    SecretValue,
    validate_connector_authority,
)


GOOGLE_DRIVE_API_ROOT = "https://www.googleapis.com/drive/v3/files"
DRIVE_SELECTED_FILE_OPERATION_ID = "drive.read_selected_file"
MAX_DRIVE_FILE_ID_CHARS = 256
MAX_DRIVE_FILE_NAME_CHARS = 1_024
MAX_DRIVE_METADATA_RESPONSE_BYTES = 64 * 1024
MAX_DRIVE_FILE_CONTENT_BYTES = 256 * 1024
MAX_DRIVE_PROVIDER_RESPONSE_BYTES = (
    MAX_DRIVE_METADATA_RESPONSE_BYTES + MAX_DRIVE_FILE_CONTENT_BYTES
)
MAX_DRIVE_TASK_OUTPUT_BYTES = 384 * 1024
_FILE_ID = re.compile(r"^[A-Za-z0-9_-]{10,256}$")
_MIME_TYPE = re.compile(
    r"^[a-z0-9][a-z0-9!#$&^_.+-]*/"
    r"[a-z0-9][a-z0-9!#$&^_.+-]*$"
)
_MD5 = re.compile(r"^[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_METADATA_KEYS = frozenset(
    {
        "id",
        "md5Checksum",
        "mimeType",
        "modifiedTime",
        "name",
        "sha256Checksum",
        "size",
        "trashed",
    }
)
_REQUIRED_METADATA_KEYS = frozenset(
    {"id", "mimeType", "modifiedTime", "name", "trashed"}
)
_ALLOWED_TEXT_MEDIA_TYPES = frozenset(
    {
        "application/json",
        "text/csv",
        "text/markdown",
        "text/plain",
    }
)
_EXPORTABLE_GOOGLE_MEDIA_TYPES = frozenset(
    {
        "application/vnd.google-apps.document",
        "application/vnd.google-apps.drawing",
        "application/vnd.google-apps.presentation",
        "application/vnd.google-apps.spreadsheet",
    }
)
_METADATA_FIELDS = (
    "id,md5Checksum,mimeType,modifiedTime,name,sha256Checksum,size,trashed"
)


class DriveNativeExportRequiredError(ConnectorResponseError):
    """A Google-native file must use a separate reviewed export route."""


class DriveUnsupportedMediaTypeError(ConnectorResponseError):
    """The selected file cannot be safely represented as task text."""


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
        raise ValueError("Drive value is not canonical JSON") from exc


def _selected_file_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or value.strip() != value
        or _FILE_ID.fullmatch(value) is None
    ):
        raise ValueError("Selected Drive file ID is invalid")
    return value


def _media_type(value: object) -> str:
    if (
        not isinstance(value, str)
        or value != value.casefold()
        or len(value) > 127
        or _MIME_TYPE.fullmatch(value) is None
    ):
        raise ConnectorResponseError(
            "Selected Drive file media type is invalid"
        )
    return value


@dataclass(frozen=True, slots=True)
class DriveSelectedFileRequest:
    """One exact file ID; never a query, folder, or account-wide selector."""

    selected_file_id: str = field(repr=False)
    maximum_content_bytes: int = MAX_DRIVE_FILE_CONTENT_BYTES
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_DRIVE,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.DRIVE_SELECTED_FILE_READ,
        init=False,
    )
    operation_id: str = field(
        default=DRIVE_SELECTED_FILE_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _selected_file_id(self.selected_file_id)
        if (
            type(self.maximum_content_bytes) is not int
            or not 1
            <= self.maximum_content_bytes
            <= MAX_DRIVE_FILE_CONTENT_BYTES
        ):
            raise ValueError(
                "Selected Drive file content limit is invalid"
            )
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "allowed_media_types": sorted(
                            _ALLOWED_TEXT_MEDIA_TYPES
                        ),
                        "maximum_content_bytes": (
                            self.maximum_content_bytes
                        ),
                        "selected_file_id": self.selected_file_id,
                    }
                )
            ).hexdigest(),
        )

    @property
    def metadata_endpoint(self) -> str:
        quoted = urllib.parse.quote(self.selected_file_id, safe="")
        query = urllib.parse.urlencode(
            (
                ("fields", _METADATA_FIELDS),
                ("supportsAllDrives", "true"),
            )
        )
        return f"{GOOGLE_DRIVE_API_ROOT}/{quoted}?{query}"

    @property
    def content_endpoint(self) -> str:
        quoted = urllib.parse.quote(self.selected_file_id, safe="")
        return (
            f"{GOOGLE_DRIVE_API_ROOT}/{quoted}"
            "?alt=media&supportsAllDrives=true"
        )


@dataclass(frozen=True, slots=True)
class DriveFileMetadata:
    file_id: str
    name: str = field(repr=False)
    mime_type: str
    size_bytes: int
    modified_time: str
    md5_checksum: str | None = None
    sha256_checksum: str | None = None

    def __post_init__(self) -> None:
        _selected_file_id(self.file_id)
        if (
            not isinstance(self.name, str)
            or not self.name
            or len(self.name) > MAX_DRIVE_FILE_NAME_CHARS
            or self.name.strip() != self.name
            or "\x00" in self.name
            or not self.name.isprintable()
        ):
            raise ConnectorResponseError(
                "Selected Drive file name is invalid"
            )
        _media_type(self.mime_type)
        if (
            type(self.size_bytes) is not int
            or not 0 <= self.size_bytes <= MAX_DRIVE_FILE_CONTENT_BYTES
        ):
            raise ConnectorResponseError(
                "Selected Drive file size exceeds its limit"
            )
        if (
            not isinstance(self.modified_time, str)
            or not self.modified_time
            or len(self.modified_time) > 64
            or self.modified_time.strip() != self.modified_time
        ):
            raise ConnectorResponseError(
                "Selected Drive file modification time is invalid"
            )
        candidate = (
            self.modified_time[:-1] + "+00:00"
            if self.modified_time.endswith("Z")
            else self.modified_time
        )
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ConnectorResponseError(
                "Selected Drive file modification time is invalid"
            ) from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ConnectorResponseError(
                "Selected Drive file modification time lacks a zone"
            )
        if self.md5_checksum is not None and (
            not isinstance(self.md5_checksum, str)
            or _MD5.fullmatch(self.md5_checksum) is None
        ):
            raise ConnectorResponseError(
                "Selected Drive file MD5 checksum is invalid"
            )
        if self.sha256_checksum is not None and (
            not isinstance(self.sha256_checksum, str)
            or _SHA256.fullmatch(self.sha256_checksum) is None
        ):
            raise ConnectorResponseError(
                "Selected Drive file SHA-256 checksum is invalid"
            )


@dataclass(frozen=True, slots=True)
class DriveSelectedFileResult:
    """Bounded, explicitly untrusted UTF-8 content plus selected metadata."""

    metadata: DriveFileMetadata
    content_text: str = field(repr=False)
    content_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, DriveFileMetadata):
            raise TypeError("Selected Drive metadata is invalid")
        if (
            not isinstance(self.content_text, str)
            or "\x00" in self.content_text
            or len(self.content_text.encode("utf-8"))
            != self.metadata.size_bytes
        ):
            raise ConnectorResponseError(
                "Selected Drive text content is invalid"
            )
        if (
            not isinstance(self.content_sha256, str)
            or _SHA256.fullmatch(self.content_sha256) is None
            or self.content_sha256
            != hashlib.sha256(
                self.content_text.encode("utf-8")
            ).hexdigest()
        ):
            raise ConnectorResponseError(
                "Selected Drive content digest is invalid"
            )

    def to_json_bytes(self) -> bytes:
        output = _canonical_json(
            {
                "content": self.content_text,
                "content_bytes": self.metadata.size_bytes,
                "content_sha256": self.content_sha256,
                "content_untrusted": True,
                "file_id": self.metadata.file_id,
                "md5_checksum": self.metadata.md5_checksum,
                "mime_type": self.metadata.mime_type,
                "modified_time": self.metadata.modified_time,
                "name": self.metadata.name,
                "sha256_checksum": self.metadata.sha256_checksum,
            }
        )
        if len(output) > MAX_DRIVE_TASK_OUTPUT_BYTES:
            raise ConnectorResponseError(
                "Selected Drive task output exceeds its limit"
            )
        return output


@dataclass(frozen=True, slots=True)
class DriveHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Drive HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Drive response content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_DRIVE_PROVIDER_RESPONSE_BYTES
        ):
            raise ValueError("Drive response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Drive retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("Drive provider request ID is invalid")


class DriveHttpTransport(Protocol):
    def get(
        self,
        *,
        endpoint: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DriveHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleDriveHttpsTransport:
    """Fixed Drive host, GET-only, bounded, proxy-free, and no redirects."""

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
            raise ValueError("Drive request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get(
        self,
        *,
        endpoint: str,
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> DriveHttpResponse:
        _validate_fixed_drive_endpoint(endpoint)
        if not isinstance(access_token, SecretValue):
            raise TypeError("Drive access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1
            <= maximum_response_bytes
            <= MAX_DRIVE_PROVIDER_RESPONSE_BYTES
        ):
            raise ValueError("Drive response limit is invalid")
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Drive access token encoding is invalid"
                ) from exc
            request = urllib.request.Request(
                endpoint,
                method="GET",
                headers={
                    "Accept": "*/*",
                    "Authorization": authorization,
                    "Cache-Control": "no-store",
                    "User-Agent": "Clicky-Windows-Drive/1",
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
                    "Drive provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleDriveSelectedFileAdapter:
    """Adapter sealed to one selected small UTF-8 Drive file."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_DRIVE

    def __init__(
        self,
        account: ConnectedAccount,
        transport: DriveHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Drive adapter requires a connected account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Drive adapter account is invalid")
        candidate = transport or FixedGoogleDriveHttpsTransport()
        if not callable(getattr(candidate, "get", None)):
            raise TypeError("Drive adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Drive revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: DriveSelectedFileRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[DriveSelectedFileResult]:
        if not isinstance(request, DriveSelectedFileRequest):
            raise TypeError("Drive adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Drive adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_DRIVE_PROVIDER_RESPONSE_BYTES,
        )
        metadata_response = self._transport.get(
            endpoint=request.metadata_endpoint,
            access_token=access_token,
            maximum_response_bytes=min(
                maximum,
                MAX_DRIVE_METADATA_RESPONSE_BYTES,
            ),
        )
        if not isinstance(metadata_response, DriveHttpResponse):
            raise TypeError("Drive metadata response is invalid")
        _raise_for_status(metadata_response)
        metadata = _parse_metadata(metadata_response, request)
        if metadata.mime_type in _EXPORTABLE_GOOGLE_MEDIA_TYPES:
            raise DriveNativeExportRequiredError(
                "Selected Google-native file requires reviewed export"
            )
        if metadata.mime_type.startswith("application/vnd.google-apps."):
            raise DriveUnsupportedMediaTypeError(
                "Selected Drive item is not an exportable file"
            )
        if metadata.mime_type not in _ALLOWED_TEXT_MEDIA_TYPES:
            raise DriveUnsupportedMediaTypeError(
                "Selected Drive file type is not approved for task text"
            )
        if metadata.size_bytes > request.maximum_content_bytes:
            raise ConnectorResponseError(
                "Selected Drive file exceeds the reviewed content limit"
            )
        remaining = maximum - len(metadata_response.body)
        if remaining <= 0:
            raise ConnectorResponseError(
                "Drive provider response budget is exhausted"
            )
        content_response = self._transport.get(
            endpoint=request.content_endpoint,
            access_token=access_token,
            maximum_response_bytes=min(
                remaining,
                request.maximum_content_bytes,
            ),
        )
        if not isinstance(content_response, DriveHttpResponse):
            raise TypeError("Drive content response is invalid")
        _raise_for_status(content_response)
        content_type = (
            content_response.content_type.partition(";")[0]
            .strip()
            .casefold()
        )
        if content_type != metadata.mime_type:
            raise ConnectorResponseError(
                "Drive content type does not match selected metadata"
            )
        if len(content_response.body) != metadata.size_bytes:
            raise ConnectorResponseError(
                "Drive content size does not match selected metadata"
            )
        content_sha256 = hashlib.sha256(content_response.body).hexdigest()
        if (
            metadata.sha256_checksum is not None
            and metadata.sha256_checksum != content_sha256
        ):
            raise ConnectorResponseError(
                "Drive content digest does not match selected metadata"
            )
        if (
            metadata.md5_checksum is not None
            and metadata.md5_checksum
            != hashlib.md5(
                content_response.body,
                usedforsecurity=False,
            ).hexdigest()
        ):
            raise ConnectorResponseError(
                "Drive content checksum does not match selected metadata"
            )
        try:
            content_text = content_response.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConnectorResponseError(
                "Selected Drive file content is not UTF-8"
            ) from exc
        if "\x00" in content_text:
            raise ConnectorResponseError(
                "Selected Drive file content contains a null byte"
            )
        if metadata.mime_type == "application/json":
            try:
                json.loads(content_text)
            except json.JSONDecodeError as exc:
                raise ConnectorResponseError(
                    "Selected Drive JSON content is invalid"
                ) from exc
        output = DriveSelectedFileResult(
            metadata=metadata,
            content_text=content_text,
            content_sha256=content_sha256,
        )
        response_bytes = (
            len(metadata_response.body) + len(content_response.body)
        )
        if response_bytes > maximum:
            raise ConnectorResponseError(
                "Drive provider response exceeds its limit"
            )
        response_digest = hashlib.sha256(
            len(metadata_response.body).to_bytes(8, "big")
            + metadata_response.body
            + len(content_response.body).to_bytes(8, "big")
            + content_response.body
        ).hexdigest()
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=call.operation_id,
                http_status=content_response.status,
                response_digest=response_digest,
                response_bytes=response_bytes,
                provider_request_id=_combined_request_id(
                    metadata_response.provider_request_id,
                    content_response.provider_request_id,
                ),
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
        result = revoker(
            self.provider,
            request,
            refresh_token,
        )
        if not isinstance(result, ConnectorRevocationResult):
            raise TypeError("Drive revocation evidence is invalid")
        return result


def _validate_fixed_drive_endpoint(endpoint: object) -> None:
    if not isinstance(endpoint, str) or len(endpoint) > 2_048:
        raise ConnectorRequestError(
            "Drive request endpoint is not fixed by policy"
        )
    parsed = urllib.parse.urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "www.googleapis.com"
        or parsed.fragment
        or not parsed.path.startswith("/drive/v3/files/")
    ):
        raise ConnectorRequestError(
            "Drive request endpoint is not fixed by policy"
        )
    raw_id = parsed.path.removeprefix("/drive/v3/files/")
    try:
        _selected_file_id(raw_id)
    except ValueError as exc:
        raise ConnectorRequestError(
            "Drive request endpoint is not fixed by policy"
        ) from exc
    metadata_query = urllib.parse.urlencode(
        (
            ("fields", _METADATA_FIELDS),
            ("supportsAllDrives", "true"),
        )
    )
    if parsed.query not in {
        metadata_query,
        "alt=media&supportsAllDrives=true",
    }:
        raise ConnectorRequestError(
            "Drive request query is not fixed by policy"
        )


def _bounded_http_response(
    response,
    maximum_response_bytes: int,
) -> DriveHttpResponse:
    content_length = response.headers.get("Content-Length")
    if content_length is not None and (
        not content_length.isascii()
        or not content_length.isdigit()
        or int(content_length) > maximum_response_bytes
    ):
        raise ConnectorResponseError(
            "Drive provider response exceeds its limit"
        )
    body = response.read(maximum_response_bytes + 1)
    if len(body) > maximum_response_bytes:
        raise ConnectorResponseError(
            "Drive provider response exceeds its limit"
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
    return DriveHttpResponse(
        status=response.status,
        content_type=response.headers.get("Content-Type", ""),
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


def _raise_for_status(response: DriveHttpResponse) -> None:
    if 200 <= response.status <= 299:
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Drive access token expired or is invalid"
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
            "Drive provider denied the selected-file scope"
        )
    if response.status == 404:
        raise ConnectorResponseError(
            "Selected Drive file is unavailable"
        )
    if response.status == 400:
        raise ConnectorRequestError(
            "Drive provider rejected the selected-file request"
        )
    raise ConnectorResponseError("Drive provider returned an error")


def _provider_error_reasons(body: bytes) -> frozenset[str]:
    if not body or len(body) > MAX_DRIVE_METADATA_RESPONSE_BYTES:
        return frozenset()
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return frozenset()
    error = payload.get("error") if isinstance(payload, dict) else None
    errors = error.get("errors", []) if isinstance(error, dict) else ()
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


def _parse_metadata(
    response: DriveHttpResponse,
    request: DriveSelectedFileRequest,
) -> DriveFileMetadata:
    media_type = response.content_type.partition(";")[0].strip().casefold()
    if media_type != "application/json":
        raise ConnectorResponseError(
            "Drive metadata response is not JSON"
        )
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorResponseError(
            "Drive metadata response is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or not _REQUIRED_METADATA_KEYS.issubset(payload)
        or not set(payload).issubset(_ALLOWED_METADATA_KEYS)
        or payload.get("id") != request.selected_file_id
        or payload.get("trashed") is not False
    ):
        raise ConnectorResponseError(
            "Drive metadata does not match the selected file"
        )
    mime_type = _media_type(payload.get("mimeType"))
    raw_size = payload.get("size")
    if mime_type.startswith("application/vnd.google-apps."):
        size_bytes = 0
    elif (
        not isinstance(raw_size, str)
        or not raw_size.isascii()
        or not raw_size.isdigit()
        or len(raw_size) > 20
    ):
        raise ConnectorResponseError(
            "Drive metadata does not match the selected file"
        )
    else:
        size_bytes = int(raw_size, 10)
    return DriveFileMetadata(
        file_id=payload["id"],
        name=payload["name"],
        mime_type=mime_type,
        size_bytes=size_bytes,
        modified_time=payload["modifiedTime"],
        md5_checksum=payload.get("md5Checksum"),
        sha256_checksum=payload.get("sha256Checksum"),
    )


def _combined_request_id(
    metadata_id: str | None,
    content_id: str | None,
) -> str | None:
    values = tuple(value for value in (metadata_id, content_id) if value)
    if not values:
        return None
    combined = "/".join(values)
    if len(combined) > 256:
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return combined


__all__ = [
    "DRIVE_SELECTED_FILE_OPERATION_ID",
    "DriveFileMetadata",
    "DriveHttpResponse",
    "DriveNativeExportRequiredError",
    "DriveSelectedFileRequest",
    "DriveSelectedFileResult",
    "DriveUnsupportedMediaTypeError",
    "FixedGoogleDriveHttpsTransport",
    "GOOGLE_DRIVE_API_ROOT",
    "GoogleDriveSelectedFileAdapter",
    "MAX_DRIVE_FILE_CONTENT_BYTES",
    "MAX_DRIVE_PROVIDER_RESPONSE_BYTES",
]
