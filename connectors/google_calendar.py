"""Narrow Google Calendar free/busy adapter.

Only calendars named by the caller are queried.  The typed output contains
calendar IDs and busy intervals; event titles, descriptions, attendees, and
other event bodies are neither requested nor represented.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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


GOOGLE_CALENDAR_FREEBUSY_ENDPOINT = (
    "https://www.googleapis.com/calendar/v3/freeBusy"
)
CALENDAR_AVAILABILITY_OPERATION_ID = "calendar.read_availability"
MAX_SELECTED_CALENDARS = 50
MAX_CALENDAR_ID_CHARS = 1_024
MAX_AVAILABILITY_WINDOW_DAYS = 31
MAX_BUSY_INTERVALS_PER_CALENDAR = 4_096
MAX_CALENDAR_RESPONSE_BYTES = 1024 * 1024
MAX_CALENDAR_REQUEST_BYTES = 128 * 1024
_UTC = timezone.utc
_ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {"kind", "timeMin", "timeMax", "groups", "calendars"}
)
_ALLOWED_CALENDAR_KEYS = frozenset({"busy", "errors"})
_ALLOWED_INTERVAL_KEYS = frozenset({"start", "end"})
_ALLOWED_ERROR_KEYS = frozenset({"domain", "reason"})
_RFC3339 = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"
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
        raise ValueError("Calendar value is not canonical JSON") from exc


def _calendar_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_CALENDAR_ID_CHARS
        or value.strip() != value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Selected calendar ID is invalid")
    return value


def _rfc3339(value: object, label: str) -> datetime:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 64
        or value.strip() != value
        or "\x00" in value
        or _RFC3339.fullmatch(value) is None
    ):
        raise ValueError(f"{label} must be bounded RFC 3339")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{label} must be RFC 3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a time-zone offset")
    return parsed.astimezone(_UTC)


def _format_utc(value: datetime) -> str:
    normalized = value.astimezone(_UTC)
    if normalized.microsecond:
        text = normalized.isoformat(timespec="microseconds")
    else:
        text = normalized.isoformat(timespec="seconds")
    return text.replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class CalendarAvailabilityRequest:
    """Exact selected calendars and bounded UTC availability window."""

    selected_calendar_ids: tuple[str, ...] = field(repr=False)
    time_min: str
    time_max: str
    connector: ConnectorId = field(
        default=ConnectorId.GOOGLE_CALENDAR,
        init=False,
    )
    capability: CapabilityId = field(
        default=CapabilityId.CALENDAR_EVENT_READ,
        init=False,
    )
    operation_id: str = field(
        default=CALENDAR_AVAILABILITY_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.selected_calendar_ids, tuple)
            or not self.selected_calendar_ids
            or len(self.selected_calendar_ids) > MAX_SELECTED_CALENDARS
        ):
            raise TypeError(
                "Calendar availability requires selected calendar IDs"
            )
        for calendar_id in self.selected_calendar_ids:
            _calendar_id(calendar_id)
        if len(self.selected_calendar_ids) != len(
            set(self.selected_calendar_ids)
        ):
            raise ValueError("Selected calendar IDs must be unique")
        start = _rfc3339(self.time_min, "Availability start")
        end = _rfc3339(self.time_max, "Availability end")
        if end <= start:
            raise ValueError("Availability end must follow its start")
        if end - start > timedelta(days=MAX_AVAILABILITY_WINDOW_DAYS):
            raise ValueError("Availability window exceeds its limit")
        canonical_start = _format_utc(start)
        canonical_end = _format_utc(end)
        object.__setattr__(self, "time_min", canonical_start)
        object.__setattr__(self, "time_max", canonical_end)
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(self.provider_payload())
            ).hexdigest(),
        )

    def provider_payload(self) -> dict[str, object]:
        return {
            "calendarExpansionMax": len(self.selected_calendar_ids),
            "items": [
                {"id": calendar_id}
                for calendar_id in self.selected_calendar_ids
            ],
            "timeMax": self.time_max,
            "timeMin": self.time_min,
            "timeZone": "UTC",
        }


@dataclass(frozen=True, slots=True)
class CalendarBusyInterval:
    start: str
    end: str

    def __post_init__(self) -> None:
        start = _rfc3339(self.start, "Busy interval start")
        end = _rfc3339(self.end, "Busy interval end")
        if end <= start:
            raise ValueError("Busy interval end must follow its start")
        object.__setattr__(self, "start", _format_utc(start))
        object.__setattr__(self, "end", _format_utc(end))


@dataclass(frozen=True, slots=True)
class CalendarAvailability:
    calendar_id: str = field(repr=False)
    busy: tuple[CalendarBusyInterval, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _calendar_id(self.calendar_id)
        if (
            not isinstance(self.busy, tuple)
            or len(self.busy) > MAX_BUSY_INTERVALS_PER_CALENDAR
            or any(
                not isinstance(interval, CalendarBusyInterval)
                for interval in self.busy
            )
        ):
            raise TypeError("Calendar busy intervals are invalid")
        if tuple(sorted(self.busy, key=lambda item: (item.start, item.end))) != (
            self.busy
        ):
            raise ValueError("Calendar busy intervals must be ordered")
        if len({(item.start, item.end) for item in self.busy}) != len(
            self.busy
        ):
            raise ValueError("Calendar busy intervals must be unique")


@dataclass(frozen=True, slots=True)
class CalendarAvailabilityResult:
    """Free/busy output only; no event-body fields exist in this model."""

    time_min: str
    time_max: str
    calendars: tuple[CalendarAvailability, ...] = field(repr=False)

    def __post_init__(self) -> None:
        start = _rfc3339(self.time_min, "Availability result start")
        end = _rfc3339(self.time_max, "Availability result end")
        if end <= start:
            raise ValueError("Availability result range is invalid")
        object.__setattr__(self, "time_min", _format_utc(start))
        object.__setattr__(self, "time_max", _format_utc(end))
        if (
            not isinstance(self.calendars, tuple)
            or not self.calendars
            or len(self.calendars) > MAX_SELECTED_CALENDARS
            or any(
                not isinstance(calendar, CalendarAvailability)
                for calendar in self.calendars
            )
        ):
            raise TypeError("Calendar availability result is invalid")
        if len({item.calendar_id for item in self.calendars}) != len(
            self.calendars
        ):
            raise ValueError("Calendar availability results must be unique")

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "calendars": [
                    {
                        "busy": [
                            {"end": interval.end, "start": interval.start}
                            for interval in calendar.busy
                        ],
                        "calendar_id": calendar.calendar_id,
                    }
                    for calendar in self.calendars
                ],
                "time_max": self.time_max,
                "time_min": self.time_min,
            }
        )


@dataclass(frozen=True, slots=True)
class CalendarHttpResponse:
    status: int
    content_type: str
    body: bytes = field(repr=False)
    retry_after_seconds: int | None = None
    provider_request_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not int or not 100 <= self.status <= 599:
            raise ValueError("Calendar HTTP status is invalid")
        if (
            not isinstance(self.content_type, str)
            or len(self.content_type) > 256
            or "\x00" in self.content_type
        ):
            raise ValueError("Calendar response content type is invalid")
        if (
            not isinstance(self.body, bytes)
            or len(self.body) > MAX_CALENDAR_RESPONSE_BYTES
        ):
            raise ValueError("Calendar response body is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) is not int
            or not 0 <= self.retry_after_seconds <= 24 * 60 * 60
        ):
            raise ValueError("Calendar retry delay is invalid")
        if self.provider_request_id is not None and (
            not isinstance(self.provider_request_id, str)
            or not self.provider_request_id
            or len(self.provider_request_id) > 256
            or "\x00" in self.provider_request_id
            or not self.provider_request_id.isprintable()
        ):
            raise ValueError("Calendar provider request ID is invalid")


class CalendarHttpTransport(Protocol):
    def post_json(
        self,
        *,
        endpoint: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> CalendarHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleCalendarHttpsTransport:
    """Fixed-host bounded HTTPS transport with no proxies or redirects."""

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
            raise ValueError("Calendar request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def post_json(
        self,
        *,
        endpoint: str,
        payload: Mapping[str, object],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> CalendarHttpResponse:
        if endpoint != GOOGLE_CALENDAR_FREEBUSY_ENDPOINT:
            raise ConnectorRequestError(
                "Calendar request endpoint is not fixed by policy"
            )
        if not isinstance(payload, Mapping) or not payload:
            raise ConnectorRequestError("Calendar request payload is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Calendar access token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1
            <= maximum_response_bytes
            <= MAX_CALENDAR_RESPONSE_BYTES
        ):
            raise ValueError("Calendar response limit is invalid")
        encoded = _canonical_json(dict(payload))
        if len(encoded) > MAX_CALENDAR_REQUEST_BYTES:
            raise ConnectorRequestError("Calendar request exceeds its limit")
        token = access_token.reveal()
        try:
            try:
                authorization = "Bearer " + token.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorAuthorizationError(
                    "Calendar access token encoding is invalid"
                ) from exc
            request = urllib.request.Request(
                endpoint,
                data=encoded,
                method="POST",
                headers={
                    "Accept": "application/json",
                    "Authorization": authorization,
                    "Cache-Control": "no-store",
                    "Content-Type": "application/json; charset=utf-8",
                    "User-Agent": "Clicky-Windows-Calendar/1",
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
                    "Calendar provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleCalendarAvailabilityAdapter:
    """Google Calendar adapter sealed to free/busy for one connected account."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_CALENDAR

    def __init__(
        self,
        account: ConnectedAccount,
        transport: CalendarHttpTransport | None = None,
        *,
        _revoker=None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Calendar adapter requires a connected account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Calendar adapter account is invalid")
        candidate = transport or FixedGoogleCalendarHttpsTransport()
        if not callable(getattr(candidate, "post_json", None)):
            raise TypeError("Calendar adapter transport is invalid")
        if _revoker is not None and not callable(_revoker):
            raise TypeError("Calendar revocation adapter is invalid")
        self._account = account
        self._transport = candidate
        self._revoker = _revoker

    async def execute(
        self,
        call: ConnectorCall,
        request: CalendarAvailabilityRequest,
        access_token: SecretValue,
    ) -> ConnectorExecution[CalendarAvailabilityResult]:
        if not isinstance(request, CalendarAvailabilityRequest):
            raise TypeError("Calendar adapter request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Calendar adapter token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_CALENDAR_RESPONSE_BYTES,
        )
        response = self._transport.post_json(
            endpoint=GOOGLE_CALENDAR_FREEBUSY_ENDPOINT,
            payload=MappingProxyType(request.provider_payload()),
            access_token=access_token,
            maximum_response_bytes=maximum,
        )
        if not isinstance(response, CalendarHttpResponse):
            raise TypeError("Calendar transport response is invalid")
        if len(response.body) > maximum:
            raise ConnectorResponseError(
                "Calendar provider response exceeds its limit"
            )
        _raise_for_status(response)
        output = _parse_availability(response, request)
        return ConnectorExecution(
            result=ConnectorCallResult(
                call_id=call.call_id,
                run_id=call.run_id,
                operation_id=call.operation_id,
                http_status=response.status,
                response_digest=hashlib.sha256(response.body).hexdigest(),
                response_bytes=len(response.body),
                provider_request_id=response.provider_request_id,
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
            raise TypeError("Calendar revocation evidence is invalid")
        return result


def _bounded_http_response(
    response,
    maximum_response_bytes: int,
) -> CalendarHttpResponse:
    body = response.read(maximum_response_bytes + 1)
    if len(body) > maximum_response_bytes:
        raise ConnectorResponseError(
            "Calendar provider response exceeds its limit"
        )
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
    retry_after = headers.get("Retry-After")
    retry_seconds = None
    if retry_after is not None:
        try:
            candidate = int(retry_after, 10)
        except ValueError:
            candidate = -1
        if 0 <= candidate <= 24 * 60 * 60:
            retry_seconds = candidate
    return CalendarHttpResponse(
        status=response.status,
        content_type=headers.get("Content-Type", ""),
        body=body,
        retry_after_seconds=retry_seconds,
        provider_request_id=request_id,
    )


def _raise_for_status(response: CalendarHttpResponse) -> None:
    if 200 <= response.status <= 299:
        return
    if response.status == 401:
        raise ConnectorTokenExpiredError(
            "Calendar access token expired or is invalid"
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
            "Calendar provider denied the requested availability scope"
        )
    if response.status == 400:
        raise ConnectorRequestError(
            "Calendar provider rejected the bounded availability request"
        )
    if response.status == 404:
        raise ConnectorResponseError(
            "A selected calendar is unavailable"
        )
    raise ConnectorResponseError("Calendar provider returned an error")


def _provider_error_reasons(body: bytes) -> frozenset[str]:
    if not body or len(body) > MAX_CALENDAR_RESPONSE_BYTES:
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


def _parse_availability(
    response: CalendarHttpResponse,
    request: CalendarAvailabilityRequest,
) -> CalendarAvailabilityResult:
    media_type = response.content_type.partition(";")[0].strip().casefold()
    if media_type != "application/json":
        raise ConnectorResponseError(
            "Calendar provider response is not JSON"
        )
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorResponseError(
            "Calendar provider response is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or not set(payload).issubset(_ALLOWED_TOP_LEVEL_KEYS)
        or payload.get("kind") not in (None, "calendar#freeBusy")
        or payload.get("groups", {}) != {}
        or not isinstance(payload.get("calendars"), dict)
    ):
        raise ConnectorResponseError(
            "Calendar provider response shape is invalid"
        )
    try:
        response_start = _rfc3339(
            payload["timeMin"],
            "Provider availability start",
        )
        response_end = _rfc3339(
            payload["timeMax"],
            "Provider availability end",
        )
        request_start = _rfc3339(request.time_min, "Availability start")
        request_end = _rfc3339(request.time_max, "Availability end")
    except (KeyError, ValueError) as exc:
        raise ConnectorResponseError(
            "Calendar provider response range is invalid"
        ) from exc
    if response_start != request_start or response_end != request_end:
        raise ConnectorResponseError(
            "Calendar provider response range does not match the request"
        )
    raw_calendars = payload["calendars"]
    if set(raw_calendars) != set(request.selected_calendar_ids):
        raise ConnectorResponseError(
            "Calendar provider returned an unselected or missing calendar"
        )

    calendars: list[CalendarAvailability] = []
    for calendar_id in request.selected_calendar_ids:
        entry = raw_calendars[calendar_id]
        if (
            not isinstance(entry, dict)
            or not set(entry).issubset(_ALLOWED_CALENDAR_KEYS)
        ):
            raise ConnectorResponseError(
                "Calendar provider entry is invalid"
            )
        errors = entry.get("errors", [])
        if errors:
            _validate_calendar_errors(errors)
            raise ConnectorResponseError(
                "A selected calendar could not return availability"
            )
        raw_busy = entry.get("busy")
        if (
            not isinstance(raw_busy, list)
            or len(raw_busy) > MAX_BUSY_INTERVALS_PER_CALENDAR
        ):
            raise ConnectorResponseError(
                "Calendar busy interval collection is invalid"
            )
        intervals: list[CalendarBusyInterval] = []
        for raw_interval in raw_busy:
            if (
                not isinstance(raw_interval, dict)
                or set(raw_interval) != _ALLOWED_INTERVAL_KEYS
            ):
                raise ConnectorResponseError(
                    "Calendar busy interval shape is invalid"
                )
            try:
                interval = CalendarBusyInterval(
                    start=raw_interval["start"],
                    end=raw_interval["end"],
                )
            except (TypeError, ValueError) as exc:
                raise ConnectorResponseError(
                    "Calendar busy interval is invalid"
                ) from exc
            interval_start = _rfc3339(interval.start, "Busy interval start")
            interval_end = _rfc3339(interval.end, "Busy interval end")
            if interval_start < request_start or interval_end > request_end:
                raise ConnectorResponseError(
                    "Calendar busy interval exceeds the requested range"
                )
            intervals.append(interval)
        intervals.sort(key=lambda item: (item.start, item.end))
        if len({(item.start, item.end) for item in intervals}) != len(
            intervals
        ):
            raise ConnectorResponseError(
                "Calendar provider returned duplicate busy intervals"
            )
        calendars.append(
            CalendarAvailability(
                calendar_id=calendar_id,
                busy=tuple(intervals),
            )
        )
    return CalendarAvailabilityResult(
        time_min=request.time_min,
        time_max=request.time_max,
        calendars=tuple(calendars),
    )


def _validate_calendar_errors(errors: object) -> None:
    if (
        not isinstance(errors, list)
        or not errors
        or len(errors) > 32
    ):
        raise ConnectorResponseError("Calendar provider errors are invalid")
    for item in errors:
        if (
            not isinstance(item, dict)
            or not set(item).issubset(_ALLOWED_ERROR_KEYS)
            or not isinstance(item.get("reason"), str)
            or not 0 < len(item["reason"]) <= 128
            or not item["reason"].isprintable()
        ):
            raise ConnectorResponseError(
                "Calendar provider error shape is invalid"
            )


__all__ = [
    "CALENDAR_AVAILABILITY_OPERATION_ID",
    "GOOGLE_CALENDAR_FREEBUSY_ENDPOINT",
    "CalendarAvailability",
    "CalendarAvailabilityRequest",
    "CalendarAvailabilityResult",
    "CalendarBusyInterval",
    "CalendarHttpResponse",
    "FixedGoogleCalendarHttpsTransport",
    "GoogleCalendarAvailabilityAdapter",
    "MAX_CALENDAR_RESPONSE_BYTES",
    "MAX_SELECTED_CALENDARS",
]
