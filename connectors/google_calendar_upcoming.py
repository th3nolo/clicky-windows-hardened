"""Minimal selected-calendar event metadata for private countdown widgets."""

from __future__ import annotations

import hashlib
import json
import math
import ssl
import urllib.error
import urllib.parse
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
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorTokenExpiredError,
    SecretValue,
    validate_connector_authority,
)
from connectors.google_calendar import (
    CalendarHttpResponse,
    _bounded_http_response,
    _format_utc,
    _provider_error_reasons,
    _rfc3339,
)


CALENDAR_UPCOMING_OPERATION_ID = "calendar.read_upcoming_metadata"
GOOGLE_CALENDAR_EVENTS_ENDPOINT_PREFIX = (
    "https://www.googleapis.com/calendar/v3/calendars/"
)
MAX_UPCOMING_CALENDARS = 10
MAX_UPCOMING_EVENTS_PER_CALENDAR = 10
MAX_UPCOMING_WINDOW_HOURS = 24
MAX_UPCOMING_RESPONSE_BYTES = 256 * 1024
MAX_TOTAL_UPCOMING_RESPONSE_BYTES = 1024 * 1024
_FIELDS = "items(id,status,start,end)"
_ALLOWED_TOP_LEVEL = frozenset({"items"})
_ALLOWED_EVENT_FIELDS = frozenset({"id", "status", "start", "end"})
_ALLOWED_TIME_FIELDS = frozenset({"dateTime", "date", "timeZone"})
_UTC = timezone.utc


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
        raise ValueError("Upcoming calendar value is not canonical JSON") from exc


def _calendar_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_024
        or value.strip() != value
        or "\x00" in value
        or not value.isprintable()
    ):
        raise ValueError("Selected calendar ID is invalid")
    return value


@dataclass(frozen=True, slots=True)
class CalendarUpcomingRequest:
    """Selected calendars and a short UTC window, with no title request."""

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
        default=CALENDAR_UPCOMING_OPERATION_ID,
        init=False,
    )
    idempotency_key: None = field(default=None, init=False)
    request_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.selected_calendar_ids, tuple)
            or not self.selected_calendar_ids
            or len(self.selected_calendar_ids) > MAX_UPCOMING_CALENDARS
        ):
            raise TypeError("Upcoming events require selected calendar IDs")
        for calendar_id in self.selected_calendar_ids:
            _calendar_id(calendar_id)
        if len(self.selected_calendar_ids) != len(
            set(self.selected_calendar_ids)
        ):
            raise ValueError("Selected calendar IDs must be unique")
        start = _rfc3339(self.time_min, "Upcoming window start")
        end = _rfc3339(self.time_max, "Upcoming window end")
        if end <= start:
            raise ValueError("Upcoming window end must follow its start")
        if end - start > timedelta(hours=MAX_UPCOMING_WINDOW_HOURS):
            raise ValueError("Upcoming event window exceeds its limit")
        object.__setattr__(self, "time_min", _format_utc(start))
        object.__setattr__(self, "time_max", _format_utc(end))
        object.__setattr__(
            self,
            "request_digest",
            hashlib.sha256(
                _canonical_json(
                    {
                        "calendar_ids": list(self.selected_calendar_ids),
                        "time_max": self.time_max,
                        "time_min": self.time_min,
                    }
                )
            ).hexdigest(),
        )

    def provider_query(self) -> Mapping[str, str]:
        return MappingProxyType(
            {
                "eventTypes": "default",
                "fields": _FIELDS,
                "maxResults": str(MAX_UPCOMING_EVENTS_PER_CALENDAR),
                "orderBy": "startTime",
                "showDeleted": "false",
                "singleEvents": "true",
                "timeMax": self.time_max,
                "timeMin": self.time_min,
                "timeZone": "UTC",
            }
        )


@dataclass(frozen=True, slots=True)
class UpcomingCalendarEvent:
    """Opaque event identity and timing only; no body fields exist."""

    opaque_event_id: str
    starts_at: str
    ends_at: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.opaque_event_id, str)
            or len(self.opaque_event_id) != 64
            or any(char not in "0123456789abcdef" for char in self.opaque_event_id)
        ):
            raise ValueError("Upcoming event identity is invalid")
        start = _rfc3339(self.starts_at, "Upcoming event start")
        end = _rfc3339(self.ends_at, "Upcoming event end")
        if end <= start:
            raise ValueError("Upcoming event end must follow its start")
        object.__setattr__(self, "starts_at", _format_utc(start))
        object.__setattr__(self, "ends_at", _format_utc(end))


@dataclass(frozen=True, slots=True)
class CalendarUpcomingEvidence:
    response_digest: str
    response_bytes: int
    http_status: int
    provider_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class CalendarUpcomingResult:
    fetched_at: str
    events: tuple[UpcomingCalendarEvent, ...] = field(repr=False)
    evidence: tuple[CalendarUpcomingEvidence, ...] = field(repr=False)

    def __post_init__(self) -> None:
        fetched = _rfc3339(self.fetched_at, "Upcoming result fetch time")
        object.__setattr__(self, "fetched_at", _format_utc(fetched))
        if (
            not isinstance(self.events, tuple)
            or len(self.events)
            > MAX_UPCOMING_CALENDARS * MAX_UPCOMING_EVENTS_PER_CALENDAR
            or any(not isinstance(item, UpcomingCalendarEvent) for item in self.events)
        ):
            raise TypeError("Upcoming event collection is invalid")
        if len({item.opaque_event_id for item in self.events}) != len(self.events):
            raise ValueError("Upcoming event identities must be unique")
        if tuple(
            sorted(self.events, key=lambda item: (item.starts_at, item.opaque_event_id))
        ) != self.events:
            raise ValueError("Upcoming events must be ordered")
        if (
            not isinstance(self.evidence, tuple)
            or not self.evidence
            or len(self.evidence) > MAX_UPCOMING_CALENDARS
            or any(
                not isinstance(item, CalendarUpcomingEvidence)
                for item in self.evidence
            )
        ):
            raise TypeError("Upcoming event evidence is invalid")


class CalendarEventsHttpTransport(Protocol):
    def get_json(
        self,
        *,
        calendar_id: str,
        query: Mapping[str, str],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> CalendarHttpResponse: ...


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


class FixedGoogleCalendarEventsHttpsTransport:
    """Fixed-host, selected-calendar GET with no proxy or redirect path."""

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
            raise ValueError("Calendar event request timeout is invalid")
        self._timeout = float(timeout_seconds)
        self._opener = _opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

    def get_json(
        self,
        *,
        calendar_id: str,
        query: Mapping[str, str],
        access_token: SecretValue,
        maximum_response_bytes: int,
    ) -> CalendarHttpResponse:
        selected = _calendar_id(calendar_id)
        if dict(query) != dict(CalendarUpcomingRequest(
            selected_calendar_ids=(selected,),
            time_min=query.get("timeMin", ""),
            time_max=query.get("timeMax", ""),
        ).provider_query()):
            raise ConnectorRequestError("Calendar event query is not fixed by policy")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Calendar event token must use SecretValue")
        if (
            type(maximum_response_bytes) is not int
            or not 1 <= maximum_response_bytes <= MAX_UPCOMING_RESPONSE_BYTES
        ):
            raise ValueError("Calendar event response limit is invalid")
        encoded_id = urllib.parse.quote(selected, safe="")
        encoded_query = urllib.parse.urlencode(sorted(query.items()))
        endpoint = (
            GOOGLE_CALENDAR_EVENTS_ENDPOINT_PREFIX
            + encoded_id
            + "/events?"
            + encoded_query
        )
        parsed = urllib.parse.urlsplit(endpoint)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "www.googleapis.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or not parsed.path.startswith("/calendar/v3/calendars/")
            or not parsed.path.endswith("/events")
        ):
            raise ConnectorRequestError("Calendar event endpoint is not fixed")
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
                method="GET",
                headers={
                    "Accept": "application/json",
                    "Authorization": authorization,
                    "Cache-Control": "no-store",
                    "User-Agent": "Clicky-Windows-Calendar-Countdown/1",
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
                    "Calendar event provider request failed"
                ) from exc
        finally:
            token = b""
            if "authorization" in locals():
                authorization = ""


class GoogleCalendarUpcomingAdapter:
    """Read only start/end metadata from selected calendars."""

    provider = ConnectorProviderId.GOOGLE
    connector = ConnectorId.GOOGLE_CALENDAR

    def __init__(
        self,
        account: ConnectedAccount,
        transport: CalendarEventsHttpTransport | None = None,
    ) -> None:
        if not isinstance(account, ConnectedAccount):
            raise TypeError("Upcoming Calendar adapter requires an account")
        if (
            account.provider is not self.provider
            or account.connector is not self.connector
        ):
            raise ValueError("Upcoming Calendar adapter account is invalid")
        candidate = transport or FixedGoogleCalendarEventsHttpsTransport()
        if not callable(getattr(candidate, "get_json", None)):
            raise TypeError("Upcoming Calendar transport is invalid")
        self._account = account
        self._transport = candidate

    async def execute(
        self,
        call: ConnectorCall,
        request: CalendarUpcomingRequest,
        access_token: SecretValue,
        *,
        fetched_at: datetime | None = None,
    ) -> CalendarUpcomingResult:
        if not isinstance(request, CalendarUpcomingRequest):
            raise TypeError("Upcoming Calendar request is invalid")
        if not isinstance(access_token, SecretValue):
            raise TypeError("Upcoming Calendar token is invalid")
        validate_connector_authority(call, self._account, request)
        maximum = min(
            call.maximum_response_bytes,
            MAX_UPCOMING_RESPONSE_BYTES,
        )
        request_start = _rfc3339(request.time_min, "Upcoming window start")
        request_end = _rfc3339(request.time_max, "Upcoming window end")
        events: list[UpcomingCalendarEvent] = []
        evidence: list[CalendarUpcomingEvidence] = []
        total_bytes = 0
        for calendar_id in request.selected_calendar_ids:
            response = self._transport.get_json(
                calendar_id=calendar_id,
                query=request.provider_query(),
                access_token=access_token,
                maximum_response_bytes=maximum,
            )
            if not isinstance(response, CalendarHttpResponse):
                raise TypeError("Upcoming Calendar response is invalid")
            total_bytes += len(response.body)
            if total_bytes > MAX_TOTAL_UPCOMING_RESPONSE_BYTES:
                raise ConnectorResponseError(
                    "Upcoming Calendar responses exceed their total bound"
                )
            _raise_for_status(response)
            events.extend(
                _parse_events(
                    response,
                    calendar_id=calendar_id,
                    request_start=request_start,
                    request_end=request_end,
                )
            )
            evidence.append(
                CalendarUpcomingEvidence(
                    response_digest=hashlib.sha256(response.body).hexdigest(),
                    response_bytes=len(response.body),
                    http_status=response.status,
                    provider_request_id=response.provider_request_id,
                )
            )
        events.sort(key=lambda item: (item.starts_at, item.opaque_event_id))
        if len({item.opaque_event_id for item in events}) != len(events):
            raise ConnectorResponseError(
                "Upcoming Calendar returned duplicate event identities"
            )
        current = fetched_at or datetime.now(_UTC)
        if current.tzinfo is None:
            raise TypeError("Upcoming Calendar fetch time must be timezone-aware")
        return CalendarUpcomingResult(
            fetched_at=_format_utc(current.astimezone(_UTC)),
            events=tuple(events),
            evidence=tuple(evidence),
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
            "Calendar provider denied upcoming-event metadata"
        )
    if response.status == 400:
        raise ConnectorRequestError(
            "Calendar provider rejected the upcoming-event request"
        )
    if response.status == 404:
        raise ConnectorResponseError("A selected calendar is unavailable")
    raise ConnectorResponseError("Calendar provider returned an error")


def _parse_events(
    response: CalendarHttpResponse,
    *,
    calendar_id: str,
    request_start: datetime,
    request_end: datetime,
) -> list[UpcomingCalendarEvent]:
    media_type = response.content_type.partition(";")[0].strip().casefold()
    if media_type != "application/json":
        raise ConnectorResponseError("Upcoming Calendar response is not JSON")
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorResponseError(
            "Upcoming Calendar response is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or not set(payload).issubset(_ALLOWED_TOP_LEVEL)
        or not isinstance(payload.get("items", []), list)
        or len(payload.get("items", [])) > MAX_UPCOMING_EVENTS_PER_CALENDAR
    ):
        raise ConnectorResponseError(
            "Upcoming Calendar response shape is invalid"
        )
    result: list[UpcomingCalendarEvent] = []
    for value in payload.get("items", []):
        if (
            not isinstance(value, dict)
            or not set(value).issubset(_ALLOWED_EVENT_FIELDS)
        ):
            raise ConnectorResponseError("Upcoming event shape is invalid")
        status = value.get("status", "confirmed")
        if status == "cancelled":
            continue
        if status not in {"confirmed", "tentative"}:
            raise ConnectorResponseError("Upcoming event status is invalid")
        raw_id = value.get("id")
        if (
            not isinstance(raw_id, str)
            or not raw_id
            or len(raw_id) > 1_024
            or "\x00" in raw_id
        ):
            raise ConnectorResponseError("Upcoming event identity is invalid")
        start_value = value.get("start")
        end_value = value.get("end")
        if (
            not isinstance(start_value, dict)
            or not isinstance(end_value, dict)
            or not set(start_value).issubset(_ALLOWED_TIME_FIELDS)
            or not set(end_value).issubset(_ALLOWED_TIME_FIELDS)
        ):
            raise ConnectorResponseError("Upcoming event time shape is invalid")
        # All-day entries are not meetings and deliberately do not produce a
        # countdown. The partial-fields request never asks for body metadata.
        if "dateTime" not in start_value or "dateTime" not in end_value:
            continue
        try:
            start = _rfc3339(start_value["dateTime"], "Upcoming event start")
            end = _rfc3339(end_value["dateTime"], "Upcoming event end")
        except (KeyError, ValueError) as exc:
            raise ConnectorResponseError("Upcoming event time is invalid") from exc
        if end <= start or start < request_start or start >= request_end:
            raise ConnectorResponseError("Upcoming event exceeds its request window")
        opaque = hashlib.sha256(
            calendar_id.encode("utf-8")
            + b"\x00"
            + raw_id.encode("utf-8")
        ).hexdigest()
        result.append(
            UpcomingCalendarEvent(
                opaque_event_id=opaque,
                starts_at=_format_utc(start),
                ends_at=_format_utc(end),
            )
        )
    return result


__all__ = [
    "CALENDAR_UPCOMING_OPERATION_ID",
    "GOOGLE_CALENDAR_EVENTS_ENDPOINT_PREFIX",
    "CalendarUpcomingEvidence",
    "CalendarUpcomingRequest",
    "CalendarUpcomingResult",
    "FixedGoogleCalendarEventsHttpsTransport",
    "GoogleCalendarUpcomingAdapter",
    "UpcomingCalendarEvent",
]
