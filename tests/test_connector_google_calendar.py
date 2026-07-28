"""Google Calendar selected free/busy adapter tests."""

from __future__ import annotations

import hashlib
import json
import unittest
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
    ConnectorAdapter,
    ConnectorAuthorizationError,
    ConnectorCall,
    ConnectorExecution,
    ConnectorProviderId,
    ConnectorRateLimitError,
    ConnectorRequestError,
    ConnectorResponseError,
    ConnectorTokenExpiredError,
    SecretValue,
)
from connectors.google_calendar import (
    CALENDAR_AVAILABILITY_OPERATION_ID,
    GOOGLE_CALENDAR_FREEBUSY_ENDPOINT,
    CalendarAvailabilityRequest,
    CalendarHttpResponse,
    FixedGoogleCalendarHttpsTransport,
    GoogleCalendarAvailabilityAdapter,
)


TIME_MIN = "2026-07-27T12:00:00Z"
TIME_MAX = "2026-07-28T12:00:00Z"
CALENDARS = ("primary", "team@example.com")


def _account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.calendar-one",
            connector=ConnectorId.GOOGLE_CALENDAR,
            account_reference="google.calendar-one",
            capabilities=frozenset(
                {CapabilityId.CALENDAR_EVENT_READ}
            ),
            oauth_scopes=frozenset(
                {OAuthScopeId.CALENDAR_EVENTS_READ}
            ),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def _request() -> CalendarAvailabilityRequest:
    return CalendarAvailabilityRequest(
        selected_calendar_ids=CALENDARS,
        time_min=TIME_MIN,
        time_max=TIME_MAX,
    )


def _call(
    request: CalendarAvailabilityRequest,
    *,
    authorization_id: str = "oauth.calendar-one",
) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-calendar",
        run_id="run-calendar",
        authorization_id=authorization_id,
        connector=ConnectorId.GOOGLE_CALENDAR,
        capability=CapabilityId.CALENDAR_EVENT_READ,
        operation_id=request.operation_id,
        request_digest=request.request_digest,
        maximum_response_bytes=1024 * 1024,
    )


def _body(*, interval_extra: dict[str, object] | None = None) -> bytes:
    first_interval: dict[str, object] = {
        "start": "2026-07-27T14:00:00Z",
        "end": "2026-07-27T15:00:00Z",
    }
    if interval_extra:
        first_interval.update(interval_extra)
    return json.dumps(
        {
            "kind": "calendar#freeBusy",
            "timeMin": TIME_MIN,
            "timeMax": TIME_MAX,
            "groups": {},
            "calendars": {
                "primary": {
                    "busy": [
                        {
                            "start": "2026-07-27T18:00:00Z",
                            "end": "2026-07-27T19:00:00Z",
                        },
                        first_interval,
                    ]
                },
                "team@example.com": {"busy": []},
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class _FakeTransport:
    def __init__(self, response: CalendarHttpResponse) -> None:
        self.response = response
        self.calls = []

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
                endpoint,
                dict(payload),
                access_token.reveal(),
                maximum_response_bytes,
            )
        )
        return self.response


class CalendarAvailabilityRequestTests(unittest.TestCase):
    def test_request_is_bounded_selected_only_and_digest_bound(self):
        request = _request()

        self.assertEqual(
            request.operation_id,
            CALENDAR_AVAILABILITY_OPERATION_ID,
        )
        self.assertEqual(
            request.capability,
            CapabilityId.CALENDAR_EVENT_READ,
        )
        self.assertEqual(
            request.provider_payload(),
            {
                "calendarExpansionMax": 2,
                "items": [{"id": "primary"}, {"id": "team@example.com"}],
                "timeMax": TIME_MAX,
                "timeMin": TIME_MIN,
                "timeZone": "UTC",
            },
        )
        self.assertNotIn("groupExpansionMax", request.provider_payload())
        self.assertNotIn("team@example.com", repr(request))
        self.assertNotIn("'primary'", repr(request))
        self.assertEqual(len(request.request_digest), 64)

    def test_request_rejects_duplicate_unbounded_or_naive_ranges(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            CalendarAvailabilityRequest(
                selected_calendar_ids=("primary", "primary"),
                time_min=TIME_MIN,
                time_max=TIME_MAX,
            )
        with self.assertRaisesRegex(ValueError, "RFC 3339"):
            CalendarAvailabilityRequest(
                selected_calendar_ids=("primary",),
                time_min="2026-07-27T12:00:00",
                time_max=TIME_MAX,
            )
        with self.assertRaisesRegex(ValueError, "RFC 3339"):
            CalendarAvailabilityRequest(
                selected_calendar_ids=("primary",),
                time_min="2026-07-27 12:00:00Z",
                time_max=TIME_MAX,
            )
        with self.assertRaisesRegex(ValueError, "exceeds"):
            CalendarAvailabilityRequest(
                selected_calendar_ids=("primary",),
                time_min="2026-01-01T00:00:00Z",
                time_max="2026-03-01T00:00:00Z",
            )


class FixedGoogleCalendarTransportTests(unittest.TestCase):
    def test_transport_rejects_non_policy_endpoint_before_token_or_io(self):
        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("unexpected network request")

        opener = Opener()
        transport = FixedGoogleCalendarHttpsTransport(_opener=opener)
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)

        with self.assertRaisesRegex(
            ConnectorRequestError,
            "not fixed",
        ):
            transport.post_json(
                endpoint="https://example.com/freeBusy",
                payload={"items": [{"id": "primary"}]},
                access_token=token,
                maximum_response_bytes=4096,
            )

        self.assertEqual(opener.calls, [])

    def test_transport_source_disables_proxies_redirects_and_logging(self):
        source = Path("connectors/google_calendar.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("urllib.request.ProxyHandler({})", source)
        self.assertIn("_NoRedirectHandler()", source)
        self.assertNotIn("urllib.request.urlopen", source)
        self.assertNotIn("logging", source)
        self.assertNotIn("requests.", source)
        self.assertNotIn("aiohttp", source)


class GoogleCalendarAvailabilityAdapterTests(
    unittest.IsolatedAsyncioTestCase
):
    async def test_returns_only_selected_free_busy_with_provider_evidence(self):
        response_body = _body()
        transport = _FakeTransport(
            CalendarHttpResponse(
                status=200,
                content_type="application/json; charset=UTF-8",
                body=response_body,
                provider_request_id="google-request-1",
            )
        )
        adapter = GoogleCalendarAvailabilityAdapter(
            _account(),
            transport,
            _revoker=lambda *_args: None,
        )
        self.assertIsInstance(adapter, ConnectorAdapter)
        request = _request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)

        execution = await adapter.execute(
            _call(request),
            request,
            token,
        )

        self.assertIsInstance(execution, ConnectorExecution)
        self.assertEqual(
            execution.result.response_digest,
            hashlib.sha256(response_body).hexdigest(),
        )
        self.assertEqual(
            execution.result.provider_request_id,
            "google-request-1",
        )
        self.assertEqual(
            tuple(
                calendar.calendar_id
                for calendar in execution.output.calendars
            ),
            CALENDARS,
        )
        self.assertEqual(
            tuple(
                interval.start
                for interval in execution.output.calendars[0].busy
            ),
            (
                "2026-07-27T14:00:00Z",
                "2026-07-27T18:00:00Z",
            ),
        )
        output = execution.output.to_json_bytes()
        self.assertNotIn(b"summary", output)
        self.assertNotIn(b"description", output)
        self.assertNotIn(b"attendees", output)
        self.assertEqual(
            transport.calls[0][0],
            GOOGLE_CALENDAR_FREEBUSY_ENDPOINT,
        )
        self.assertEqual(
            transport.calls[0][2],
            b"calendar-access-token",
        )

    async def test_event_body_fields_and_unselected_calendars_fail_closed(self):
        request = _request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        body = _body(interval_extra={"summary": "private title"})
        adapter = GoogleCalendarAvailabilityAdapter(
            _account(),
            _FakeTransport(
                CalendarHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=body,
                )
            ),
        )
        with self.assertRaisesRegex(
            ConnectorResponseError,
            "interval shape",
        ):
            await adapter.execute(_call(request), request, token)

        payload = json.loads(_body().decode("utf-8"))
        payload["calendars"]["unselected@example.com"] = {"busy": []}
        adapter = GoogleCalendarAvailabilityAdapter(
            _account(),
            _FakeTransport(
                CalendarHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=json.dumps(payload).encode("utf-8"),
                )
            ),
        )
        with self.assertRaisesRegex(
            ConnectorResponseError,
            "unselected or missing",
        ):
            await adapter.execute(_call(request), request, token)

    async def test_account_authority_is_checked_before_transport(self):
        request = _request()
        transport = _FakeTransport(
            CalendarHttpResponse(
                status=200,
                content_type="application/json",
                body=_body(),
            )
        )
        adapter = GoogleCalendarAvailabilityAdapter(
            _account(),
            transport,
        )
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)

        with self.assertRaisesRegex(
            ConnectorAuthorizationError,
            "exact account authority",
        ):
            await adapter.execute(
                _call(request, authorization_id="oauth.another"),
                request,
                token,
            )

        self.assertEqual(transport.calls, [])

    async def test_expired_and_rate_limited_responses_are_explicit(self):
        request = _request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        expired = GoogleCalendarAvailabilityAdapter(
            _account(),
            _FakeTransport(
                CalendarHttpResponse(
                    status=401,
                    content_type="application/json",
                    body=b'{"error":{"code":401}}',
                )
            ),
        )
        with self.assertRaises(ConnectorTokenExpiredError):
            await expired.execute(_call(request), request, token)

        limited = GoogleCalendarAvailabilityAdapter(
            _account(),
            _FakeTransport(
                CalendarHttpResponse(
                    status=429,
                    content_type="application/json",
                    body=b'{"error":{"code":429}}',
                    retry_after_seconds=17,
                )
            ),
        )
        with self.assertRaises(ConnectorRateLimitError) as raised:
            await limited.execute(_call(request), request, token)
        self.assertEqual(raised.exception.retry_after_seconds, 17)


if __name__ == "__main__":
    unittest.main()
