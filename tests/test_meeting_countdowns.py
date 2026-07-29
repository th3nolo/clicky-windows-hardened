"""Selected-calendar metadata and lock/share-safe meeting countdowns."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
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
    ConnectorProviderId,
    ConnectorRequestError,
    ConnectorResponseError,
    SecretValue,
)
from connectors.google_calendar import CalendarHttpResponse
from connectors.google_calendar_upcoming import (
    CALENDAR_UPCOMING_OPERATION_ID,
    CalendarUpcomingRequest,
    FixedGoogleCalendarEventsHttpsTransport,
    GoogleCalendarUpcomingAdapter,
)
from widgets.meeting_countdown import (
    MeetingCountdownPrivacy,
    MeetingDismissalStore,
    build_meeting_countdowns,
)


TIME_MIN = "2026-07-28T12:00:00Z"
TIME_MAX = "2026-07-28T18:00:00Z"
NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.calendar-countdown",
            connector=ConnectorId.GOOGLE_CALENDAR,
            account_reference="google.calendar-countdown",
            capabilities=frozenset({CapabilityId.CALENDAR_EVENT_READ}),
            oauth_scopes=frozenset({OAuthScopeId.CALENDAR_EVENTS_READ}),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


def request() -> CalendarUpcomingRequest:
    return CalendarUpcomingRequest(
        selected_calendar_ids=("primary",),
        time_min=TIME_MIN,
        time_max=TIME_MAX,
    )


def call(value: CalendarUpcomingRequest) -> ConnectorCall:
    return ConnectorCall(
        call_id="call-countdown",
        run_id="run-countdown",
        authorization_id="oauth.calendar-countdown",
        connector=ConnectorId.GOOGLE_CALENDAR,
        capability=CapabilityId.CALENDAR_EVENT_READ,
        operation_id=value.operation_id,
        request_digest=value.request_digest,
        maximum_response_bytes=256 * 1024,
    )


def body(*, extra: dict | None = None) -> bytes:
    item = {
        "id": "provider-event-id-must-not-escape",
        "status": "confirmed",
        "start": {"dateTime": "2026-07-28T12:10:00Z"},
        "end": {"dateTime": "2026-07-28T12:40:00Z"},
    }
    if extra:
        item.update(extra)
    return json.dumps(
        {"items": [item]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


class FakeTransport:
    def __init__(self, response: CalendarHttpResponse) -> None:
        self.response = response
        self.calls = []

    def get_json(
        self,
        *,
        calendar_id,
        query,
        access_token,
        maximum_response_bytes,
    ):
        self.calls.append(
            (
                calendar_id,
                dict(query),
                access_token.reveal(),
                maximum_response_bytes,
            )
        )
        return self.response


class CalendarUpcomingTests(unittest.IsolatedAsyncioTestCase):
    async def test_reads_only_timing_metadata_from_selected_calendar(self):
        response_body = body()
        transport = FakeTransport(
            CalendarHttpResponse(
                status=200,
                content_type="application/json",
                body=response_body,
                provider_request_id="google-countdown-1",
            )
        )
        adapter = GoogleCalendarUpcomingAdapter(account(), transport)
        selected = request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)

        result = await adapter.execute(
            call(selected),
            selected,
            token,
            fetched_at=NOW,
        )

        self.assertEqual(len(result.events), 1)
        event = result.events[0]
        self.assertEqual(event.starts_at, "2026-07-28T12:10:00Z")
        self.assertEqual(event.ends_at, "2026-07-28T12:40:00Z")
        self.assertEqual(
            event.opaque_event_id,
            hashlib.sha256(
                b"primary\x00provider-event-id-must-not-escape"
            ).hexdigest(),
        )
        self.assertNotIn("provider-event-id", repr(result))
        self.assertNotIn("primary", repr(result))
        query = transport.calls[0][1]
        self.assertEqual(
            query["fields"],
            "items(id,status,start,end)",
        )
        self.assertEqual(query["maxResults"], "10")
        self.assertEqual(query["singleEvents"], "true")
        self.assertNotIn("summary", query["fields"])
        self.assertNotIn("attendees", query["fields"])
        self.assertEqual(transport.calls[0][2], b"calendar-access-token")
        self.assertEqual(
            result.evidence[0].response_digest,
            hashlib.sha256(response_body).hexdigest(),
        )

    async def test_unrequested_event_body_fields_fail_closed(self):
        selected = request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        adapter = GoogleCalendarUpcomingAdapter(
            account(),
            FakeTransport(
                CalendarHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=body(extra={"summary": "Private meeting"}),
                )
            ),
        )
        with self.assertRaisesRegex(
            ConnectorResponseError,
            "shape is invalid",
        ):
            await adapter.execute(
                call(selected),
                selected,
                token,
                fetched_at=NOW,
            )

    async def test_all_day_entries_do_not_become_meeting_countdowns(self):
        selected = request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        response = json.dumps(
            {
                "items": [
                    {
                        "id": "all-day",
                        "status": "confirmed",
                        "start": {"date": "2026-07-28"},
                        "end": {"date": "2026-07-29"},
                    }
                ]
            }
        ).encode("utf-8")
        result = await GoogleCalendarUpcomingAdapter(
            account(),
            FakeTransport(
                CalendarHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=response,
                )
            ),
        ).execute(call(selected), selected, token, fetched_at=NOW)
        self.assertEqual(result.events, ())

    def test_request_is_selected_bounded_and_digest_bound(self):
        selected = request()
        self.assertEqual(
            selected.operation_id,
            CALENDAR_UPCOMING_OPERATION_ID,
        )
        self.assertEqual(selected.capability, CapabilityId.CALENDAR_EVENT_READ)
        self.assertEqual(len(selected.request_digest), 64)
        self.assertNotIn("primary", repr(selected))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            CalendarUpcomingRequest(
                selected_calendar_ids=("primary",),
                time_min="2026-07-28T00:00:00Z",
                time_max="2026-07-30T00:00:00Z",
            )


class FixedCalendarEventsTransportTests(unittest.TestCase):
    def test_transport_builds_only_fixed_google_endpoint_and_query(self):
        class Response:
            status = 200
            headers = {"Content-Type": "application/json"}

            def read(self, _maximum):
                return b'{"items":[]}'

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

        class Opener:
            def __init__(self):
                self.calls = []

            def open(self, request, timeout):
                self.calls.append((request, timeout))
                return Response()

        opener = Opener()
        transport = FixedGoogleCalendarEventsHttpsTransport(_opener=opener)
        selected = request()
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        response = transport.get_json(
            calendar_id="team+private@example.com",
            query=selected.provider_query(),
            access_token=token,
            maximum_response_bytes=4096,
        )
        self.assertEqual(response.status, 200)
        url = opener.calls[0][0].full_url
        self.assertTrue(
            url.startswith(
                "https://www.googleapis.com/calendar/v3/calendars/"
            )
        )
        self.assertIn("team%2Bprivate%40example.com/events?", url)
        self.assertNotIn("calendar-access-token", url)
        self.assertEqual(
            opener.calls[0][0].headers["Authorization"],
            "Bearer calendar-access-token",
        )

    def test_transport_rejects_any_query_change_before_network(self):
        class Opener:
            calls = []

            def open(self, *args, **kwargs):
                self.calls.append((args, kwargs))
                raise AssertionError("unexpected network")

        opener = Opener()
        transport = FixedGoogleCalendarEventsHttpsTransport(_opener=opener)
        selected = request()
        changed = dict(selected.provider_query())
        changed["fields"] = "items(*)"
        token = SecretValue(b"calendar-access-token")
        self.addCleanup(token.close)
        with self.assertRaisesRegex(ConnectorRequestError, "not fixed"):
            transport.get_json(
                calendar_id="primary",
                query=changed,
                access_token=token,
                maximum_response_bytes=4096,
            )
        self.assertEqual(opener.calls, [])


class MeetingCountdownPrivacyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        selected = request()
        self.token = SecretValue(b"calendar-access-token")
        self.result = await GoogleCalendarUpcomingAdapter(
            account(),
            FakeTransport(
                CalendarHttpResponse(
                    status=200,
                    content_type="application/json",
                    body=body(),
                )
            ),
        ).execute(call(selected), selected, self.token, fetched_at=NOW)

    async def asyncTearDown(self):
        self.token.close()

    async def test_default_off_locked_and_shared_states_render_nothing(self):
        private = MeetingCountdownPrivacy(
            session_locked=False,
            screen_shared=False,
        )
        self.assertEqual(
            build_meeting_countdowns(
                self.result,
                enabled=False,
                privacy=private,
                now=NOW,
            ),
            (),
        )
        for privacy in (
            MeetingCountdownPrivacy(session_locked=True, screen_shared=False),
            MeetingCountdownPrivacy(session_locked=False, screen_shared=True),
        ):
            with self.subTest(privacy=privacy):
                self.assertEqual(
                    build_meeting_countdowns(
                        self.result,
                        enabled=True,
                        privacy=privacy,
                        now=NOW,
                    ),
                    (),
                )

    async def test_visible_card_is_generic_and_dismissible(self):
        privacy = MeetingCountdownPrivacy(
            session_locked=False,
            screen_shared=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = MeetingDismissalStore(
                Path(temporary) / "dismissals.json"
            )
            cards = build_meeting_countdowns(
                self.result,
                enabled=True,
                privacy=privacy,
                now=NOW,
                lead_minutes=15,
                dismissals=store,
            )
            self.assertEqual(len(cards), 1)
            self.assertEqual(cards[0].display_text, "Meeting soon")
            self.assertEqual(cards[0].remaining_seconds, 600)
            self.assertNotIn("Private", repr(cards[0]))
            store.dismiss(
                cards[0].opaque_event_id,
                until=cards[0].ends_at,
            )
            self.assertEqual(
                build_meeting_countdowns(
                    self.result,
                    enabled=True,
                    privacy=privacy,
                    now=NOW,
                    lead_minutes=15,
                    dismissals=store,
                ),
                (),
            )


if __name__ == "__main__":
    unittest.main()
