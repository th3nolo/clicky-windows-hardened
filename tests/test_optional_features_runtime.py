"""Caller-path tests for meeting countdown and signed skill import."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from capability_registry import (
    AccountAuthorization,
    CapabilityId,
    ConnectorId,
    OAuthScopeId,
)
from connectors.base import (
    ConnectedAccount,
    ConnectionHealth,
    ConnectorProviderId,
    SecretValue,
)
from connectors.google_calendar_upcoming import (
    CalendarUpcomingEvidence,
    CalendarUpcomingResult,
    UpcomingCalendarEvent,
)
from optional_features_runtime import (
    MeetingCountdownRuntime,
    OptionalFeatureUnavailableError,
    SignedSkillImportRuntime,
)
from skills.signed_import import SignedSkillStore
from tests.test_signed_skill_import import (
    NOW,
    definition,
    package_bytes,
    public_bytes,
    trust_policy_bytes,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from widgets.meeting_countdown import MeetingDismissalStore


MEETING_NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)


def calendar_account() -> ConnectedAccount:
    return ConnectedAccount(
        provider=ConnectorProviderId.GOOGLE,
        authorization=AccountAuthorization(
            authorization_id="oauth.runtime-calendar",
            connector=ConnectorId.GOOGLE_CALENDAR,
            account_reference="google.runtime-calendar",
            capabilities=frozenset({CapabilityId.CALENDAR_EVENT_READ}),
            oauth_scopes=frozenset({OAuthScopeId.CALENDAR_EVENTS_READ}),
        ),
        connected_at=1.0,
        updated_at=2.0,
        health=ConnectionHealth.CONNECTED,
    )


class TokenLease:
    def __init__(self) -> None:
        self.token = SecretValue(b"test-access-token")

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        self.token.close()


class FakeAccounts:
    def __init__(self, accounts=()) -> None:
        self.accounts = tuple(accounts)
        self.leases = []

    def list_accounts(self):
        return self.accounts

    def lease_access_token(self, authorization_id, capability):
        self.leases.append((authorization_id, capability))
        return TokenLease()


class FakeUpcomingAdapter:
    def __init__(self, account) -> None:
        self.account = account

    async def execute(self, call, request, access_token, *, fetched_at=None):
        self.call = call
        self.request = request
        self.token = access_token.reveal()
        return CalendarUpcomingResult(
            fetched_at="2026-07-28T12:00:00Z",
            events=(
                UpcomingCalendarEvent(
                    opaque_event_id="a" * 64,
                    starts_at="2026-07-28T12:10:00Z",
                    ends_at="2026-07-28T12:40:00Z",
                ),
            ),
            evidence=(
                CalendarUpcomingEvidence(
                    response_digest="b" * 64,
                    response_bytes=100,
                    http_status=200,
                ),
            ),
        )


class MeetingCountdownRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_privacy_hides_before_account_or_network_access(self):
        accounts = FakeAccounts()
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "optional_features_runtime.windows_session_locked",
            return_value=False,
        ):
            runtime = MeetingCountdownRuntime(
                accounts,
                dismissals=MeetingDismissalStore(
                    Path(tmp) / "dismissals.json"
                ),
                adapter_factory=FakeUpcomingAdapter,
            )
            hidden = await runtime.refresh(
                enabled=True,
                connector_read_allowed=True,
                screen_shared=True,
                now=MEETING_NOW,
            )
        self.assertEqual(hidden, ())
        self.assertEqual(accounts.leases, [])

    async def test_selected_primary_calendar_produces_generic_countdown(self):
        accounts = FakeAccounts((calendar_account(),))
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "optional_features_runtime.windows_session_locked",
            return_value=False,
        ):
            runtime = MeetingCountdownRuntime(
                accounts,
                dismissals=MeetingDismissalStore(
                    Path(tmp) / "dismissals.json"
                ),
                adapter_factory=FakeUpcomingAdapter,
            )
            cards = await runtime.refresh(
                enabled=True,
                connector_read_allowed=True,
                screen_shared=False,
                now=MEETING_NOW,
            )
            self.assertEqual(len(cards), 1)
            self.assertEqual(cards[0].display_text, "Meeting soon")
            self.assertEqual(cards[0].remaining_seconds, 600)
            runtime.dismiss(cards[0])
            hidden = await runtime.refresh(
                enabled=True,
                connector_read_allowed=True,
                screen_shared=False,
                now=MEETING_NOW,
            )
        self.assertEqual(hidden, ())
        self.assertEqual(
            accounts.leases,
            [
                (
                    "oauth.runtime-calendar",
                    CapabilityId.CALENDAR_EVENT_READ,
                ),
                (
                    "oauth.runtime-calendar",
                    CapabilityId.CALENDAR_EVENT_READ,
                ),
            ],
        )

    async def test_missing_account_and_permission_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "optional_features_runtime.windows_session_locked",
            return_value=False,
        ):
            runtime = MeetingCountdownRuntime(
                FakeAccounts(),
                dismissals=MeetingDismissalStore(
                    Path(tmp) / "dismissals.json"
                ),
                adapter_factory=FakeUpcomingAdapter,
            )
            with self.assertRaises(OptionalFeatureUnavailableError):
                await runtime.refresh(
                    enabled=True,
                    connector_read_allowed=False,
                    screen_shared=False,
                    now=MEETING_NOW,
                )
            with self.assertRaises(OptionalFeatureUnavailableError):
                await runtime.refresh(
                    enabled=True,
                    connector_read_allowed=True,
                    screen_shared=False,
                    now=MEETING_NOW,
                )


class SignedSkillRuntimeTests(unittest.TestCase):
    def test_preview_persists_trust_and_reloads_active_entry(self):
        root = Ed25519PrivateKey.generate()
        release = Ed25519PrivateKey.generate()
        roots = {"clicky-root-2026": public_bytes(root)}
        policy_payload = trust_policy_bytes(root, release)
        package_payload = package_bytes(release, definition())

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            policy_path = directory / "trust.json"
            package_path = directory / "skill.clickyskill"
            policy_path.write_bytes(policy_payload)
            package_path.write_bytes(package_payload)
            store_path = directory / "store"
            runtime = SignedSkillImportRuntime(
                feature_enabled=True,
                approved_roots=roots,
                store=SignedSkillStore(
                    store_path,
                    feature_enabled=True,
                ),
            )
            policy, preview = runtime.preview(
                trust_policy_path=policy_path,
                package_path=package_path,
                now=NOW,
            )
            self.assertEqual(policy.sequence, 1)
            runtime.activate(
                preview,
                reviewed_approval_digest=preview.approval_digest,
                now=NOW,
            )
            self.assertTrue((store_path / "trust-policy.json").exists())

            restored = SignedSkillImportRuntime(
                feature_enabled=True,
                approved_roots=roots,
                store=SignedSkillStore(
                    store_path,
                    feature_enabled=True,
                ),
            )
            entries = restored.active_entries(now=NOW)
            self.assertEqual(
                tuple(entry.skill_id for entry in entries),
                ("clicky.signed_test",),
            )
            from skills.registry import (
                load_bundled_declarative_skills,
                register_signed_external_skills,
            )

            snapshot = register_signed_external_skills(
                load_bundled_declarative_skills(),
                entries,
            )
            self.assertIsNotNone(snapshot.resolve("clicky.signed_test"))

    def test_production_empty_root_and_missing_preview_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = SignedSkillImportRuntime(
                feature_enabled=True,
                approved_roots={},
                store=SignedSkillStore(
                    Path(tmp) / "store",
                    feature_enabled=True,
                ),
            )
            with self.assertRaises(OptionalFeatureUnavailableError):
                runtime.preview(
                    trust_policy_path=Path(tmp) / "missing-policy",
                    package_path=Path(tmp) / "missing-package",
                    now=NOW,
                )

class OptionalFeaturePackagingTests(unittest.TestCase):
    def test_restored_feature_modules_are_explicitly_packaged(self):
        spec = (Path(__file__).resolve().parents[1] / "clicky.spec").read_text(
            encoding="utf-8"
        )
        for module in (
            "audio.realtime.controller",
            "audio.realtime.openai_realtime",
            "audio.realtime.windows_audio",
            "connectors.google_calendar_upcoming",
            "data_providers.places",
            "data_providers.stocks",
            "optional_features_runtime",
            "skills.signed_import",
            "widgets.meeting_countdown",
            "widgets.result_cards",
        ):
            self.assertIn(f'"{module}"', spec)



if __name__ == "__main__":
    unittest.main()
