"""Explicit Screen-Aware Compose insertion tests."""

from __future__ import annotations

import hashlib
import types
import unittest

from capability_registry import CapabilityId
from compose.insertion import ComposeInsertionService
from compose.models import (
    Draft,
    DraftInsertionApproval,
    DraftProvenance,
)
from dictation.insertion import (
    InsertionAdapterKind,
    InsertionBroker,
    InsertionStatus,
    MutationOutcome,
)
from dictation.policy import SecureTargetPolicy, TargetDescriptor
from dictation.session import DictationSessionCoordinator
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
    RunCapabilityGrant,
)
from privacy_controls import PRIVACY_NOTICE_VERSION
from turn_coordinator import TurnCoordinator


PRIVATE_DRAFT = "private compose draft"


def descriptor(**changes) -> TargetDescriptor:
    values = {
        "process_id": 4000,
        "application_name": "synthetic-mail.exe",
        "application_identity": hashlib.sha256(
            b"c:\\synthetic\\mail.exe"
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": "DocumentControl",
        "framework_id": "Chrome",
        "editable": True,
        "enabled": True,
        "read_only": False,
        "password": False,
        "protected": False,
        "has_keyboard_focus": True,
        "foreground_hwnd": 100,
        "focused_runtime_id": (42, 7),
        "clicky_process_id": 9000,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
        "sensitive_surface": False,
    }
    values.update(changes)
    return TargetDescriptor(**values)


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.SCREEN_AWARE_COMPOSE] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


def configured(**changes):
    values = {
        "privacy_consent_version": PRIVACY_NOTICE_VERSION,
        "action_permission_schema_version": (
            ACTION_PERMISSION_SCHEMA_VERSION
        ),
        "global_dictation_permission": False,
        "screen_compose_permission": True,
        "task_agent_permission": False,
        "connector_read_permission": False,
        "connector_write_permission": False,
        "workspace_coding_permission": False,
        "desktop_automation_permission": False,
    }
    values.update(changes)
    return types.SimpleNamespace(**values)


class Guard:
    def __init__(self):
        self.policy = SecureTargetPolicy()
        self.original = descriptor()
        self.current = self.original
        decision = self.policy.evaluate(self.original)
        assert decision.lease is not None
        self.lease = decision.lease
        self.calls = 0

    def revalidate(self, lease):
        self.calls += 1
        return self.policy.revalidate(lease, self.current)


class Backend:
    def __init__(self):
        self.events = []
        self.destination = ["original destination"]
        self.unicode_available = True
        self.clipboard_available = True
        self.raise_unicode = False

    def value_pattern_available(self, target):
        self.events.append("query_value")
        return False

    def replace_whole_value(self, target, text):
        raise AssertionError("whole-value replacement was not approved")

    def unicode_input_available(self, target):
        self.events.append("query_unicode")
        return self.unicode_available

    def send_unicode(self, target, text):
        self.events.append(("mutate_unicode", text))
        if self.raise_unicode:
            raise RuntimeError("private backend failure")
        self.destination.append(text)
        return MutationOutcome(True, True, False)

    def clipboard_paste_available(self, target):
        self.events.append("query_clipboard")
        return self.clipboard_available

    def paste_via_clipboard(self, target, text):
        self.events.append(("mutate_clipboard", text))
        self.destination.append(text)
        return MutationOutcome(True, True, False)

    def copy_text(self, text):
        self.events.append(("copy", text))
        return True

    @property
    def mutations(self):
        return [
            event
            for event in self.events
            if isinstance(event, tuple)
            and event[0].startswith("mutate_")
        ]


def approval(guard: Guard, *, run_id="compose-insert-1"):
    target = guard.lease.descriptor
    draft = Draft(
        text=PRIVATE_DRAFT,
        provenance=DraftProvenance(
            run_id=run_id,
            provider_id="openai",
            model_id="gpt-4o-mini",
            destination_application=target.application_name,
            destination_identity=target.application_identity,
            target_type=(
                f"{target.framework_id}:{target.control_type}"
            ),
            screenshot_ids=("monitor-one",),
            response_language="en-US",
            style_profile_id="work-concise",
            max_output_chars=240,
        ),
    )
    grant = RunCapabilityGrant(
        run_id,
        frozenset(
            {
                CapabilityId.COMPOSE_SCREEN_CONTEXT,
                CapabilityId.STYLE_PROFILE_USE,
            }
        ),
    )
    return DraftInsertionApproval(
        draft=draft,
        target=guard.lease,
        grant=grant,
    )


def service_fixture():
    guard = Guard()
    backend = Backend()
    sessions = DictationSessionCoordinator(TurnCoordinator())
    broker = InsertionBroker(sessions, guard, backend)
    service = ComposeInsertionService(
        broker,
        build_flags=enabled_build_flags(),
    )
    return service, broker, guard, backend


class ComposeInsertionTests(unittest.TestCase):
    def test_one_approval_produces_at_most_one_insertion_attempt(self):
        service, _, guard, backend = service_fixture()
        approved = approval(guard)

        result = service.insert(approved, configured())
        duplicate = service.insert(approved, configured())

        self.assertEqual(
            result.status,
            InsertionStatus.ATTEMPTED_UNVERIFIED,
        )
        self.assertEqual(
            result.adapter,
            InsertionAdapterKind.UNICODE_SEND_INPUT,
        )
        self.assertEqual(len(backend.mutations), 1)
        self.assertEqual(duplicate.status, InsertionStatus.BLOCKED)
        self.assertEqual(
            duplicate.result_code,
            "compose_insertion_duplicate_blocked",
        )
        self.assertNotIn(PRIVATE_DRAFT, repr(result))

    def test_permission_alone_cannot_authorize_insertion(self):
        service, _, _, backend = service_fixture()

        with self.assertRaisesRegex(TypeError, "explicit preview approval"):
            service.insert(None, configured())

        self.assertEqual(backend.events, [])
        self.assertEqual(
            backend.destination,
            ["original destination"],
        )

    def test_revoked_or_baseline_permission_fails_before_target(self):
        service, _, guard, backend = service_fixture()
        denied = service.insert(
            approval(guard),
            configured(
                global_dictation_permission=True,
                screen_compose_permission=False,
            ),
        )

        baseline_sessions = DictationSessionCoordinator(
            TurnCoordinator()
        )
        baseline_broker = InsertionBroker(
            baseline_sessions,
            guard,
            backend,
        )
        baseline = ComposeInsertionService(baseline_broker)
        baseline_denied = baseline.insert(
            approval(guard, run_id="compose-insert-2"),
            configured(),
        )

        self.assertEqual(denied.status, InsertionStatus.BLOCKED)
        self.assertEqual(
            denied.result_code,
            "compose_insertion_permission_blocked",
        )
        self.assertEqual(baseline_denied.status, InsertionStatus.BLOCKED)
        self.assertEqual(guard.calls, 0)
        self.assertEqual(backend.events, [])

    def test_second_service_instance_cannot_reuse_the_approval(self):
        service, broker, guard, backend = service_fixture()
        second = ComposeInsertionService(
            broker,
            build_flags=enabled_build_flags(),
        )
        approved = approval(guard)

        first = service.insert(approved, configured())
        duplicate = second.insert(approved, configured())

        self.assertTrue(first.terminal_success)
        self.assertEqual(duplicate.status, InsertionStatus.BLOCKED)
        self.assertEqual(
            duplicate.result_code,
            "insertion_duplicate_blocked",
        )
        self.assertEqual(len(backend.mutations), 1)

    def test_target_change_blocks_before_backend_query(self):
        service, _, guard, backend = service_fixture()
        approved = approval(guard)
        guard.current = descriptor(
            top_level_hwnd=200,
            foreground_hwnd=200,
            runtime_id=(99, 1),
            focused_runtime_id=(99, 1),
        )

        result = service.insert(approved, configured())

        self.assertEqual(result.status, InsertionStatus.BLOCKED)
        self.assertEqual(guard.calls, 1)
        self.assertEqual(backend.events, [])
        self.assertEqual(
            backend.destination,
            ["original destination"],
        )

    def test_clipboard_fallback_is_never_implicitly_approved(self):
        service, _, guard, backend = service_fixture()
        backend.unicode_available = False

        result = service.insert(approval(guard), configured())

        self.assertEqual(result.status, InsertionStatus.UNSUPPORTED)
        self.assertEqual(result.adapter, InsertionAdapterKind.PREVIEW_COPY)
        self.assertNotIn("query_clipboard", backend.events)
        self.assertEqual(backend.mutations, [])
        self.assertEqual(
            backend.destination,
            ["original destination"],
        )

    def test_backend_failure_is_content_free_and_does_not_retry(self):
        service, _, guard, backend = service_fixture()
        backend.raise_unicode = True

        with self.assertLogs(
            "compose.insertion",
            level="INFO",
        ) as captured:
            result = service.insert(approval(guard), configured())

        self.assertEqual(result.status, InsertionStatus.FAILED)
        self.assertEqual(len(backend.mutations), 1)
        self.assertNotIn("query_clipboard", backend.events)
        self.assertNotIn(PRIVATE_DRAFT, repr(result))
        self.assertNotIn(
            PRIVATE_DRAFT,
            "\n".join(captured.output),
        )
        self.assertNotIn(
            "private backend failure",
            "\n".join(captured.output),
        )
        self.assertEqual(
            backend.destination,
            ["original destination"],
        )

    def test_approval_requires_matching_compose_grant(self):
        guard = Guard()
        approved = approval(guard)
        wrong = RunCapabilityGrant(
            approved.run_id,
            frozenset({CapabilityId.DICTATION_INSERT_TEXT}),
        )

        with self.assertRaisesRegex(
            ValueError,
            "matching compose run grant",
        ):
            DraftInsertionApproval(
                draft=approved.draft,
                target=approved.target,
                grant=wrong,
            )


if __name__ == "__main__":
    unittest.main()
