"""Truthful, exactly-once Global Dictation insertion adapters."""

from __future__ import annotations

import contextlib
import hashlib
import os
import threading
import time
from pathlib import Path
import types
import unittest
from unittest import mock

from dictation.insertion import (
    CopyPreview,
    InsertionAdapterKind,
    InsertionBroker,
    InsertionIntent,
    InsertionRequest,
    InsertionStatus,
    MutationOutcome,
)
from dictation.policy import (
    SecureTargetPolicy,
    TargetDecision,
    TargetDescriptor,
    TargetReason,
    TargetStatus,
)
from dictation.session import DictationSessionCoordinator
from dictation import windows_insertion
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from privacy_controls import PRIVACY_NOTICE_VERSION
from turn_coordinator import TurnCoordinator


def descriptor(**changes) -> TargetDescriptor:
    values = {
        "process_id": 4000,
        "application_name": "notepad.exe",
        "application_identity": hashlib.sha256(
            b"c:\\windows\\notepad.exe"
        ).hexdigest(),
        "top_level_hwnd": 100,
        "runtime_id": (42, 7),
        "control_type": "EditControl",
        "framework_id": "Win32",
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


def configured():
    return types.SimpleNamespace(
        privacy_consent_version=PRIVACY_NOTICE_VERSION,
        microphone_consent=True,
        action_permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
        global_dictation_permission=True,
        screen_compose_permission=False,
        task_agent_permission=False,
        connector_read_permission=False,
        connector_write_permission=False,
        workspace_coding_permission=False,
        desktop_automation_permission=False,
    )


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.GLOBAL_DICTATION] = BuildFeatureFlag(
        available=True,
        permission_schema_version=ACTION_PERMISSION_SCHEMA_VERSION,
    )
    return flags


class ScriptedGuard:
    def __init__(self, *revalidations: TargetDecision):
        self.policy = SecureTargetPolicy()
        self.capture_decision = self.policy.evaluate(descriptor())
        self.revalidations = list(revalidations)
        self.revalidation_calls = 0

    def capture(self):
        return self.capture_decision

    def revalidate(self, lease):
        self.revalidation_calls += 1
        if self.revalidations:
            return self.revalidations.pop(0)
        return self.policy.revalidate(lease, descriptor())


class FakeBackend:
    def __init__(self):
        self.events = []
        self.value_available = False
        self.unicode_available = True
        self.clipboard_available = True
        self.value_outcome = MutationOutcome(True, True, True)
        self.unicode_outcome = MutationOutcome(True, True, False)
        self.clipboard_outcome = MutationOutcome(
            True,
            True,
            False,
            clipboard_restored=True,
            clipboard_changed_externally=False,
        )
        self.copy_succeeds = True
        self.raise_unicode = False

    def value_pattern_available(self, target):
        self.events.append("query_value")
        return self.value_available

    def replace_whole_value(self, target, text):
        self.events.append("mutate_value")
        return self.value_outcome

    def unicode_input_available(self, target):
        self.events.append("query_unicode")
        return self.unicode_available

    def send_unicode(self, target, text):
        self.events.append("mutate_unicode")
        if self.raise_unicode:
            raise RuntimeError("private backend error")
        return self.unicode_outcome

    def clipboard_paste_available(self, target):
        self.events.append("query_clipboard")
        return self.clipboard_available

    def paste_via_clipboard(self, target, text):
        self.events.append("mutate_clipboard")
        return self.clipboard_outcome

    def copy_text(self, text):
        self.events.append("copy_preview")
        return self.copy_succeeds

    @property
    def mutation_count(self):
        return sum(
            event.startswith("mutate_")
            for event in self.events
        )


class FakeApplicationAdapter:
    def __init__(self, outcome: MutationOutcome):
        self.outcome = outcome
        self.events = []

    def supports(self, target, intent):
        self.events.append("supports")
        return True

    def insert(self, target, text, intent):
        self.events.append("insert")
        return self.outcome


def prepared_commit(guard: ScriptedGuard | None = None):
    guard = guard or ScriptedGuard()
    sessions = DictationSessionCoordinator(
        TurnCoordinator(),
        targets=guard,
        build_flags=enabled_build_flags(),
    )
    session = sessions.begin_capture(configured())
    sessions.release_capture(session)
    sessions.accept_final_transcript(
        session,
        "private final transcript",
    )
    commit = sessions.begin_commit(session)
    assert commit is not None
    return sessions, guard, session, commit


class InsertionBrokerTests(unittest.TestCase):
    def test_unicode_input_is_exactly_once_and_never_claims_verification(self):
        sessions, guard, session, commit = prepared_commit()
        backend = FakeBackend()
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(InsertionRequest(commit))
        duplicate = broker.insert(InsertionRequest(commit))

        self.assertEqual(
            result.status,
            InsertionStatus.ATTEMPTED_UNVERIFIED,
        )
        self.assertEqual(
            result.adapter,
            InsertionAdapterKind.UNICODE_SEND_INPUT,
        )
        self.assertEqual(backend.mutation_count, 1)
        self.assertEqual(duplicate.status, InsertionStatus.BLOCKED)
        self.assertEqual(backend.mutation_count, 1)
        self.assertTrue(session.terminal)
        self.assertNotIn("private final transcript", repr(result))

    def test_immediate_target_change_blocks_before_any_backend_query(self):
        policy = SecureTargetPolicy()
        changed = descriptor(
            top_level_hwnd=200,
            foreground_hwnd=200,
            runtime_id=(99, 1),
            focused_runtime_id=(99, 1),
        )
        captured = policy.evaluate(descriptor()).lease
        self.assertIsNotNone(captured)
        guard = ScriptedGuard(
            policy.evaluate(descriptor()),
            policy.revalidate(captured, changed),
        )
        sessions, guard, session, commit = prepared_commit(guard)
        backend = FakeBackend()
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(InsertionRequest(commit))

        self.assertEqual(result.status, InsertionStatus.BLOCKED)
        self.assertEqual(backend.events, [])
        self.assertEqual(session.result_code, result.result_code)

    def test_whole_value_replacement_requires_explicit_intent_and_readback(self):
        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        backend.value_available = True
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(
            InsertionRequest(
                commit,
                intent=InsertionIntent.REPLACE_WHOLE_VALUE,
            )
        )

        self.assertEqual(
            result.status,
            InsertionStatus.VERIFIED_INSERTED,
        )
        self.assertEqual(
            result.adapter,
            InsertionAdapterKind.UIA_VALUE_REPLACE,
        )
        self.assertEqual(backend.mutation_count, 1)
        self.assertNotIn("mutate_unicode", backend.events)

    def test_whole_value_intent_never_degrades_to_caret_or_clipboard(self):
        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(
            InsertionRequest(
                commit,
                intent=InsertionIntent.REPLACE_WHOLE_VALUE,
                clipboard_fallback_approved=True,
            )
        )

        self.assertEqual(result.status, InsertionStatus.UNSUPPORTED)
        self.assertEqual(backend.mutation_count, 0)
        self.assertNotIn("query_unicode", backend.events)
        self.assertNotIn("query_clipboard", backend.events)

    def test_reviewed_application_adapter_has_priority_and_no_fallback(self):
        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        application = FakeApplicationAdapter(
            MutationOutcome(True, False)
        )
        broker = InsertionBroker(
            sessions,
            guard,
            backend,
            application_adapters=(application,),
        )

        result = broker.insert(InsertionRequest(commit))

        self.assertEqual(result.status, InsertionStatus.FAILED)
        self.assertEqual(application.events, ["supports", "insert"])
        self.assertEqual(backend.events, [])

    def test_clipboard_fallback_requires_separate_approval(self):
        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        backend.unicode_available = False
        broker = InsertionBroker(sessions, guard, backend)
        denied = broker.insert(InsertionRequest(commit))
        self.assertEqual(denied.status, InsertionStatus.UNSUPPORTED)
        self.assertEqual(backend.mutation_count, 0)

        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        backend.unicode_available = False
        broker = InsertionBroker(sessions, guard, backend)
        approved = broker.insert(
            InsertionRequest(
                commit,
                clipboard_fallback_approved=True,
            )
        )
        self.assertEqual(
            approved.status,
            InsertionStatus.ATTEMPTED_UNVERIFIED,
        )
        self.assertEqual(
            approved.adapter,
            InsertionAdapterKind.CLIPBOARD_PASTE,
        )
        self.assertTrue(approved.clipboard_restored)
        self.assertFalse(approved.clipboard_changed_externally)
        self.assertEqual(backend.mutation_count, 1)

    def test_unsupported_preview_is_unchanged_until_one_explicit_copy(self):
        sessions, guard, _, commit = prepared_commit()
        backend = FakeBackend()
        backend.unicode_available = False
        backend.clipboard_available = False
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(InsertionRequest(commit))

        self.assertEqual(result.status, InsertionStatus.UNSUPPORTED)
        self.assertIsInstance(result.preview, CopyPreview)
        self.assertEqual(backend.mutation_count, 0)
        self.assertNotIn("private final transcript", repr(result))
        self.assertTrue(broker.copy_preview(result.preview).copied)
        self.assertFalse(broker.copy_preview(result.preview).copied)
        self.assertEqual(backend.events.count("copy_preview"), 1)

    def test_backend_exception_is_failed_without_raw_error_or_fallback(self):
        sessions, guard, session, commit = prepared_commit()
        backend = FakeBackend()
        backend.raise_unicode = True
        broker = InsertionBroker(sessions, guard, backend)

        result = broker.insert(InsertionRequest(commit))

        self.assertEqual(result.status, InsertionStatus.FAILED)
        self.assertEqual(result.result_code, "insertion_backend_failed")
        self.assertEqual(session.result_code, "insertion_backend_failed")
        self.assertEqual(backend.mutation_count, 1)
        self.assertNotIn("private backend error", repr(result))

    def test_turn_replacement_cannot_interleave_with_owned_mutation(self):
        sessions, guard, session, commit = prepared_commit()
        backend = FakeBackend()
        mutation_started = threading.Event()
        allow_completion = threading.Event()

        def blocking_send(target, text):
            backend.events.append("mutate_unicode")
            mutation_started.set()
            self.assertTrue(allow_completion.wait(2))
            return MutationOutcome(True, True, False)

        backend.send_unicode = blocking_send
        broker = InsertionBroker(sessions, guard, backend)
        results = []
        replacement = []
        insert_thread = threading.Thread(
            target=lambda: results.append(
                broker.insert(InsertionRequest(commit))
            )
        )
        replace_thread = threading.Thread(
            target=lambda: replacement.append(
                sessions._turns.start_capture()
            )
        )

        insert_thread.start()
        self.assertTrue(mutation_started.wait(1))
        replace_thread.start()
        time.sleep(0.02)
        self.assertTrue(replace_thread.is_alive())
        allow_completion.set()
        insert_thread.join(2)
        replace_thread.join(2)

        self.assertEqual(backend.mutation_count, 1)
        self.assertEqual(
            results[0].status,
            InsertionStatus.ATTEMPTED_UNVERIFIED,
        )
        self.assertTrue(session.terminal)
        self.assertIsNotNone(replacement[0])


class WindowsInsertionPrimitiveTests(unittest.TestCase):
    def test_clipboard_owner_must_be_a_top_level_current_process_window(self):
        class Function:
            def __init__(self, callback):
                self.callback = callback
                self.argtypes = None
                self.restype = None

            def __call__(self, *args):
                return self.callback(*args)

        class User32:
            def __init__(self, *, root=123, process_id=None):
                self.IsWindow = Function(lambda handle: handle == 123)
                self.GetAncestor = Function(
                    lambda handle, relation: root
                )

                def process(_handle, output):
                    output._obj.value = (
                        os.getpid()
                        if process_id is None
                        else process_id
                    )
                    return 9

                self.GetWindowThreadProcessId = Function(process)

        with (
            mock.patch.object(windows_insertion.os, "name", "nt"),
            mock.patch.object(
                windows_insertion.ctypes,
                "WinDLL",
                return_value=User32(),
                create=True,
            ),
        ):
            self.assertTrue(
                windows_insertion.is_clicky_owned_window(123)
            )

        for backend in (
            User32(root=999),
            User32(process_id=os.getpid() + 1),
        ):
            with (
                mock.patch.object(windows_insertion.os, "name", "nt"),
                mock.patch.object(
                    windows_insertion.ctypes,
                    "WinDLL",
                    return_value=backend,
                    create=True,
                ),
            ):
                self.assertFalse(
                    windows_insertion.is_clicky_owned_window(123)
                )

    def test_clipboard_requires_a_nonzero_clicky_owner_window(self):
        backend = windows_insertion.WindowsInsertionBackend()
        self.assertEqual(backend._clipboard_owner_handle(), 0)
        backend = windows_insertion.WindowsInsertionBackend(lambda: 123)
        self.assertEqual(backend._clipboard_owner_handle(), 123)
        source = Path(windows_insertion.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn("OpenClipboard(None)", source)

    def test_unicode_input_encodes_surrogate_pairs_and_is_never_verified(self):
        inputs = windows_insertion._unicode_inputs("A😀")
        self.assertEqual(len(inputs), 6)
        self.assertEqual(
            [item.keyboard.scan_code for item in inputs[2::2]],
            [0xD83D, 0xDE00],
        )

    def test_clipboard_change_prevents_set_or_restore_overwrite(self):
        snapshot = windows_insertion.ClipboardSnapshot(
            sequence=10,
            formats=frozenset(),
            was_empty=True,
        )
        user32 = mock.Mock()
        user32.GetClipboardSequenceNumber.return_value = 11
        set_text = mock.Mock()
        with mock.patch.object(
            windows_insertion,
            "_clipboard_libraries",
            return_value=(user32, mock.Mock()),
        ), mock.patch.object(
            windows_insertion,
            "_OpenClipboard",
            side_effect=lambda *_: contextlib.nullcontext(),
        ), mock.patch.object(
            windows_insertion,
            "_set_text_locked",
            set_text,
        ):
            written = windows_insertion._set_text_if_unchanged(
                123,
                snapshot,
                "private final transcript",
            )
            restored = windows_insertion._restore_if_unchanged(
                123,
                10,
                snapshot,
            )

        self.assertIsNone(written)
        self.assertEqual(restored, (False, True))
        set_text.assert_not_called()

    def test_mutation_outcome_rejects_false_verification(self):
        with self.assertRaises(ValueError):
            MutationOutcome(
                attempted=True,
                succeeded=False,
                verified=True,
            )
        with self.assertRaises(ValueError):
            MutationOutcome(
                attempted=False,
                succeeded=True,
            )


if __name__ == "__main__":
    unittest.main()
