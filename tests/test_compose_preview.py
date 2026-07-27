"""Non-destructive Screen-Aware Compose preview tests."""

from __future__ import annotations

import ast
import hashlib
import os
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QPushButton

from compose.models import (
    Draft,
    DraftInsertionApproval,
    DraftProvenance,
)
from dictation.policy import (
    SecureTargetPolicy,
    TargetDescriptor,
)
from feature_gates import ActionCapability, RunCapabilityGrant
from ui.compose_preview import ComposePreviewPanel


ROOT = Path(__file__).resolve().parents[1]


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


class Guard:
    def __init__(self):
        self.policy = SecureTargetPolicy()
        self.original = descriptor()
        self.current = self.original
        decision = self.policy.evaluate(self.original)
        assert decision.lease is not None
        self.lease = decision.lease
        self.calls = []

    def revalidate(self, lease):
        self.calls.append(lease)
        return self.policy.revalidate(lease, self.current)


def draft_for(lease, **changes) -> Draft:
    target = lease.descriptor
    values = {
        "run_id": "compose-preview-1",
        "provider_id": "openai",
        "model_id": "gpt-4o-mini",
        "destination_application": target.application_name,
        "destination_identity": target.application_identity,
        "target_type": (
            f"{target.framework_id}:{target.control_type}"
        ),
        "screenshot_ids": ("monitor-one",),
        "response_language": "en-US",
        "style_profile_id": "work-concise",
        "max_output_chars": 240,
    }
    values.update(changes)
    return Draft(
        text="Tuesday afternoon works for me.",
        provenance=DraftProvenance(**values),
    )


class ComposePreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.guard = Guard()
        self.grant = RunCapabilityGrant(
            "compose-preview-1",
            frozenset(
                {ActionCapability.SCREEN_AWARE_COMPOSE}
            ),
        )
        self.panel = ComposePreviewPanel(self.guard)

    def tearDown(self):
        self.panel.clear_sensitive()
        self.panel.close()
        self.app.processEvents()

    def show(self, draft=None):
        current = draft or draft_for(self.guard.lease)
        self.panel.show_draft(
            current,
            self.guard.lease,
            self.grant,
        )
        self.app.processEvents()
        return current

    def test_shows_review_metadata_and_only_four_safe_actions(self):
        current = self.show()

        self.assertEqual(
            self.panel._preview.toPlainText(),
            current.text,
        )
        self.assertEqual(
            self.panel._destination.text(),
            "Destination: synthetic-mail.exe",
        )
        self.assertIn(
            "Writing profile: work-concise",
            self.panel._metadata.text(),
        )
        self.assertIn("Provider: OpenAI", self.panel._metadata.text())
        self.assertEqual(
            self.panel._character_count.text(),
            "31 characters",
        )
        labels = {
            button.text()
            for button in self.panel.findChildren(QPushButton)
        }
        self.assertEqual(
            labels,
            {"Insert", "Copy", "Regenerate", "Cancel"},
        )
        self.assertTrue(
            self.panel.windowFlags()
            & Qt.WindowType.WindowDoesNotAcceptFocus
        )
        self.assertTrue(
            self.panel.testAttribute(
                Qt.WidgetAttribute.WA_ShowWithoutActivating
            )
        )
        self.assertIs(self.panel._target, self.guard.lease)
        self.panel.setFocus()
        self.assertIs(self.panel._target, self.guard.lease)

    def test_insert_revalidates_remembered_target_and_is_one_use(self):
        current = self.show()
        approvals = []
        self.panel.insert_approved.connect(approvals.append)

        self.panel._request_insert()
        self.panel._request_insert()

        self.assertEqual(self.guard.calls, [self.guard.lease])
        self.assertEqual(len(approvals), 1)
        approval = approvals[0]
        self.assertIsInstance(approval, DraftInsertionApproval)
        self.assertIs(approval.draft, current)
        self.assertEqual(approval.run_id, "compose-preview-1")
        self.assertNotIn(current.text, repr(approval))
        self.assertEqual(self.panel._preview.toPlainText(), "")
        self.assertIsNone(self.panel._target)

    def test_target_change_invalidates_insert_without_other_action(self):
        self.show()
        approvals = []
        copies = []
        regenerations = []
        self.panel.insert_approved.connect(approvals.append)
        self.panel.copy_requested.connect(copies.append)
        self.panel.regenerate_requested.connect(regenerations.append)
        self.guard.current = descriptor(
            top_level_hwnd=200,
            foreground_hwnd=200,
            runtime_id=(99, 1),
            focused_runtime_id=(99, 1),
        )

        self.panel._request_insert()

        self.assertEqual(approvals, [])
        self.assertEqual(copies, [])
        self.assertEqual(regenerations, [])
        self.assertFalse(self.panel._insert_button.isEnabled())
        self.assertIn(
            "destination changed",
            self.panel._status.text(),
        )
        self.assertEqual(
            self.panel._preview.toPlainText(),
            "Tuesday afternoon works for me.",
        )

    def test_cancel_and_close_clear_text_and_emit_no_action(self):
        for close in (False, True):
            with self.subTest(close=close):
                current = self.show()
                actions = []
                cancelled = []
                self.panel.insert_approved.connect(actions.append)
                self.panel.copy_requested.connect(actions.append)
                self.panel.regenerate_requested.connect(actions.append)
                self.panel.cancelled.connect(cancelled.append)

                if close:
                    self.panel.close()
                    self.app.processEvents()
                else:
                    self.panel._cancel()

                self.assertEqual(actions, [])
                self.assertEqual(
                    cancelled[-1:],
                    [current.provenance.run_id],
                )
                self.assertEqual(self.panel._preview.toPlainText(), "")
                self.assertIsNone(self.panel._draft)
                self.assertIsNone(self.panel._target)

    def test_copy_and_regenerate_only_emit_requests(self):
        current = self.show()
        copies = []
        regenerations = []
        approvals = []
        self.panel.copy_requested.connect(copies.append)
        self.panel.regenerate_requested.connect(regenerations.append)
        self.panel.insert_approved.connect(approvals.append)

        self.panel._request_copy()
        self.panel._request_copy()
        self.assertEqual(copies, [current])
        self.assertEqual(approvals, [])
        self.assertFalse(self.panel._copy_button.isEnabled())
        self.panel.set_copy_result(current.provenance.run_id, True)
        self.assertEqual(self.panel._copy_button.text(), "Copied")

        self.panel._request_regenerate()
        self.panel._request_regenerate()
        self.assertEqual(regenerations, [current])
        self.assertFalse(self.panel._insert_button.isEnabled())
        self.assertFalse(self.panel._regenerate_button.isEnabled())
        self.assertIs(self.panel._target, self.guard.lease)
        self.panel.set_regeneration_failed(current.provenance.run_id)
        self.assertTrue(self.panel._insert_button.isEnabled())
        self.assertTrue(self.panel._regenerate_button.isEnabled())
        self.assertFalse(self.panel._copy_button.isEnabled())

    def test_stale_copy_and_regeneration_results_are_ignored(self):
        current = self.show()

        self.panel.set_copy_result("older-run", True)
        self.panel.set_regeneration_failed("older-run")
        self.panel.set_copy_result(current.provenance.run_id, True)
        self.panel.set_regeneration_failed(current.provenance.run_id)

        self.assertEqual(self.panel._copy_button.text(), "Copy")
        self.assertEqual(
            self.panel._regenerate_button.text(),
            "Regenerate",
        )

    def test_mismatched_draft_destination_is_rejected_before_display(self):
        mismatched = draft_for(
            self.guard.lease,
            destination_identity="f" * 64,
        )

        with self.assertRaisesRegex(
            ValueError,
            "does not match",
        ):
            self.panel.show_draft(
                mismatched,
                self.guard.lease,
                self.grant,
            )

        self.assertEqual(self.panel._preview.toPlainText(), "")
        self.assertFalse(self.panel._expiry.isActive())

    def test_target_guard_error_fails_closed(self):
        self.show()
        approvals = []
        self.panel.insert_approved.connect(approvals.append)
        self.guard.revalidate = lambda lease: (_ for _ in ()).throw(
            RuntimeError("private target error")
        )

        self.panel._request_insert()

        self.assertEqual(approvals, [])
        self.assertNotIn(
            "private target error",
            self.panel._status.text(),
        )
        self.assertFalse(self.panel._insert_button.isEnabled())

    def test_preview_has_no_clipboard_insertion_or_process_boundary(self):
        source_path = ROOT / "ui" / "compose_preview.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        imported.update(
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        )

        self.assertFalse(
            {
                "dictation.insertion",
                "dictation.windows_insertion",
                "subprocess",
                "os",
                "ctypes",
            }
            & imported
        )
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn("QApplication.clipboard", source)


if __name__ == "__main__":
    unittest.main()
