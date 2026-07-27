"""Explicit writing-style manager and pre-compose picker tests."""

from __future__ import annotations

import ast
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox

from memory.style_profiles import StyleProfileStore
from ui.style_profiles import (
    ComposeStyleProfilePicker,
    StyleProfilesPanel,
)


ROOT = Path(__file__).resolve().parents[1]
WORK_APP = hashlib.sha256(b"c:\\work\\mail.exe").hexdigest()
NOTES_APP = hashlib.sha256(b"c:\\personal\\notes.exe").hexdigest()


class SyntheticProtector:
    def encrypt(self, plaintext: bytes) -> bytes:
        return b"UI\x00" + bytes(value ^ 0xC3 for value in plaintext)

    def decrypt(self, protected: bytes) -> bytes:
        if not protected.startswith(b"UI\x00"):
            raise OSError("invalid synthetic payload")
        return bytes(value ^ 0xC3 for value in protected[3:])


class Clock:
    def __init__(self):
        self.value = 1_800_000_000.0

    def __call__(self):
        self.value += 1.0
        return self.value


class Files:
    def __init__(self):
        self.saved = None
        self.to_open = None
        self.save_calls = 0
        self.open_calls = 0

    def save(self, parent, suggested_name, payload):
        self.save_calls += 1
        self.saved = payload
        return True

    def open(self, parent):
        self.open_calls += 1
        return self.to_open


def store_for(root: Path, start=1) -> StyleProfileStore:
    identifiers = iter(
        f"{number:032x}" for number in range(start, start + 32)
    )
    return StyleProfileStore(
        root / "styles.db",
        _protector=SyntheticProtector(),
        _clock=Clock(),
        _id_factory=lambda: next(identifiers),
    )


class StyleProfilesUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = store_for(self.root)
        self.files = Files()
        self.panel = StyleProfilesPanel(
            self.store,
            file_gateway=self.files,
        )

    def tearDown(self):
        self.panel.close()
        self.app.processEvents()
        self.temporary.cleanup()

    def create_profile(self, *, scoped=False):
        self.panel.new_profile()
        if scoped:
            self.panel.set_application_context(
                "Synthetic Mail",
                WORK_APP,
            )
            self.panel._scope_current.setChecked(True)
        self.panel._name.setText("Concise work style")
        self.panel._rules.setPlainText(
            "Use active voice.\nLead with the outcome."
        )
        self.panel._examples.setPlainText(
            "Tuesday afternoon works for me."
        )
        self.panel.save_profile()
        profile = self.store.get(self.panel.selected_profile_id)
        self.assertIsNotNone(profile)
        return profile

    def test_create_edit_disable_and_delete_are_explicit(self):
        profile = self.create_profile(scoped=True)

        self.assertEqual(profile.application_scopes, (WORK_APP,))
        self.assertEqual(
            profile.rules,
            ("Use active voice.", "Lead with the outcome."),
        )
        self.panel._name.setText("Updated work style")
        self.panel._enabled.setChecked(False)
        self.panel.save_profile()
        updated = self.store.get(profile.profile_id)
        self.assertEqual(updated.name, "Updated work style")
        self.assertFalse(updated.enabled)

        with mock.patch.object(
            QMessageBox,
            "question",
            return_value=QMessageBox.StandardButton.Yes,
        ):
            self.panel.delete_profile()

        self.assertIsNone(self.store.get(profile.profile_id))
        self.assertIn("deleted", self.panel._status.text().lower())

    def test_export_and_import_require_their_buttons(self):
        profile = self.create_profile()
        self.assertEqual(self.files.save_calls, 0)
        self.assertEqual(self.files.open_calls, 0)

        self.panel.export_profile()

        self.assertEqual(self.files.save_calls, 1)
        self.assertIsNotNone(self.files.saved)
        second_root = self.root / "second"
        second = store_for(second_root, start=100)
        import_files = Files()
        import_files.to_open = self.files.saved
        imported_panel = StyleProfilesPanel(
            second,
            file_gateway=import_files,
        )
        try:
            imported_panel.import_profiles()
            imported = second.get(profile.profile_id)
            self.assertEqual(imported.name, profile.name)
            self.assertEqual(import_files.open_calls, 1)
        finally:
            imported_panel.close()

    def test_application_default_and_profile_switch_are_visible_before_confirm(self):
        profile = self.create_profile()
        self.panel.set_application_context("Synthetic Mail", WORK_APP)
        self.panel.set_application_default()
        self.assertIn(profile.name, self.panel._default.text())

        picker = ComposeStyleProfilePicker(self.store)
        confirmations = []
        picker.selection_confirmed.connect(confirmations.append)
        try:
            picker.set_application_context("Synthetic Mail", WORK_APP)
            self.assertEqual(
                picker.selected_profile_id,
                profile.profile_id,
            )
            self.assertIn("Synthetic Mail", picker._application.text())
            self.assertIn(profile.name, picker._summary.text())
            self.assertEqual(confirmations, [])

            picker._profile.setCurrentIndex(0)
            self.assertIsNone(picker.selected_profile_id)
            self.assertIn(
                "no writing style",
                picker._summary.text().lower(),
            )
            picker._confirm()
            self.assertEqual(confirmations, [None])

            picker.set_application_context("Personal Notes", NOTES_APP)
            self.assertIn("Personal Notes", picker._application.text())
            self.assertIsNone(picker.selected_profile_id)
            self.assertIn(
                "no writing style",
                picker._summary.text().lower(),
            )
        finally:
            picker.close()

    def test_ui_has_no_passive_context_or_generation_authority(self):
        source_path = ROOT / "ui" / "style_profiles.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            (
                node.module
                if isinstance(node, ast.ImportFrom)
                else alias.name
            )
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }

        self.assertFalse(
            {
                "email",
                "subprocess",
                "screen.capture",
                "clipboard",
                "companion_manager",
                "compose.service",
                "ai.provider_factory",
            }
            & imported
        )
        for forbidden in (
            "QApplication.clipboard",
            "stream_response",
        ):
            self.assertNotIn(forbidden, source)
        visible_text = " ".join(
            label.text()
            for label in self.panel.findChildren(QLabel)
        )
        self.assertIn(
            "never learns a style "
            "from email, files, screenshots, clipboard, or conversation history",
            visible_text,
        )

    def test_manager_is_hidden_behind_the_compose_build_gate(self):
        tray_source = (ROOT / "ui" / "tray.py").read_text(
            encoding="utf-8"
        )
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")

        self.assertIn('menu.addAction("Writing styles…")', tray_source)
        self.assertIn(
            "build_feature_available(\n"
            "            ActionCapability.SCREEN_AWARE_COMPOSE",
            tray_source,
        )
        self.assertIn(
            "if build_feature_available("
            "ActionCapability.SCREEN_AWARE_COMPOSE):",
            main_source,
        )


if __name__ == "__main__":
    unittest.main()
