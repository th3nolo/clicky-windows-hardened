"""Consumer Skills Catalog permission-review and hard-off UI tests."""

from __future__ import annotations

import ast
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel

import skills
from skills.registry import (
    SkillEnablementStore,
    SkillKind,
    SkillRegistrationStatus,
    declarative_skill_invocation_allowed,
    load_bundled_declarative_skills,
)
from tests.test_declarative_skill_registry import (
    _definition,
    _write_bundle,
)
from ui.skills_catalog import (
    SkillPermissionReviewDialog,
    SkillsCatalogPanel,
)


ROOT = Path(__file__).resolve().parents[1]


class Reviews:
    def __init__(self, result: str = "accept") -> None:
        self.result = result
        self.calls = []

    def review(self, parent, entry, digest):
        self.calls.append((parent, entry, digest))
        if self.result == "accept":
            return digest
        if self.result == "wrong":
            return "f" * 64
        return None


class SkillsCatalogUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        directory, anchor = _write_bundle(
            self.root / "bundle",
            {"summary.skill.json": _definition()},
        )
        self.snapshot = load_bundled_declarative_skills(
            directory=directory,
            embedded_digests=anchor,
        )
        self.store = SkillEnablementStore(
            self.root / "state" / "skills.json"
        )
        self.reviews = Reviews()
        self.panel = SkillsCatalogPanel(
            self.snapshot,
            self.store,
            developer_skills=skills.load_all(),
            review_gateway=self.reviews,
            task_agent_available=True,
        )

    def tearDown(self):
        self.panel.close()
        self.app.processEvents()
        self.temporary.cleanup()

    def test_catalog_shows_identity_provenance_permissions_and_state(self):
        entry = self.panel.selected_entry()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.kind, SkillKind.DECLARATIVE)
        visible = "\n".join(
            label.text()
            for label in self.panel.findChildren(QLabel)
        )
        for expected in (
            entry.name,
            entry.version,
            entry.publisher_name,
            entry.origin.value,
            "task_agent.run",
            "explicit catalog selection only",
            "Enabled for new invocations: no",
        ):
            self.assertIn(expected, visible)
        self.assertEqual(self.panel._list.count(), 2)
        self.panel._list.setCurrentRow(1)
        developer = self.panel.selected_entry()
        self.assertEqual(developer.kind, SkillKind.DEVELOPER_PYTHON)
        self.assertIn(
            "arbitrary Python",
            self.panel._warning.text(),
        )
        self.assertFalse(self.panel._enable_button.isEnabled())
        self.assertFalse(self.panel._disable_button.isEnabled())

    def test_enable_requires_review_then_disable_blocks_invocation(self):
        entry = self.panel.selected_entry()
        changes = []
        self.panel.skill_enabled_changed.connect(
            lambda skill_id, enabled: changes.append(
                (skill_id, enabled)
            )
        )

        self.panel.enable_selected()

        self.assertEqual(len(self.reviews.calls), 1)
        self.assertTrue(self.store.is_enabled(entry))
        self.assertEqual(changes, [(entry.skill_id, True)])
        self.assertTrue(
            declarative_skill_invocation_allowed(
                self.snapshot,
                self.store,
                entry.skill_id,
                explicit_selection=True,
            )
        )

        self.panel.disable_selected()

        self.assertFalse(self.store.is_enabled(entry))
        self.assertEqual(
            changes,
            [(entry.skill_id, True), (entry.skill_id, False)],
        )
        self.assertFalse(
            declarative_skill_invocation_allowed(
                self.snapshot,
                self.store,
                entry.skill_id,
                explicit_selection=True,
            )
        )
        self.assertIn(
            "disabled immediately",
            self.panel._status.text(),
        )

    def test_cancelled_or_stale_review_never_enables(self):
        entry = self.panel.selected_entry()
        self.reviews.result = "cancel"
        self.panel.enable_selected()
        self.assertFalse(self.store.is_enabled(entry))
        self.assertIn("cancelled", self.panel._status.text())

        self.reviews.result = "wrong"
        self.panel.enable_selected()
        self.assertFalse(self.store.is_enabled(entry))
        self.assertIn("must be reviewed", self.panel._status.text())

    def test_permission_dialog_needs_positive_checkbox(self):
        entry = self.panel.selected_entry()
        dialog = SkillPermissionReviewDialog(entry)
        try:
            self.assertFalse(dialog.permission_confirmed)
            self.assertFalse(dialog._enable_button.isEnabled())
            dialog._confirmed.setChecked(True)
            self.assertTrue(dialog.permission_confirmed)
            self.assertTrue(dialog._enable_button.isEnabled())
            visible = "\n".join(
                label.text()
                for label in dialog.findChildren(QLabel)
            )
            for capability in entry.capabilities:
                self.assertIn(capability.value, visible)
        finally:
            dialog.close()

    def test_hard_off_or_incompatible_skill_cannot_be_enabled(self):
        hard_off = SkillsCatalogPanel(
            self.snapshot,
            self.store,
            review_gateway=self.reviews,
            task_agent_available=False,
        )
        try:
            self.assertFalse(hard_off._enable_button.isEnabled())
            calls = len(self.reviews.calls)
            hard_off.enable_selected()
            self.assertEqual(len(self.reviews.calls), calls)
            self.assertIn("unavailable", hard_off._status.text())
        finally:
            hard_off.close()

        directory, anchor = _write_bundle(
            self.root / "future",
            {
                "future.skill.json": _definition(
                    minimum_clicky_version="2.0.0"
                )
            },
        )
        incompatible = load_bundled_declarative_skills(
            directory=directory,
            embedded_digests=anchor,
        )
        incompatible_panel = SkillsCatalogPanel(
            incompatible,
            SkillEnablementStore(self.root / "future-state.json"),
            review_gateway=self.reviews,
            task_agent_available=True,
        )
        try:
            self.assertEqual(
                incompatible_panel.selected_entry().status,
                SkillRegistrationStatus.DISABLED_INCOMPATIBLE,
            )
            self.assertFalse(
                incompatible_panel._enable_button.isEnabled()
            )
        finally:
            incompatible_panel.close()

    def test_catalog_is_hidden_behind_task_agent_build_gate(self):
        tray_source = (ROOT / "ui" / "tray.py").read_text(
            encoding="utf-8"
        )
        main_source = (ROOT / "main.py").read_text(encoding="utf-8")
        self.assertIn('menu.addAction("Skills…")', tray_source)
        self.assertIn(
            "build_feature_available(ActionCapability.TASK_AGENT)",
            tray_source,
        )
        self.assertIn(
            "if build_feature_available(ActionCapability.TASK_AGENT):",
            main_source,
        )

    def test_catalog_has_no_provider_tool_or_dynamic_code_authority(self):
        source = (ROOT / "ui" / "skills_catalog.py").read_text(
            encoding="utf-8"
        )
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
                "importlib",
                "subprocess",
                "ai.provider_factory",
                "tasks.tool_broker",
                "skills.declarative_runner",
            }
            & imported
        )
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertTrue(
            {"compile", "eval", "exec", "__import__"}.isdisjoint(
                called_names
            )
        )


if __name__ == "__main__":
    unittest.main()
