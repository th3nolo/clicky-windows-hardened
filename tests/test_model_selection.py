"""Per-provider model restoration and safe fallback tests."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.model_selection import (
    MAX_MODEL_CHOICES,
    model_is_available,
    normalized_model_records,
    resolve_model,
    valid_model_id,
)


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ModelResolutionTests(unittest.TestCase):
    def test_valid_saved_model_is_restored(self):
        records = [
            {"id": "gpt-4o-mini", "vision": True},
            {"id": "gpt-4o", "vision": True},
        ]
        resolution = resolve_model("openai", records, "gpt-4o")
        self.assertEqual(resolution.model_id, "gpt-4o")
        self.assertEqual(resolution.status, "restored")

    def test_removed_model_falls_back_to_reviewed_low_cost_id(self):
        records = [
            {"id": "gpt-4o", "vision": True},
            {"id": "gpt-4o-mini", "vision": True},
        ]
        resolution = resolve_model("openai", records, "removed-model")
        self.assertEqual(resolution.model_id, "gpt-4o-mini")
        self.assertEqual(resolution.status, "stale-fallback")
        self.assertEqual(resolution.previous_model, "removed-model")

    def test_no_reviewed_default_never_chooses_first_expensive_model(self):
        records = [
            {"id": "expensive-model", "vision": True},
            {"id": "another-expensive-model", "vision": True},
        ]
        resolution = resolve_model("openai", records, "removed-model")
        self.assertIsNone(resolution.model_id)
        self.assertEqual(resolution.status, "selection-required")

    def test_copilot_fallback_requires_explicit_zero_multiplier(self):
        records = [
            {"id": "premium", "vision": True, "multiplier": 1},
            {"id": "free-text", "vision": False, "multiplier": 0},
            {"id": "free-vision", "vision": True, "multiplier": 0},
        ]
        self.assertEqual(
            resolve_model("copilot", records, "gone").model_id,
            "free-vision",
        )
        self.assertIsNone(
            resolve_model(
                "copilot",
                [{"id": "premium", "vision": True, "multiplier": 1}],
                "gone",
            ).model_id
        )

    def test_provider_records_are_bounded_sanitized_and_deduplicated(self):
        records = [
            {"id": "ok-model", "label": "Okay", "vision": True},
            {"id": "ok-model", "label": "Duplicate"},
            {"id": "bad model"},
            {"id": "line\nbreak"},
        ]
        records.extend(
            {"id": f"model-{index}"} for index in range(MAX_MODEL_CHOICES + 20)
        )
        normalized = normalized_model_records(records)
        self.assertLessEqual(len(normalized), MAX_MODEL_CHOICES)
        self.assertEqual(normalized[0]["id"], "ok-model")
        self.assertNotIn("bad model", {item["id"] for item in normalized})
        self.assertTrue(model_is_available("ok-model", normalized))
        self.assertFalse(valid_model_id("line\nbreak"))


class ModelPreferenceTests(unittest.TestCase):
    def test_models_persist_independently_per_provider(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("model_preference_config")
            instance = config.Config()
            selections = {
                "claude": "claude-haiku-4-5-20251001",
                "openai": "gpt-4o-mini",
                "gemini": "gemini-2.5-flash",
                "copilot": "gpt-4o-mini",
                "ollama": "qwen2.5vl:7b",
                "lmstudio": "publisher/model-name",
            }
            for provider, model_id in selections.items():
                instance.set_selected_model(provider, model_id)

            restored = config.Config()
            self.assertEqual(
                {
                    provider: restored.selected_model(provider)
                    for provider in selections
                },
                selections,
            )
            payload = json.loads(
                config._preferences_path().read_text(encoding="utf-8")
            )
            self.assertNotEqual(
                payload["preferences"]["claude_model"],
                payload["preferences"]["gemini_model"],
            )

    def test_invalid_model_id_is_not_persisted(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("invalid_model_preference_config")
            instance = config.Config()
            with self.assertRaisesRegex(ValueError, "Invalid"):
                instance.set_selected_model("openai", "model\ninjected")
            self.assertFalse(config._preferences_path().exists())


class ModelSelectionUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def test_removed_model_fallback_is_visible_and_emitted(self):
        from ai import model_registry
        from ui import panel as panel_module

        records = [
            {"id": "gpt-4o", "vision": True},
            {"id": "gpt-4o-mini", "vision": True},
        ]
        with mock.patch.object(
            panel_module.cfg, "llm_provider", return_value="openai"
        ), mock.patch.object(
            panel_module.cfg,
            "selected_model",
            return_value="removed-model",
        ), mock.patch.object(
            model_registry,
            "cached_models",
            return_value=records,
        ):
            panel = panel_module.CompanionPanel()
            emitted = []
            panel.on_model_changed.connect(emitted.append)
            panel.emit_current_model()
            self.assertEqual(emitted, ["gpt-4o-mini"])
            self.assertIn("removed-model", panel.model_selection_notice)
            self.assertIn("gpt-4o-mini", panel.model_selection_notice)
            panel.deleteLater()


if __name__ == "__main__":
    unittest.main()
