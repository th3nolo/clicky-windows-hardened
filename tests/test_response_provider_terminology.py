"""Stable provider IDs with truthful read-only user terminology."""

from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ai.provider_catalog import provider_label


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ResponseProviderTerminologyTests(unittest.TestCase):
    def test_stable_ids_have_truthful_user_labels(self):
        self.assertEqual(
            provider_label("codex_agent"),
            "Codex — read-only response provider",
        )
        self.assertEqual(
            provider_label("qwen_code_agent"),
            "Qwen Code — read-only response provider",
        )

    def test_panel_and_tray_render_the_reviewed_labels(self):
        panel = (ROOT / "ui/panel.py").read_text(encoding="utf-8")
        tray = (ROOT / "ui/tray.py").read_text(encoding="utf-8")
        self.assertIn("PROVIDER_LABELS.get(provider, provider)", panel)
        self.assertIn("display_name = provider_label(name)", tray)

    def test_permissions_and_docs_state_the_response_only_boundary(self):
        privacy = (ROOT / "ui/privacy_consent.py").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        testing = (ROOT / "TESTING.md").read_text(encoding="utf-8")
        combined = "\n".join((privacy, readme, testing))

        self.assertIn("response providers, not Task Agents", combined)
        self.assertIn(
            "cannot edit files, run tools, or perform external actions",
            combined,
        )
        for stale in (
            "Codex agent mode",
            "Qwen Code agent mode",
            "Codex agent and",
            "Qwen Code agent.",
            "Coding-agent boundary",
            "neither agent appears",
        ):
            self.assertNotIn(stale, combined)

    def test_existing_provider_and_model_preferences_still_load(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("response_provider_compatibility_config")
            saved = config.Config()
            saved.set_active_llm("codex_agent")
            saved.set_selected_model("codex_agent", "codex-default")
            saved.set_selected_model(
                "qwen_code_agent",
                "qwen3-coder-plus",
            )

            restored = config.Config()
            self.assertEqual(restored.active_llm, "codex_agent")
            self.assertEqual(restored.codex_agent_model, "codex-default")
            self.assertEqual(
                restored.qwen_code_agent_model,
                "qwen3-coder-plus",
            )


if __name__ == "__main__":
    unittest.main()
