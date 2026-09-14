"""First-run provider choice without live profiles, local servers, or downloads."""

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication

from tests.provider_test_support import load_config


ROOT = Path(__file__).resolve().parents[1]


class AutomaticProviderTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(mock.patch.dict(os.environ, {"LOCALAPPDATA": directory}, clear=True))
        self.module = load_config("onboarding_config_test")
        self.cfg = self.module.Config()
        copilot = types.ModuleType("ai.github_copilot_provider")
        copilot.is_authenticated = mock.Mock(return_value=False)
        self.enterContext(mock.patch.dict(sys.modules, {"ai.github_copilot_provider": copilot}))
        self.enterContext(mock.patch.object(self.module.shutil, "which", return_value=None))

    def test_only_openrouter_key_selects_openrouter(self):
        self.cfg.openrouter_api_key = "synthetic"
        self.assertEqual(self.cfg.active_llm, "")
        self.assertEqual(self.cfg.llm_provider(), "openrouter")

    def test_other_configured_api_providers_are_not_skipped(self):
        for attribute, provider in (
            ("kimi_code_api_key", "kimi_code"),
            ("minimax_api_key", "minimax_plan"),
            ("deepseek_api_key", "deepseek"),
            ("dashscope_api_key", "qwen"),
        ):
            with self.subTest(provider=provider):
                self.cfg = self.module.Config()
                setattr(self.cfg, attribute, "synthetic")
                self.assertEqual(self.cfg.llm_provider(), provider)

    def test_explicit_local_selection_is_preserved_with_cloud_key(self):
        self.cfg.openrouter_api_key = "synthetic"
        for provider in ("ollama", "lmstudio"):
            with self.subTest(provider=provider):
                self.cfg.active_llm = provider
                self.assertEqual(self.cfg.llm_provider(), provider)

    def test_existing_priority_and_explicit_cloud_selection_are_preserved(self):
        self.cfg.anthropic_api_key = "synthetic"
        self.cfg.openai_api_key = "synthetic"
        self.cfg.openrouter_api_key = "synthetic"
        self.assertEqual(self.cfg.llm_provider(), "claude")
        self.cfg.active_llm = "openrouter"
        self.assertEqual(self.cfg.llm_provider(), "openrouter")
        self.cfg.active_llm = "unavailable"
        self.cfg.anthropic_api_key = None
        self.assertEqual(self.cfg.llm_provider(), "openai")

    def test_coding_cli_requires_explicit_selection(self):
        self.cfg.privacy_consent_version = self.module.PRIVACY_NOTICE_VERSION
        self.cfg.coding_agent_consent = True
        with mock.patch.object(self.module.shutil, "which", return_value="synthetic-codex"):
            self.assertIn("codex_agent", self.cfg.available_llm_providers())
            self.assertEqual(self.cfg.llm_provider(), "ollama")
            self.cfg.active_llm = "codex_agent"
            self.assertEqual(self.cfg.llm_provider(), "codex_agent")

    def test_selected_muse_12_can_use_matching_audio_without_second_key(self):
        self.cfg.openrouter_api_key = "synthetic"
        self.cfg.active_llm = "openrouter"
        self.cfg.openrouter_model = "meta/muse-spark-1.2-contributor"
        self.assertEqual(self.cfg.stt_provider(), "openrouter")
        self.assertIn("openrouter", self.cfg.available_stt_providers())
        self.assertEqual(self.cfg.describe()["stt_mode"], "cloud batch")
        self.assertFalse(self.cfg.microphone_consent)
        self.assertFalse(self.cfg.cloud_stt_consent)

    def test_openrouter_audio_auto_selection_requires_matching_response_model(self):
        self.cfg.openrouter_api_key = "synthetic"
        self.cfg.active_llm = "openrouter"
        for model in ("", "meta/muse-spark-contributor", "synthetic/other-model"):
            with self.subTest(model=model):
                self.cfg.openrouter_model = model
                self.assertIn(self.cfg.stt_provider(), ("whisper_cpp", "faster_whisper"))
        self.cfg.openrouter_model = "meta/muse-spark-1.2-contributor"
        self.cfg.active_llm = "ollama"
        self.assertIn(self.cfg.stt_provider(), ("whisper_cpp", "faster_whisper"))

    def test_openrouter_audio_does_not_override_selected_speech_or_existing_defaults(self):
        self.cfg.openrouter_api_key = "synthetic"
        self.cfg.active_llm = "openrouter"
        self.cfg.openrouter_model = "meta/muse-spark-1.2-contributor"
        for choice in ("whisper_cpp", "faster_whisper", "deepgram_batch", "openai"):
            with self.subTest(choice=choice):
                self.cfg.stt_provider_preference = choice
                self.assertEqual(self.cfg.stt_provider(), choice)
        self.cfg.stt_provider_preference = ""
        self.cfg.deepgram_api_key = "synthetic"
        self.assertEqual(self.cfg.stt_provider(), "deepgram")
        self.cfg.deepgram_api_key = None
        self.cfg.openai_speech_api_key = "synthetic"
        self.assertEqual(self.cfg.stt_provider(), "openai")

    def test_openrouter_audio_can_be_explicitly_selected_and_requires_key(self):
        self.assertNotIn("openrouter", self.cfg.available_stt_providers())
        with self.assertRaises(ValueError):
            self.cfg.set_stt_provider("openrouter")
        self.cfg.openrouter_api_key = "synthetic"
        with mock.patch.object(self.module, "_save_preferences") as save:
            self.cfg.set_stt_provider("openrouter")
            save.assert_called_once_with(stt_provider="openrouter")
        self.assertEqual(self.cfg.stt_provider(), "openrouter")


class SetupProviderFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])

    def setUp(self):
        import ai

        self.cfg = types.SimpleNamespace(
            llm_provider=mock.Mock(return_value="ollama"),
            hotkey="ctrl+shift+space",
            ollama_text_model="text-model",
            ollama_text_model_digest="a" * 64,
            ollama_vision_model="vision-model",
            ollama_vision_model_digest="b" * 64,
        )
        config = types.ModuleType("config")
        config.cfg = self.cfg
        self.bootstrap = types.ModuleType("ai.ollama_bootstrap")
        self.bootstrap.is_ollama_running = mock.Mock(return_value=False)
        self.bootstrap.is_model_installed = mock.Mock(return_value=False)
        self.bootstrap.installation_guidance = mock.Mock(return_value="Manual setup")
        self.bootstrap.model_guidance = mock.Mock(return_value="Manual model provisioning")
        spec = importlib.util.spec_from_file_location("setup_provider_flow_subject", ROOT / "ui/setup_wizard.py")
        self.module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"config": config, "ai.ollama_bootstrap": self.bootstrap}), \
                mock.patch.object(ai, "ollama_bootstrap", self.bootstrap, create=True):
            spec.loader.exec_module(self.module)
        self.flag = self.enterContext(mock.patch.object(self.module, "setup_already_ran", return_value=False))
        self.mark = self.enterContext(mock.patch.object(self.module, "mark_setup_complete"))

    def wizard(self, **kwargs):
        wizard = self.module.SetupWizard(**kwargs)
        self.addCleanup(wizard.close)
        return wizard

    def test_cloud_selection_does_not_touch_local_flag_or_server(self):
        self.cfg.llm_provider.return_value = "openrouter"
        self.assertIsNone(self.module.maybe_show_setup_wizard())
        self.flag.assert_not_called()
        self.bootstrap.is_ollama_running.assert_not_called()
        self.mark.assert_not_called()

    def test_explicit_ollama_still_gets_manual_provisioning(self):
        wizard = self.module.maybe_show_setup_wizard()
        self.addCleanup(wizard.close)
        self.assertEqual(wizard._step, "intro")
        self.assertIn("Install Ollama", wizard.title.text())

    def test_cloud_manual_setup_explains_configured_state(self):
        self.cfg.llm_provider.return_value = "openrouter"
        wizard = self.wizard()
        self.assertIn("OpenRouter", wizard.title.text())
        self.assertIn("not necessarily been connection-tested", wizard.subtitle.text())
        self.bootstrap.is_ollama_running.assert_not_called()

    def test_intro_and_missing_text_skip_handoff_once(self):
        for step in ("intro", "text_model"):
            with self.subTest(step=step):
                handoff = mock.Mock()
                wizard = self.wizard(on_choose_provider=handoff)
                wizard._set_step(step)
                wizard.show()
                wizard.skip_btn.click()
                handoff.assert_called_once_with()
                self.assertFalse(wizard.isVisible())
                self.assertNotEqual(wizard._step, "done")

    def test_skip_without_handoff_shows_actionable_guidance(self):
        wizard = self.wizard()
        wizard._set_step("text_model")
        wizard.show()
        wizard.skip_btn.click()
        self.assertTrue(wizard.isVisible())
        self.assertEqual(wizard._step, "provider_choice")
        self.assertIn("OPENROUTER_API_KEY", wizard.status.text())
        self.mark.assert_not_called()

    def test_verified_text_can_skip_optional_vision_without_global_ready_claim(self):
        self.bootstrap.is_ollama_running.return_value = True
        self.bootstrap.is_model_installed.side_effect = [True, False]
        wizard = self.wizard()
        wizard.action_btn.click()
        self.assertEqual(wizard._step, "vision_model")
        self.bootstrap.is_model_installed.assert_any_call("text-model", "a" * 64, "OLLAMA_TEXT_MODEL_DIGEST")
        wizard.skip_btn.click()
        self.assertEqual(wizard._step, "done")
        self.assertIn("text model detected", wizard.title.text())
        self.assertNotIn("Clicky is ready", wizard.subtitle.text())
        self.mark.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
