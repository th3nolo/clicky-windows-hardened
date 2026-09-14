"""Independent original-Clicky routing/persistence checks; no devices or network."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
VOICE = "en-US-Harper:MAI-Voice-2"

class OriginalOpenRouterPreferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {"LOCALAPPDATA":self.temp.name}, clear=True)
        self.env.start(); self.addCleanup(self.env.stop)
        spec = importlib.util.spec_from_file_location("independent_original_voice_config", ROOT / "config.py")
        self.module = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.module)

    def configured(self, **changes):
        values = dict(openrouter_api_key="synthetic-openrouter-key", active_llm="openrouter",
                      openai_api_key="", elevenlabs_api_key="")
        values.update(changes)
        return self.module.Config(**values)

    def test_openrouter_response_selection_uses_its_own_tts(self):
        cfg = self.configured(openai_api_key="synthetic-openai", elevenlabs_api_key="synthetic-elevenlabs")
        self.assertEqual(cfg.tts_provider(), "openrouter")
        self.assertEqual(cfg.get_tts_voice(), VOICE)

    def test_other_selected_provider_preserves_existing_speech_priority(self):
        cfg = self.configured(active_llm="openai", openai_api_key="synthetic-openai", elevenlabs_api_key="synthetic-elevenlabs")
        self.assertEqual(cfg.tts_provider(), "elevenlabs")
        cfg.elevenlabs_api_key = ""
        self.assertEqual(cfg.tts_provider(), "openai")

    def test_missing_openrouter_key_does_not_select_openrouter_tts(self):
        cfg = self.configured(openrouter_api_key="")
        self.assertEqual(cfg.tts_provider(), "edge_tts")

    def test_default_video_opt_in_and_permissions_remain_false(self):
        cfg = self.configured()
        self.assertFalse(cfg.openrouter_voice_video_enabled)
        self.assertFalse(cfg.screen_capture_consent)
        self.assertFalse(cfg.microphone_consent)
        self.assertFalse(cfg.cloud_tts_consent)

    def test_muse_13_response_keeps_muse_12_transcription_role(self):
        from audio.stt.openrouter_stt import OPENROUTER_STT_MODEL
        cfg = self.configured(openrouter_model="meta/muse-spark-1.3-contributor")
        self.assertEqual(cfg.stt_provider(), "openrouter")
        self.assertEqual(OPENROUTER_STT_MODEL, "meta/muse-spark-1.2-contributor")
        self.assertEqual(cfg.selected_model("openrouter"), "meta/muse-spark-1.3-contributor")
        self.assertFalse(cfg.openrouter_voice_video_enabled)

    def test_muse_selection_does_not_override_explicit_local_transcription(self):
        cfg = self.configured(openrouter_model="meta/muse-spark-1.3-contributor",
                              stt_provider_preference="whisper_cpp")
        self.assertEqual(cfg.stt_provider(), "whisper_cpp")

    def test_voice_persistence_keeps_other_provider_voices_and_consent(self):
        cfg = self.configured()
        cfg.set_tts_voice("openai", "coral")
        cfg.set_tts_voice("edge_tts", "en-US-AriaNeural")
        cfg.set_tts_voice("openrouter", VOICE)
        loaded = self.configured()
        self.assertEqual(loaded.get_tts_voice("openrouter"), VOICE)
        self.assertEqual(loaded.get_tts_voice("openai"), "coral")
        self.assertEqual(loaded.get_tts_voice("edge_tts"), "en-US-AriaNeural")
        self.assertFalse(loaded.openrouter_voice_video_enabled)
        self.assertFalse(loaded.cloud_tts_consent)

    def test_unreviewed_openrouter_voice_rejected_without_disk_change(self):
        cfg = self.configured(); cfg.set_tts_voice("openrouter", VOICE)
        path = Path(self.temp.name) / "Clicky/preferences.json"
        before = path.read_bytes()
        with self.assertRaises(ValueError): cfg.set_tts_voice("openrouter", "https://unreviewed.invalid/voice")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(cfg.get_tts_voice("openrouter"), VOICE)

    def test_video_opt_in_persists_separately_without_granting_permissions(self):
        self.module._save_preferences(openrouter_voice_video_enabled=True)
        loaded = self.configured()
        self.assertTrue(loaded.openrouter_voice_video_enabled)
        self.assertFalse(loaded.screen_capture_consent)
        self.assertFalse(loaded.microphone_consent)
        self.assertFalse(loaded.cloud_tts_consent)
        self.module._save_preferences(openrouter_voice_video_enabled=False)
        self.assertFalse(self.configured().openrouter_voice_video_enabled)

    def test_tampered_flag_and_voice_fail_closed_on_reload(self):
        path = Path(self.temp.name) / "Clicky/preferences.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({"version":1,"preferences":{
            "openrouter_voice_video_enabled":"true", "openrouter_tts_voice_id":"unreviewed"}}))
        loaded = self.configured()
        self.assertFalse(loaded.openrouter_voice_video_enabled)
        self.assertEqual(loaded.get_tts_voice("openrouter"), VOICE)

    def test_persistence_failure_does_not_mutate_selected_voice(self):
        cfg = self.configured(); before = cfg.openrouter_tts_voice_id
        with patch.object(self.module, "_save_preferences", side_effect=OSError("synthetic storage failure")):
            with self.assertRaises(OSError): cfg.set_tts_voice("openrouter", "es-MX-Valeria:MAI-Voice-2")
        self.assertEqual(cfg.openrouter_tts_voice_id, before)

if __name__ == "__main__": unittest.main()
