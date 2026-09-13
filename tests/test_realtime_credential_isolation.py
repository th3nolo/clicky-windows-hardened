"""Exercise the real Realtime caller with synthetic credentials and no devices."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock


ROOT = Path(__file__).resolve().parents[1]


def realtime_start(config):
    tree = ast.parse((ROOT / "companion_manager.py").read_text(encoding="utf-8"))
    manager = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name == "CompanionManager")
    method = next(node for node in manager.body if isinstance(node, ast.AsyncFunctionDef)
                  and node.name == "_start_realtime_voice")
    namespace = {"cfg": config, "microphone_allowed": lambda _: False}
    exec(compile(ast.Module(body=[method], type_ignores=[]), "companion_manager.py", "exec"), namespace)
    return namespace[method.name]


class RealtimeCredentialIsolationTests(unittest.TestCase):
    def run_start(self, *, chat_key, speech_key, base_url):
        config = SimpleNamespace(
            openai_api_key=chat_key, openai_speech_api_key=speech_key,
            openai_base_url=base_url, realtime_voice_enabled=True,
            microphone_consent=True, cloud_stt_consent=True, cloud_tts_consent=True,
            mic_device_index=None, realtime_output_device_index=None,
        )
        controller = SimpleNamespace(start=AsyncMock())
        manager = SimpleNamespace(
            _realtime_stopping=False, _realtime_controller=controller,
            _realtime_future=object(), sig_realtime_transcript=SimpleNamespace(emit=Mock()),
            sig_realtime_status=SimpleNamespace(emit=Mock()), sig_error=SimpleNamespace(emit=Mock()),
        )
        return realtime_start(config), controller, manager

    def test_custom_chat_key_is_rejected_before_realtime_transport(self):
        start, controller, manager = self.run_start(
            chat_key="dummy-router-key", speech_key=None, base_url="http://127.0.0.1:8000/v1",
        )
        with self.assertRaisesRegex(RuntimeError, "OPENAI_SPEECH_API_KEY"):
            asyncio.run(start(manager, controller))
        controller.start.assert_not_awaited()
        self.assertIsNone(manager._realtime_controller)

    def test_speech_key_is_used_with_custom_chat_router(self):
        start, controller, manager = self.run_start(
            chat_key="dummy-router-key", speech_key="dummy-speech-key",
            base_url="http://127.0.0.1:8000/v1",
        )
        asyncio.run(start(manager, controller))
        self.assertEqual(controller.start.await_args.kwargs["api_key"], "dummy-speech-key")

    def test_official_openai_chat_key_remains_compatible(self):
        start, controller, manager = self.run_start(
            chat_key="dummy-openai-key", speech_key=None, base_url="",
        )
        asyncio.run(start(manager, controller))
        self.assertEqual(controller.start.await_args.kwargs["api_key"], "dummy-openai-key")

    def test_speech_only_key_does_not_require_chat_credentials(self):
        start, controller, manager = self.run_start(
            chat_key=None, speech_key="dummy-speech-key", base_url="",
        )
        asyncio.run(start(manager, controller))
        self.assertEqual(controller.start.await_args.kwargs["api_key"], "dummy-speech-key")


if __name__ == "__main__":
    unittest.main()
