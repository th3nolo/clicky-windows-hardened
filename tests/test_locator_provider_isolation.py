"""The live locator caller must honor the selected provider after a local miss."""

import asyncio
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch


import companion_manager as manager_module
from companion_manager import CompanionManager
from ai.response_selection import ProviderIdentity, ResponseDispatch, ResponseSelection


class LocatorProviderIsolationTests(unittest.TestCase):
    def locate(self, provider):
        modules = {name: ModuleType(name) for name in (
            "ai.hybrid_pointer", "ai.element_locator", "ai.universal_locator",
        )}
        modules["ai.hybrid_pointer"].find_target = Mock(return_value=None)
        anthropic = modules["ai.element_locator"].detect_element = AsyncMock(return_value=None)
        selected = modules["ai.universal_locator"].detect_element_universal = AsyncMock(return_value=None)
        llm = object()
        host = SimpleNamespace(_get_llm=lambda: llm, _current_model="selected-model",
                               _acquire_response_dispatch=lambda: ResponseDispatch(
                                   ResponseSelection(ProviderIdentity(provider, "synthetic"), "selected-model", 1), llm),
                               _turns=SimpleNamespace(is_current=lambda _: True))
        shot = SimpleNamespace(base64_jpeg="synthetic-image", width=100, height=100,
                               physical_width=100, physical_height=100, physical_left=0,
                               physical_top=0, dpi_scale=1, logical_left=0, logical_top=0,
                               logical_width=100, logical_height=100, index=0)
        with patch.dict("sys.modules", modules), patch.object(
            manager_module, "cfg", SimpleNamespace(anthropic_api_key="dummy-anthropic-key"),
        ):
            asyncio.run(CompanionManager._locate_question_target(host, "where", shot, object()))
        return anthropic, selected, llm

    def test_unrelated_anthropic_key_does_not_change_selected_recipient(self):
        for provider in ("openrouter", "openai", "ollama", "lmstudio", "qwen", "deepseek"):
            with self.subTest(provider=provider):
                anthropic, selected, llm = self.locate(provider)
                anthropic.assert_not_awaited()
                selected.assert_awaited_once()
                self.assertIs(selected.await_args.kwargs["llm"], llm)
                self.assertEqual(selected.await_args.kwargs["model"], "selected-model")

    def test_selected_anthropic_uses_selected_model(self):
        anthropic, selected, _ = self.locate("claude")
        anthropic.assert_awaited_once()
        selected.assert_not_awaited()
        self.assertEqual(anthropic.await_args.kwargs["model"], "selected-model")


if __name__ == "__main__":
    unittest.main()
