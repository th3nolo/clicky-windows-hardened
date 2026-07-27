"""Focused regressions for provider transport and voice privacy fixes."""

from __future__ import annotations

import ast
import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str, modules: dict[str, types.ModuleType]):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with mock.patch.dict(sys.modules, modules):
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def provider_modules(cfg) -> dict[str, types.ModuleType]:
    config = types.ModuleType("config")
    config.cfg = cfg
    base = types.ModuleType("ai.base_provider")
    base.BaseLLMProvider = object
    base.Message = object
    ai = types.ModuleType("ai")
    ai.__path__ = []
    return {"config": config, "ai": ai, "ai.base_provider": base}


class FakeResponse:
    def __init__(self, *, lines=(), payload=None, status_code=200):
        self._lines = list(lines)
        self._payload = payload or {}
        self.status_code = status_code

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def raise_for_status(self):
        return None

    async def aiter_lines(self):
        for line in self._lines:
            yield line

    def json(self):
        return self._payload


class RecordingAsyncClient:
    init_calls: list[dict] = []
    request_calls: list[tuple[str, str, dict]] = []
    stream_response = FakeResponse()
    get_response = FakeResponse()

    def __init__(self, **kwargs):
        self.init_calls.append(kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def stream(self, method, url, **kwargs):
        self.request_calls.append((method, url, kwargs))
        return self.stream_response

    async def get(self, url, **kwargs):
        self.request_calls.append(("GET", url, kwargs))
        return self.get_response


def fake_httpx(client_type=RecordingAsyncClient) -> types.ModuleType:
    module = types.ModuleType("httpx")
    module.AsyncClient = client_type
    module.ConnectError = OSError
    return module


class GeminiKeyTransportTests(unittest.TestCase):
    def setUp(self):
        RecordingAsyncClient.init_calls = []
        RecordingAsyncClient.request_calls = []

    def test_generation_and_health_use_header_not_query(self):
        RecordingAsyncClient.stream_response = FakeResponse(lines=[
            'data: {"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}',
        ])
        RecordingAsyncClient.get_response = FakeResponse(status_code=200)
        cfg = types.SimpleNamespace(google_api_key="top-secret")
        modules = provider_modules(cfg)
        modules["httpx"] = fake_httpx()
        gemini = load_module(
            "provider_security_gemini", "ai/gemini_provider.py", modules
        )

        async def exercise():
            provider = gemini.GeminiProvider()
            chunks = [
                chunk
                async for chunk in provider.stream_response(
                    "hello", [], [], "system"
                )
            ]
            healthy = await provider.health_check()
            return chunks, healthy

        chunks, healthy = asyncio.run(exercise())
        self.assertEqual(chunks, ["ok"])
        self.assertTrue(healthy)
        self.assertEqual(len(RecordingAsyncClient.request_calls), 2)
        for _method, url, kwargs in RecordingAsyncClient.request_calls:
            self.assertNotIn("top-secret", url)
            self.assertNotIn("key=", url)
            self.assertEqual(
                kwargs["headers"], {"x-goog-api-key": "top-secret"}
            )

    def test_model_registry_uses_header_not_query(self):
        RecordingAsyncClient.get_response = FakeResponse(payload={"models": [{
            "name": "models/gemini-2.5-flash",
            "displayName": "Gemini 2.5 Flash",
            "supportedGenerationMethods": ["generateContent"],
        }]})
        cfg = types.SimpleNamespace(google_api_key="registry-secret")
        config = types.ModuleType("config")
        config.cfg = cfg
        provider_catalog = types.ModuleType("ai.provider_catalog")
        provider_catalog.OPENAI_COMPATIBLE_SPECS = {}
        modules = {
            "config": config,
            "httpx": fake_httpx(),
            "ai.provider_catalog": provider_catalog,
        }
        registry = load_module(
            "provider_security_registry", "ai/model_registry.py", modules
        )

        models = asyncio.run(registry._fetch_gemini())
        self.assertEqual(models[0]["id"], "gemini-2.5-flash")
        _method, url, kwargs = RecordingAsyncClient.request_calls[-1]
        self.assertNotIn("registry-secret", url)
        self.assertNotIn("key=", url)
        self.assertNotIn("params", kwargs)
        self.assertEqual(
            kwargs["headers"], {"x-goog-api-key": "registry-secret"}
        )


class LMStudioTransportTests(unittest.TestCase):
    def setUp(self):
        RecordingAsyncClient.init_calls = []
        RecordingAsyncClient.request_calls = []

    def test_every_client_ignores_environment_proxies_and_redirects(self):
        RecordingAsyncClient.stream_response = FakeResponse(lines=[
            'data: {"choices":[{"delta":{"content":"ok"}}]}',
            "data: [DONE]",
        ])
        RecordingAsyncClient.get_response = FakeResponse(
            payload={"data": [{"id": "local"}]}, status_code=200
        )
        cfg = types.SimpleNamespace(
            lmstudio_host="http://127.0.0.1:1234/v1",
            lmstudio_model="local",
        )
        modules = provider_modules(cfg)
        modules["httpx"] = fake_httpx()
        lmstudio = load_module(
            "provider_security_lmstudio", "ai/lmstudio_provider.py", modules
        )

        async def exercise():
            provider = lmstudio.LMStudioProvider()
            chunks = [
                chunk
                async for chunk in provider.stream_response(
                    "hello", [], [], "system"
                )
            ]
            return chunks, await provider.health_check(), await provider.list_models()

        chunks, healthy, models = asyncio.run(exercise())
        self.assertEqual((chunks, healthy, models), (["ok"], True, ["local"]))
        self.assertEqual(len(RecordingAsyncClient.init_calls), 3)
        for kwargs in RecordingAsyncClient.init_calls:
            self.assertIs(kwargs["trust_env"], False)
            self.assertIs(kwargs["follow_redirects"], False)


class TranscriptLoggingTests(unittest.TestCase):
    def test_transcript_content_never_reaches_a_log_call(self):
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        leaking_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in {
                "debug", "info", "warning", "error", "exception", "critical"
            }:
                continue
            if any(
                isinstance(child, ast.Name) and child.id == "transcript"
                for arg in node.args
                for child in ast.walk(arg)
            ):
                leaking_calls.append(node.lineno)
        self.assertEqual(leaking_calls, [])


class TierThreeFallbackTests(unittest.TestCase):
    def _load_hybrid(self, detector):
        ai = types.ModuleType("ai")
        ai.__path__ = []
        locator = types.ModuleType("ai.element_locator")
        locator.detect_element = detector
        modules = {"ai": ai, "ai.element_locator": locator}
        hybrid = load_module(
            "provider_security_hybrid", "ai/hybrid_pointer.py", modules
        )
        return hybrid, modules

    def test_tier_three_calls_async_detector_with_screenshot_contract(self):
        calls = []

        async def detect_element(**kwargs):
            calls.append(kwargs)
            return types.SimpleNamespace(x=321, y=654)

        hybrid, modules = self._load_hybrid(detect_element)
        screenshot = types.SimpleNamespace(
            base64_jpeg="jpeg-b64",
            width=1280,
            height=720,
            physical_width=2560,
            physical_height=1440,
            physical_left=-2560,
            physical_top=0,
            dpi_scale=1.5,
            index=2,
        )
        with mock.patch.dict(sys.modules, modules):
            target = hybrid.find_target(
                "save button",
                screenshot=screenshot,
                llm_provider=object(),
                skip_uia=True,
                skip_ocr=True,
            )

        self.assertEqual(target.center_xy, (321, 654))
        self.assertEqual(target.source, "vision")
        self.assertEqual(calls, [{
            "screenshot_jpeg_b64": "jpeg-b64",
            "original_width": 1280,
            "original_height": 720,
            "physical_width": 2560,
            "physical_height": 1440,
            "physical_left": -2560,
            "physical_top": 0,
            "dpi_scale": 1.5,
            "screen_index": 2,
            "user_question": "save button",
        }])

    def test_tier_three_refuses_to_block_a_running_event_loop(self):
        calls = []

        async def detect_element(**_kwargs):
            calls.append(_kwargs)
            return types.SimpleNamespace(x=10, y=20)

        hybrid, modules = self._load_hybrid(detect_element)
        screenshot = types.SimpleNamespace(
            base64_jpeg="jpeg-b64",
            width=1,
            height=1,
            physical_width=1,
            physical_height=1,
            physical_left=0,
            physical_top=0,
            dpi_scale=1.0,
            index=1,
        )

        async def exercise():
            with mock.patch.dict(sys.modules, modules):
                with self.assertRaisesRegex(
                    RuntimeError, "cannot run inside an active asyncio event loop"
                ):
                    hybrid.find_target(
                        "target",
                        screenshot=screenshot,
                        llm_provider=object(),
                        skip_uia=True,
                        skip_ocr=True,
                    )

        asyncio.run(exercise())
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
