"""Security and wiring regressions for plan providers and coding agents."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from ai.base_provider import Message
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
from privacy_controls import PRIVACY_NOTICE_VERSION


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class ProviderCatalogTests(unittest.TestCase):
    def test_cloud_destinations_are_fixed_reviewed_https_urls(self):
        self.assertEqual(
            {
                provider: spec.base_url
                for provider, spec in OPENAI_COMPATIBLE_SPECS.items()
            },
            {
                "kimi_code": "https://api.kimi.com/coding/v1",
                "minimax_plan": "https://api.minimax.io/v1",
                "deepseek": "https://api.deepseek.com",
                "qwen": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
            },
        )

    def test_keys_enable_only_their_provider_and_never_persist(self):
        keys = {
            "KIMI_CODE_API_KEY": "kimi-secret",
            "MINIMAX_API_KEY": "minimax-secret",
            "DEEPSEEK_API_KEY": "deepseek-secret",
            "DASHSCOPE_API_KEY": "qwen-secret",
            "BAILIAN_CODING_PLAN_API_KEY": "plan-secret",
        }
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary, **keys},
            clear=True,
        ):
            config = load_config("extended_provider_config")
            instance = config.Config()
            self.assertEqual(
                instance.available_llm_providers()[:4],
                ["kimi_code", "minimax_plan", "deepseek", "qwen"],
            )
            self.assertNotIn("codex_agent", instance.available_llm_providers())
            instance.set_privacy_permissions(
                microphone=False,
                cloud_stt=False,
                cloud_tts=False,
                screen_capture=False,
                coding_agent=True,
                notice_version=PRIVACY_NOTICE_VERSION,
            )
            with mock.patch.object(
                config.shutil,
                "which",
                side_effect=lambda name: f"C:/tools/{name}.exe",
            ):
                available = instance.available_llm_providers()
            self.assertIn("codex_agent", available)
            self.assertIn("qwen_code_agent", available)
            payload = config._preferences_path().read_text(encoding="utf-8")
            for secret in keys.values():
                self.assertNotIn(secret, payload)


class FakeStream:
    def __init__(self):
        self.closed = False
        self._chunks = [
            types.SimpleNamespace(
                choices=[
                    types.SimpleNamespace(
                        delta=types.SimpleNamespace(content="hello")
                    )
                ]
            )
        ]

    def __aiter__(self):
        self._iterator = iter(self._chunks)
        return self

    async def __anext__(self):
        try:
            return next(self._iterator)
        except StopIteration as exc:
            raise StopAsyncIteration from exc

    async def close(self):
        self.closed = True


class FakeCompletions:
    def __init__(self, stream):
        self.stream = stream
        self.calls = []

    async def create(self, **kwargs):
        self.calls.append(kwargs)
        return self.stream


class FakeOpenAIClient:
    init_calls = []

    def __init__(self, **kwargs):
        self.init_calls.append(kwargs)
        self.stream = FakeStream()
        self.chat = types.SimpleNamespace(
            completions=FakeCompletions(self.stream)
        )
        self.models = types.SimpleNamespace(list=self._models)

    async def _models(self):
        return []


class FakeHTTPClient:
    calls = []

    def __init__(self, **kwargs):
        self.calls.append(kwargs)


class OpenAICompatibleTransportTests(unittest.TestCase):
    def test_every_provider_uses_only_catalog_url_and_proxy_free_client(self):
        FakeOpenAIClient.init_calls = []
        FakeHTTPClient.calls = []
        fake_openai = types.ModuleType("openai")
        fake_openai.AsyncOpenAI = FakeOpenAIClient
        fake_httpx = types.ModuleType("httpx")
        fake_httpx.AsyncClient = FakeHTTPClient
        fake_httpx.Timeout = lambda *args, **kwargs: (args, kwargs)
        spec = importlib.util.spec_from_file_location(
            "extended_openai_compatible_provider",
            ROOT / "ai" / "openai_compatible_provider.py",
        )
        assert spec and spec.loader
        provider_module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(
            sys.modules,
            {"openai": fake_openai, "httpx": fake_httpx},
        ):
            spec.loader.exec_module(provider_module)

        async def exercise(provider_id):
            provider = provider_module.OpenAICompatibleProvider(provider_id)
            chunks = [
                chunk
                async for chunk in provider.stream_response(
                    "question",
                    [],
                    [Message("assistant", "prior")],
                    "system",
                    "deepseek-chat",
                )
            ]
            return chunks, provider

        for provider_id, spec in OPENAI_COMPATIBLE_SPECS.items():
            with mock.patch.object(
                provider_module.cfg,
                spec.credential_attribute,
                "provider-secret",
            ):
                chunks, provider = asyncio.run(exercise(provider_id))
            self.assertEqual(chunks, ["hello"])
            self.assertTrue(provider._client.stream.closed)

        self.assertEqual(
            [call["base_url"] for call in FakeOpenAIClient.init_calls],
            [spec.base_url for spec in OPENAI_COMPATIBLE_SPECS.values()],
        )
        for call in FakeOpenAIClient.init_calls:
            self.assertEqual(call["api_key"], "provider-secret")
            self.assertEqual(call["max_retries"], 0)
        for call in FakeHTTPClient.calls:
            self.assertIs(call["trust_env"], False)
            self.assertIs(call["follow_redirects"], False)

    def test_model_discovery_uses_same_fixed_endpoint_and_bounded_stream(self):
        from ai import model_registry

        class Response:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def raise_for_status(self):
                return None

            async def aiter_bytes(self):
                yield b'{"data":[{"id":"provider-model"}]}'

        class Client:
            init_calls = []
            request_calls = []

            def __init__(self, **kwargs):
                self.init_calls.append(kwargs)

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return False

            def stream(self, method, url, **kwargs):
                self.request_calls.append((method, url, kwargs))
                return Response()

        with mock.patch.object(model_registry.httpx, "AsyncClient", Client):
            for provider_id, spec in OPENAI_COMPATIBLE_SPECS.items():
                with mock.patch.object(
                    model_registry.cfg,
                    spec.credential_attribute,
                    "model-list-secret",
                ):
                    models = asyncio.run(
                        model_registry._fetch_openai_compatible(provider_id)
                    )
                self.assertEqual(models[0]["id"], "provider-model")

        for spec, (_method, url, kwargs) in zip(
            OPENAI_COMPATIBLE_SPECS.values(),
            Client.request_calls,
        ):
            self.assertEqual(url, f"{spec.base_url}/models")
            self.assertEqual(
                kwargs["headers"],
                {"Authorization": "Bearer model-list-secret"},
            )
        for call in Client.init_calls:
            self.assertIs(call["trust_env"], False)
            self.assertIs(call["follow_redirects"], False)


class FakeStdin:
    def __init__(self):
        self.value = b""
        self.closed = False

    def write(self, value):
        self.value += value

    async def drain(self):
        return None

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, events):
        self.stdin = FakeStdin()
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        for event in events:
            self.stdout.feed_data(json.dumps(event).encode() + b"\n")
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self.returncode = 0

    async def wait(self):
        return self.returncode

    def terminate(self):
        self.returncode = -15

    def kill(self):
        self.returncode = -9


class AgentProviderTests(unittest.TestCase):
    def test_codex_prompt_uses_stdin_and_restrictive_ephemeral_flags(self):
        from ai import agent_cli_provider as agent

        created = {}

        async def create(*command, **kwargs):
            created["command"] = command
            created["kwargs"] = kwargs
            created["process"] = FakeProcess([{
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "agent reply"},
            }])
            return created["process"]

        async def exercise():
            with mock.patch.object(
                agent, "coding_agent_allowed", return_value=True
            ), mock.patch.object(
                agent, "executable_path", return_value="C:/tools/codex.exe"
            ), mock.patch.object(
                agent.asyncio,
                "create_subprocess_exec",
                side_effect=create,
            ):
                provider = agent.AgentCLIProvider("codex_agent")
                return [
                    chunk
                    async for chunk in provider.stream_response(
                        "private spoken transcript",
                        [],
                        [],
                        "private system prompt",
                        "codex-default",
                    )
                ]

        with mock.patch.dict(
            os.environ,
            {
                "PATH": "C:/tools",
                "OPENAI_API_KEY": "must-not-leak",
                "KIMI_CODE_API_KEY": "must-not-leak-either",
            },
            clear=True,
        ):
            chunks = asyncio.run(exercise())
        self.assertEqual(chunks, ["agent reply"])
        command_text = "\n".join(created["command"])
        self.assertNotIn("private spoken transcript", command_text)
        self.assertIn(
            "private spoken transcript",
            created["process"].stdin.value.decode(),
        )
        self.assertIn("--ephemeral", created["command"])
        self.assertIn("--ignore-user-config", created["command"])
        self.assertIn("--ignore-rules", created["command"])
        self.assertIn("read-only", created["command"])
        self.assertNotIn("OPENAI_API_KEY", created["kwargs"]["env"])
        self.assertNotIn("KIMI_CODE_API_KEY", created["kwargs"]["env"])

    def test_qwen_agent_forces_international_coding_plan_endpoint(self):
        from ai import agent_cli_provider as agent

        with mock.patch.object(
            agent.cfg,
            "qwen_coding_plan_api_key",
            "sk-sp-plan",
        ), mock.patch.dict(
            os.environ,
            {
                "PATH": "C:/tools",
                "OPENAI_BASE_URL": "https://attacker.invalid/v1",
                "OPENAI_API_KEY": "wrong-key",
            },
            clear=True,
        ):
            environment = agent._agent_environment(
                "qwen_code_agent",
                "qwen3-coder-plus",
            )
        self.assertEqual(
            environment["OPENAI_BASE_URL"],
            "https://coding-intl.dashscope.aliyuncs.com/v1",
        )
        self.assertEqual(
            environment["BAILIAN_CODING_PLAN_API_KEY"],
            "sk-sp-plan",
        )
        self.assertEqual(environment["OPENAI_MODEL"], "qwen3-coder-plus")
        self.assertNotIn("OPENAI_API_KEY", environment)

    def test_agent_permission_fails_closed(self):
        from ai import agent_cli_provider as agent

        with mock.patch.object(
            agent, "coding_agent_allowed", return_value=False
        ), self.assertRaises(PermissionError):
            agent.AgentCLIProvider("codex_agent")

    @unittest.skipUnless(os.name == "nt", "Windows process-boundary test")
    def test_codex_adapter_crosses_a_real_bounded_process_boundary(self):
        from ai import agent_cli_provider as agent

        async def exercise(executable):
            with mock.patch.object(
                agent, "coding_agent_allowed", return_value=True
            ), mock.patch.object(
                agent, "executable_path", return_value=str(executable)
            ):
                provider = agent.AgentCLIProvider("codex_agent")
                return [
                    chunk
                    async for chunk in provider.stream_response(
                        "synthetic prompt",
                        [],
                        [],
                        "synthetic system",
                        "codex-default",
                    )
                ]

        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "codex.cmd"
            script = (
                "@echo off\r\n"
                f'"{sys.executable}" -c "import json,sys;'
                "sys.stdin.read();"
                "print(json.dumps({'type':'item.completed',"
                "'item':{'type':'agent_message','text':'process reply'}}))"
                '"\r\n'
            )
            executable.write_text(script, encoding="utf-8", newline="")
            chunks = asyncio.run(exercise(executable))
        self.assertEqual(chunks, ["process reply"])


if __name__ == "__main__":
    unittest.main()
