"""Offline request evidence for speech, explicit routers and discovery clients."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import httpx

from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
from ai.sdk_isolation import create_openai_client
from audio import openai_client
from privacy_controls import PRIVACY_NOTICE_VERSION
from tests.provider_test_support import configuration, load_subject, mock_client_factory


HOSTILE_ENV = {
    "OPENAI_API_KEY": "ambient-openai",
    "OPENAI_ADMIN_KEY": "ambient-admin",
    "OPENAI_BASE_URL": "https://ambient.invalid/v1",
    "OPENAI_CUSTOM_HEADERS": "Authorization: Bearer ambient-other\nX-Ambient-Secret: dummy",
    "OPENAI_ORG_ID": "ambient-org",
    "OPENAI_PROJECT_ID": "ambient-project",
    "HTTP_PROXY": "http://ambient.invalid:8080",
    "HTTPS_PROXY": "http://ambient.invalid:8080",
}


class ProviderClientCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def assert_no_shared_headers(self, request):
        for header in ("x-ambient-secret", "openai-organization", "openai-project"):
            self.assertNotIn(header, request.headers)
        self.assertNotIn("ambient", str(request.headers))

    async def test_speech_requests_keep_explicit_openai_key_and_official_destination(self):
        for relative, class_name, endpoint in (
            ("audio/stt/openai_stt.py", "OpenAISTT", "/v1/audio/transcriptions"),
            ("audio/tts/openai_tts_provider.py", "OpenAITTSProvider", "/v1/audio/speech"),
        ):
            with self.subTest(provider=class_name):
                requests = []
                def respond(request):
                    requests.append(request)
                    return httpx.Response(200, content=b"synthetic response", headers={"content-type": "text/plain"})
                subject = load_subject(relative, configuration())
                client = httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False)
                def factory(**kwargs):
                    return create_openai_client(**kwargs, http_client=client)
                with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(openai_client, "create_openai_client", side_effect=factory):
                    provider = getattr(subject, class_name)()
                    try:
                        if class_name == "OpenAISTT":
                            self.assertEqual(await provider.transcribe(b"\x00\x00"), "synthetic response")
                        else:
                            await provider.speak("synthetic text")
                            subject.play_mp3_async.assert_awaited_once_with(b"synthetic response")
                    finally:
                        await provider._client.close()
                self.assertEqual(len(requests), 1)
                self.assertEqual(str(requests[0].url), "https://api.openai.com" + endpoint)
                self.assertEqual(requests[0].headers["authorization"], "Bearer explicit-openai")
                self.assert_no_shared_headers(requests[0])

    async def test_custom_chat_credential_is_never_reused_for_speech(self):
        for relative, class_name in (
            ("audio/stt/openai_stt.py", "OpenAISTT"),
            ("audio/tts/openai_tts_provider.py", "OpenAITTSProvider"),
        ):
            subject = load_subject(relative, configuration(openai_base_url="http://127.0.0.1:9876/v1"))
            with self.subTest(provider=class_name), mock.patch.object(openai_client, "create_openai_client") as factory:
                with self.assertRaisesRegex(RuntimeError, "OPENAI_SPEECH_API_KEY"):
                    getattr(subject, class_name)()
                factory.assert_not_called()

    async def test_explicit_speech_key_preserves_speech_with_custom_chat_router(self):
        subject = load_subject("audio/tts/openai_tts_provider.py", configuration(
            openai_base_url="http://127.0.0.1:9876/v1", openai_speech_api_key="explicit-speech",
        ))
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, content=b"speech")
        client = httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False)
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(openai_client, "create_openai_client", side_effect=lambda **kwargs: create_openai_client(**kwargs, http_client=client)):
            provider = subject.OpenAITTSProvider()
            try:
                await provider.speak("synthetic text")
            finally:
                await provider._client.close()
        self.assertEqual(requests[0].headers["authorization"], "Bearer explicit-speech")
        self.assertEqual(str(requests[0].url), "https://api.openai.com/v1/audio/speech")
        self.assert_no_shared_headers(requests[0])

    async def test_official_trailing_slash_keeps_legacy_speech_key(self):
        subject = load_subject("audio/stt/openai_stt.py", configuration(openai_base_url="https://api.openai.com/v1/"))
        with mock.patch.object(openai_client, "create_openai_client") as factory:
            subject.OpenAISTT()
        self.assertEqual(factory.call_args.kwargs["api_key"], "explicit-openai")

    async def test_readiness_matches_speech_credential_isolation(self):
        config = configuration(
            openai_base_url="http://127.0.0.1:9876/v1",
            privacy_consent_version=PRIVACY_NOTICE_VERSION,
            microphone_consent=True, cloud_stt_consent=True,
        )
        subject = load_subject("audio/stt/readiness.py", config)
        blocked = subject._cloud_readiness(config, "openai")
        self.assertFalse(blocked.ready)
        self.assertIn("OPENAI_SPEECH_API_KEY", blocked.detail)
        config.openai_speech_api_key = "speech-only"
        ready = subject._cloud_readiness(config, "openai")
        self.assertTrue(ready.ready)
        self.assertEqual(ready.destination, "https://api.openai.com/v1/audio/transcriptions")

    async def test_explicit_router_url_dummy_key_and_headers_survive_sdk_isolation(self):
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json={"data": [{"id": "qwen-local", "object": "model", "created": 0, "owned_by": "local"}]})
        transport = httpx.AsyncClient(transport=httpx.MockTransport(respond), trust_env=False)
        with mock.patch.dict(os.environ, HOSTILE_ENV):
            client = create_openai_client(
                api_key="local-dummy", base_url="http://127.0.0.1:54321/router/v1",
                http_client=transport, default_headers={"X-Explicit-Router": "route-a"},
            )
            try:
                result = await client.models.list()
            finally:
                await client.close()
        self.assertEqual(result.data[0].id, "qwen-local")
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:54321/router/v1/models")
        self.assertEqual(requests[0].headers["authorization"], "Bearer local-dummy")
        self.assertEqual(requests[0].headers["x-explicit-router"], "route-a")
        self.assert_no_shared_headers(requests[0])

    async def test_model_discovery_uses_only_selected_cloud_key(self):
        subject = load_subject("ai/model_registry.py", configuration())
        requests, options = [], []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json={"data": [], "models": []})
        factory = mock_client_factory(respond, options)
        cases = [
            (subject._fetch_openai, "https://api.openai.com/v1/models", "authorization", "Bearer explicit-openai"),
            (subject._fetch_claude, "https://api.anthropic.com/v1/models", "x-api-key", "explicit-anthropic"),
            (subject._fetch_gemini, "https://generativelanguage.googleapis.com/v1beta/models", "x-goog-api-key", "explicit-gemini"),
        ]
        for provider, spec in OPENAI_COMPATIBLE_SPECS.items():
            cases.append((lambda selected=provider: subject._fetch_openai_compatible(selected), spec.base_url.rstrip("/") + "/models", "authorization", "Bearer explicit-" + provider))
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject.httpx, "AsyncClient", side_effect=factory):
            for fetch, url, header, value in cases:
                await fetch()
                self.assertEqual(str(requests[-1].url), url)
                self.assertEqual(requests[-1].headers[header], value)
                self.assert_no_shared_headers(requests[-1])
        self.assertTrue(all(option["trust_env"] is False and option["follow_redirects"] is False for option in options))

    async def test_custom_openai_discovery_preserves_non_openai_router_models(self):
        subject = load_subject("ai/model_registry.py", configuration(openai_base_url="http://127.0.0.1:54321/router/v1/", openai_api_key="router-only"))
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json={"data": [
                {"id": "qwen-local"}, {"id": "MiniMax-M2.7"}, {"id": "deepseek-chat"},
                {"id": []}, {"id": {}}, {"id": "\x00invalid"}, {"id": "x" * 1024}, None,
            ]})
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject.httpx, "AsyncClient", side_effect=mock_client_factory(respond)):
            models = await subject._fetch_openai()
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:54321/router/v1/models")
        self.assertEqual(requests[0].headers["authorization"], "Bearer router-only")
        self.assertEqual({m["id"] for m in models}, {"qwen-local", "MiniMax-M2.7", "deepseek-chat"})
        self.assertTrue(all(m["vision"] is False for m in models))
        self.assert_no_shared_headers(requests[0])

    async def test_lmstudio_preserves_custom_local_route_without_cloud_authorization(self):
        subject = load_subject("ai/lmstudio_provider.py", configuration())
        requests, options = [], []
        def respond(request):
            requests.append(request)
            if request.url.path.endswith("/models"):
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            return httpx.Response(200, text='data: {"choices":[{"delta":{"content":"local reply"}}]}\n\ndata: [DONE]\n\n')
        factory = mock_client_factory(respond, options)
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject.httpx, "AsyncClient", side_effect=factory):
            provider = subject.LMStudioProvider()
            self.assertEqual([chunk async for chunk in provider.stream_response("synthetic", [], [], "system")], ["local reply"])
            self.assertTrue(await provider.health_check())
            self.assertEqual(await provider.list_models(), ["qwen-local"])
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:54321/custom/v1/chat/completions")
        for request in requests:
            self.assertNotIn("authorization", request.headers)
            self.assert_no_shared_headers(request)
        self.assertTrue(all(option["trust_env"] is False and option["follow_redirects"] is False for option in options))

    async def test_anthropic_discovery_uses_explicit_compatible_router(self):
        subject = load_subject("ai/model_registry.py", configuration(
            anthropic_base_url="http://127.0.0.1:54321/router/", anthropic_api_key="anthropic-router-only",
        ))
        requests = []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json={"data": [{"id": "router-model"}]})
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject.httpx, "AsyncClient", side_effect=mock_client_factory(respond)):
            models = await subject._fetch_claude()
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:54321/router/v1/models")
        self.assertEqual(requests[0].headers["x-api-key"], "anthropic-router-only")
        self.assertEqual(models[0]["id"], "router-model")
        self.assert_no_shared_headers(requests[0])

    async def test_copilot_token_and_discovery_keep_distinct_credentials(self):
        subject = load_subject("ai/github_copilot_provider.py", configuration())
        requests, options = [], []
        def respond(request):
            requests.append(request)
            if str(request.url) == subject.COPILOT_TOKEN_URL:
                return httpx.Response(200, json={"token": "explicit-session"})
            return httpx.Response(200, json={"data": []})
        factory = mock_client_factory(respond, options)
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject, "load_github_token", return_value="explicit-github"), mock.patch.object(subject.httpx, "AsyncClient", side_effect=factory):
            await subject.fetch_models_live()
        self.assertEqual([str(request.url) for request in requests], [subject.COPILOT_TOKEN_URL, subject.COPILOT_MODELS_URL])
        self.assertEqual(requests[0].headers["authorization"], "token explicit-github")
        self.assertEqual(requests[1].headers["authorization"], "Bearer explicit-session")
        for request in requests:
            self.assert_no_shared_headers(request)
        self.assertTrue(all(option["trust_env"] is False and option["follow_redirects"] is False for option in options))

    async def test_anthropic_locator_keeps_custom_router_key_at_its_endpoint(self):
        subject = load_subject("ai/element_locator.py", configuration(
            anthropic_base_url="http://127.0.0.1:54321/router/", anthropic_api_key="anthropic-router-only",
        ))
        requests, options = [], []
        def respond(request):
            requests.append(request)
            return httpx.Response(200, json={"content": []})
        factory = mock_client_factory(respond, options)
        with mock.patch.dict(os.environ, HOSTILE_ENV), mock.patch.object(subject, "_resize_jpeg", return_value=b"synthetic-image"), mock.patch.object(subject.httpx, "AsyncClient", side_effect=factory):
            await subject.detect_element(
                screenshot_jpeg_b64="YQ==", original_width=100, original_height=100,
                screen_index=0, user_question="synthetic question",
            )
        self.assertEqual(str(requests[0].url), "http://127.0.0.1:54321/router/v1/messages")
        self.assertEqual(requests[0].headers["x-api-key"], "anthropic-router-only")
        self.assert_no_shared_headers(requests[0])
        self.assertTrue(all(option["trust_env"] is False and option["follow_redirects"] is False for option in options))

    async def test_custom_endpoint_model_caches_and_fallbacks_are_isolated(self):
        for provider, attribute, official in (
            ("openai", "openai_base_url", "https://api.openai.com/v1"),
            ("claude", "anthropic_base_url", "https://api.anthropic.com"),
        ):
            config = configuration(**{attribute: official})
            subject = load_subject("ai/model_registry.py", config)
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as temporary, mock.patch.object(subject, "_data_dir", return_value=Path(temporary)):
                self.assertEqual(subject._cache_path(provider).name, f"models_{provider}.json")
                self.assertTrue(subject.cached_models(provider))
                setattr(config, attribute, "http://127.0.0.1:54321/router-a")
                first_path = subject._cache_path(provider)
                self.assertEqual(subject.cached_models(provider), [])
                first_path.write_text(json.dumps({"models": [{"id": "only-router-a", "vision": False}]}), encoding="utf-8")
                self.assertEqual(subject.cached_models(provider)[0]["id"], "only-router-a")
                setattr(config, attribute, "http://127.0.0.1:54321/router-b")
                self.assertNotEqual(subject._cache_path(provider), first_path)
                self.assertEqual(subject.cached_models(provider), [])

    async def test_discovery_does_not_write_old_results_into_changed_endpoint_cache(self):
        config = configuration(openai_base_url="http://127.0.0.1:54321/router-a/v1")
        subject = load_subject("ai/model_registry.py", config)
        async def switch_endpoint():
            config.openai_base_url = "http://127.0.0.1:54321/router-b/v1"
            return [{"id": "router-a-model", "vision": False}]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(subject, "_data_dir", return_value=Path(temporary)), mock.patch.dict(subject._FETCHERS, {"openai": switch_endpoint}):
            with self.assertRaisesRegex(ValueError, "endpoint changed"):
                await subject.refresh("openai")
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
