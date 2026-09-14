"""Real SDK serialization with synthetic credentials and in-memory transport."""

from __future__ import annotations

import json
import os
import types
import unittest
from unittest.mock import patch

import httpx

from ai import sdk_isolation
from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
from ai.video_input import VideoInput
from tests.provider_test_support import load_subject


MODEL = "meta/muse-spark-1.3-contributor"
AMBIENT = {
    "OPENAI_API_KEY": "unrelated-openai-key",
    "OPENAI_ADMIN_KEY": "unrelated-admin-key",
    "OPENAI_BASE_URL": "https://unrelated.invalid/v1",
    "OPENAI_ORG_ID": "unrelated-organization",
    "OPENAI_PROJECT_ID": "unrelated-project",
    "OPENAI_WEBHOOK_SECRET": "unrelated-webhook",
    "OPENAI_CUSTOM_HEADERS": (
        "authorization: Bearer unrelated-authorization\n"
        "Host: unrelated.invalid\nX-Unrelated: unrelated-secret\n"
        "OpenAI-Organization: unrelated-header-org\n"
        ": malformed header that must never reach request validation"
    ),
    "ANTHROPIC_API_KEY": "unrelated-anthropic-key",
    "ANTHROPIC_AUTH_TOKEN": "unrelated-anthropic-auth",
    "ANTHROPIC_BASE_URL": "https://unrelated.invalid",
    "ANTHROPIC_WEBHOOK_SIGNING_KEY": "unrelated-anthropic-webhook",
    "ANTHROPIC_CUSTOM_HEADERS": (
        "X-Api-Key: unrelated-anthropic-header\n"
        "Authorization: Bearer unrelated-anthropic-auth\n"
        "X-Unrelated: unrelated-secret\nHost: unrelated.invalid\n"
        ": malformed header that must never reach request validation"
    ),
    "HTTP_PROXY": "http://unrelated.invalid:9",
    "HTTPS_PROXY": "http://unrelated.invalid:9",
    "SSL_CERT_FILE": "unrelated-certificate-file-that-does-not-exist",
}


class SDKIsolationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.requests = []
        self.clients = []
        self.ambient = patch.dict(os.environ, AMBIENT)
        self.ambient.start()
        self.addCleanup(self.ambient.stop)
        self.environment = dict(os.environ)

        def respond(request):
            self.requests.append(request)
            if request.url.path.endswith("/models"):
                return httpx.Response(200, json={"data": [], "has_more": False})
            if request.url.path.endswith("/chat/completions"):
                return httpx.Response(
                    200, headers={"content-type": "text/event-stream"},
                    content=(b'data: {"id":"test","object":"chat.completion.chunk",'
                             b'"created":0,"model":"test","choices":[{"index":0,'
                             b'"delta":{"content":"Test answer"},"finish_reason":"stop"}]}\n\n'
                             b'data: [DONE]\n\n'),
                )
            return httpx.Response(
                200, headers={"content-type": "text/event-stream"},
                content=b"data: [DONE]\n\n",
            )

        def http_client(timeout):
            client = httpx.AsyncClient(
                transport=httpx.MockTransport(respond),
                trust_env=False, follow_redirects=False, timeout=timeout,
            )
            self.clients.append(client)
            return client

        self.transport = patch.object(sdk_isolation, "_http_client", http_client)
        self.transport.start()
        self.addCleanup(self.transport.stop)

    async def asyncTearDown(self):
        for client in self.clients:
            await client.aclose()
        self.assertEqual(dict(os.environ), self.environment)

    def assert_isolated(self, request, key, *, anthropic=False):
        serialized = json.dumps(dict(request.headers))
        self.assertNotIn("unrelated", serialized)
        self.assertEqual(request.headers["host"], request.url.netloc.decode())
        if anthropic:
            self.assertEqual(request.headers["x-api-key"], key)
            self.assertNotIn("authorization", request.headers)
        else:
            self.assertEqual(request.headers["authorization"], "Bearer " + key)
            self.assertNotIn("openai-organization", request.headers)
            self.assertNotIn("openai-project", request.headers)

    async def test_catalog_text_video_and_private_routing_keep_source_credentials(self):
        cfg = types.SimpleNamespace(openrouter_private_routing=False)
        for provider_id, spec in OPENAI_COMPATIBLE_SPECS.items():
            setattr(cfg, spec.credential_attribute, "selected-" + provider_id)
        module = load_subject("ai/openai_compatible_provider.py", cfg)
        for provider_id, spec in OPENAI_COMPATIBLE_SPECS.items():
            with self.subTest(provider=provider_id):
                provider = module.OpenAICompatibleProvider(provider_id)
                self.assertFalse(provider._client._client.trust_env)
                self.assertFalse(provider._client._client.follow_redirects)
                self.assertEqual(provider._client.max_retries, 0)
                chunks = [chunk async for chunk in provider.stream_response(
                    "synthetic question", ["synthetic-image"], [], "system", MODEL,
                )]
                self.assertEqual(chunks, ["Test answer"])
                request = self.requests[-1]
                self.assertEqual(str(request.url), spec.base_url + "/chat/completions")
                self.assert_isolated(request, "selected-" + provider_id)
                payload = json.loads(request.content)
                if provider_id == "openrouter":
                    self.assertEqual(payload["provider"], {"allow_fallbacks": False})
                    video = VideoInput.from_bytes(b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00")
                    for private in (False, True):
                        cfg.openrouter_private_routing = private
                        _ = [chunk async for chunk in provider.stream_video_response(
                            "spoken instructions", video, [], "system", MODEL,
                        )]
                        request = self.requests[-1]
                        self.assert_isolated(request, "selected-openrouter")
                        body = json.loads(request.content)
                        expected = {"allow_fallbacks": False}
                        if private:
                            expected.update(zdr=True, data_collection="deny")
                        self.assertEqual(body["provider"], expected)
                        self.assertEqual(body["messages"][-1]["content"][-1]["type"], "video_url")
                else:
                    self.assertNotIn("provider", payload)
                await provider._client.close()

    async def test_openai_defaults_and_explicit_router_endpoints_are_preserved(self):
        for base_url in ("", "http://127.0.0.1:4321/v1", "https://router.example/v1"):
            with self.subTest(base_url=base_url):
                cfg = types.SimpleNamespace(openai_api_key="selected-router-key", openai_base_url=base_url)
                module = load_subject("ai/openai_provider.py", cfg)
                provider = module.OpenAIProvider()
                self.assertEqual(provider._client.max_retries, 2)
                self.assertEqual(provider._client.timeout, 600.0)
                self.assertTrue(await provider.health_check())
                request = self.requests[-1]
                expected = base_url or "https://api.openai.com/v1"
                self.assertEqual(str(request.url), expected + "/models")
                self.assert_isolated(request, "selected-router-key")
                await provider._client.close()

    async def test_private_video_rejection_never_retries_without_restrictions(self):
        from openai import BadRequestError

        rejected = []

        def deny(request):
            rejected.append(request)
            return httpx.Response(400, json={"error": {"message": "No eligible endpoint"}})

        http_client = httpx.AsyncClient(
            transport=httpx.MockTransport(deny), trust_env=False,
            follow_redirects=False,
        )
        cfg = types.SimpleNamespace(
            openrouter_api_key="selected-openrouter", openrouter_private_routing=True,
        )
        module = load_subject("ai/openai_compatible_provider.py", cfg)
        with patch.object(sdk_isolation, "_http_client", return_value=http_client):
            provider = module.OpenAICompatibleProvider("openrouter")
        try:
            video = VideoInput.from_bytes(b"\x00\x00\x00\x10ftypisom\x00\x00\x00\x00")
            with self.assertRaises(BadRequestError):
                _ = [chunk async for chunk in provider.stream_video_response(
                    "spoken instructions", video, [], "system", MODEL,
                )]
            self.assertEqual(len(rejected), 1)
            self.assertEqual(json.loads(rejected[0].content)["provider"], {
                "allow_fallbacks": False, "zdr": True, "data_collection": "deny",
            })
            self.assert_isolated(rejected[0], "selected-openrouter")
        finally:
            await provider._client.close()

    async def test_anthropic_key_and_explicit_router_ignore_ambient_auth(self):
        cfg = types.SimpleNamespace(anthropic_api_key="selected-anthropic-key")
        module = load_subject("ai/claude_provider.py", cfg)
        provider = module.ClaudeProvider()
        self.assertEqual(provider._client.max_retries, 2)
        self.assertEqual(provider._client.timeout, 600.0)
        self.assertTrue(await provider.health_check())
        self.assertEqual(str(self.requests[-1].url), "https://api.anthropic.com/v1/models")
        self.assert_isolated(self.requests[-1], "selected-anthropic-key", anthropic=True)
        self.assertIsNone(provider._client.auth_token)
        self.assertIsNone(provider._client.credentials)
        self.assertIsNone(provider._client.webhook_key)
        await provider._client.close()
        cfg.anthropic_base_url = "http://127.0.0.1:4321"
        cfg.anthropic_api_key = "selected-router-key"
        router = module.ClaudeProvider()
        self.assertTrue(await router.health_check())
        self.assertEqual(str(self.requests[-1].url), "http://127.0.0.1:4321/v1/models")
        self.assert_isolated(self.requests[-1], "selected-router-key", anthropic=True)
        await router._client.close()

    async def test_explicit_source_headers_survive_and_missing_credentials_fail_closed(self):
        for factory in (sdk_isolation.create_openai_client, sdk_isolation.create_anthropic_client):
            with self.subTest(factory=factory.__name__):
                for key, endpoint in ((None, "https://router.example"), ("", "https://router.example"), ("selected", "")):
                    with self.assertRaises(ValueError):
                        factory(api_key=key, base_url=endpoint)
                client = factory(
                    api_key="explicit-key", base_url="https://router.example",
                    default_headers={"X-Source-Scoped": "explicit-value"},
                )
                await client.models.list()
                self.assertEqual(self.requests[-1].headers["x-source-scoped"], "explicit-value")
                self.assert_isolated(self.requests[-1], "explicit-key", anthropic=factory is sdk_isolation.create_anthropic_client)
                await client.close()

    async def test_default_transport_ignores_proxy_and_certificate_environment(self):
        self.transport.stop()
        client = sdk_isolation.create_openai_client(
            api_key="explicit-key", base_url="http://127.0.0.1:4321/v1",
        )
        self.assertFalse(client._client.trust_env)
        self.assertFalse(client._client.follow_redirects)
        self.assertIsNone(client.admin_api_key)
        self.assertIsNone(client.organization)
        self.assertIsNone(client.project)
        self.assertIsNone(client.webhook_secret)
        await client.close()


if __name__ == "__main__":
    unittest.main()
