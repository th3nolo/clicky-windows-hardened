"""Custom router image declarations survive discovery without guessing aliases."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx

from ai.provider_endpoints import router_vision_models
from compose.service import cached_model_supports_vision
from tests.provider_test_support import configuration, load_subject, mock_client_factory


class RouterVisionCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_cache_and_image_gate_honor_explicit_capabilities(self):
        endpoint = "http://127.0.0.1:4321/v1"
        config = configuration(
            openai_base_url=endpoint,
            openai_router_vision_models=router_vision_models(endpoint, "operator-vision"),
        )
        subject = load_subject("ai/model_registry.py", config)
        records = [
            {"id": "metadata-vision", "vision": True},
            {"id": "capability-vision", "capabilities": {"vision": True}},
            {"id": "modality-vision", "input_modalities": ["text", "image"]},
            {"id": "architecture-vision", "architecture": {"input_modalities": ["image"]}},
            {"id": "operator-vision"},
            {"id": "gpt-4o"},  # An alias is not a capability declaration.
            {"id": "malformed", "vision": "true", "input_modalities": "image"},
        ]
        with tempfile.TemporaryDirectory() as directory, patch.object(
            subject, "_data_dir", return_value=Path(directory),
        ), patch.object(subject.httpx, "AsyncClient", side_effect=mock_client_factory(
            lambda _: httpx.Response(200, json={"data": records}),
        )), patch.dict("sys.modules", {"ai.model_registry": subject}):
            refreshed = await subject.refresh("openai")
            enabled = {record["id"] for record in refreshed if record["vision"]}
            self.assertEqual(enabled, {"metadata-vision", "capability-vision", "modality-vision",
                                       "architecture-vision", "operator-vision"})
            for model in enabled:
                self.assertTrue(cached_model_supports_vision("openai", model))
            self.assertFalse(cached_model_supports_vision("openai", "gpt-4o"))
            self.assertFalse(cached_model_supports_vision("openai", "malformed"))
            cached = json.loads(subject._cache_path("openai").read_text())["models"]
            self.assertFalse(next(item for item in cached if item["id"] == "operator-vision")["vision"])
            config.openai_router_vision_models = {}
            self.assertFalse(cached_model_supports_vision("openai", "operator-vision"))
            self.assertTrue(cached_model_supports_vision("openai", "metadata-vision"))
            config.openai_router_vision_models = router_vision_models(endpoint, "operator-vision")
            config.openai_base_url = "http://127.0.0.1:5432/v1"
            await subject.refresh("openai")
            self.assertFalse(cached_model_supports_vision("openai", "operator-vision"))

    def test_explicit_declaration_is_bounded_and_endpoint_scoped(self):
        endpoint = "http://127.0.0.1:4321/v1"
        self.assertEqual(router_vision_models(endpoint + "/", " qwen-vl, local-vl,qwen-vl "),
                         {endpoint: ("qwen-vl", "local-vl")})
        for value in ("model,", "model with space", "a" * 257,
                      ",".join("model-" + str(i) for i in range(257)), "x" * (64 * 1024 + 1)):
            with self.subTest(value=value[:40]), self.assertRaises(ValueError):
                router_vision_models(endpoint, value)
        with self.assertRaises(ValueError):
            router_vision_models("", "model")


if __name__ == "__main__":
    unittest.main()
