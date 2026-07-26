"""Standard-library tests for fail-closed runtime model acquisition."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "audio" / "stt" / "local_models.py"
SPEC = importlib.util.spec_from_file_location("clicky_local_models_test", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
local_models = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(local_models)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_ollama_module():
    httpx_stub = types.ModuleType("httpx")
    config_stub = types.ModuleType("config")
    config_stub.cfg = types.SimpleNamespace(
        ollama_host="http://127.0.0.1:11434",
        ollama_text_model="text:1",
        ollama_vision_model="vision:1",
        ollama_text_model_digest="a" * 64,
        ollama_vision_model_digest="b" * 64,
    )
    module_spec = importlib.util.spec_from_file_location(
        "clicky_ollama_bootstrap_test", REPO_ROOT / "ai" / "ollama_bootstrap.py"
    )
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    with patch.dict(sys.modules, {"httpx": httpx_stub, "config": config_stub}):
        module_spec.loader.exec_module(module)
    return module


class LocalModelResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @staticmethod
    def _make_faster_model(directory: Path) -> Path:
        directory.mkdir(parents=True)
        (directory / "config.json").write_bytes(b"config")
        (directory / "model.bin").write_bytes(b"reviewed-local-weights")
        (directory / "tokenizer.json").write_bytes(b"tokenizer")
        return directory

    def test_faster_whisper_digest_match_is_accepted(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        resolved = local_models.resolve_faster_whisper_model(
            str(model), _sha256(model / "model.bin")
        )
        self.assertEqual(resolved, model.resolve())

    def test_faster_whisper_digest_mismatch_fails_closed(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "mismatch"):
            local_models.resolve_faster_whisper_model(str(model), "0" * 64)

    def test_missing_digest_fails_closed(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "required"):
            local_models.resolve_faster_whisper_model(str(model), "")

    def test_malformed_digest_fails_closed(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "64 hexadecimal"):
            local_models.resolve_faster_whisper_model(str(model), "not-a-digest")

    def test_incomplete_faster_whisper_directory_fails_closed(self) -> None:
        model = self.root / "incomplete"
        model.mkdir()
        (model / "model.bin").write_bytes(b"partial")
        with self.assertRaises(local_models.LocalModelUnavailable):
            local_models.resolve_faster_whisper_model(str(model), "0" * 64)

    def test_named_faster_whisper_uses_verified_cache_snapshot(self) -> None:
        repo = self.root / "models--Systran--faster-whisper-base"
        snapshot = self._make_faster_model(repo / "snapshots" / "abc123")
        (repo / "refs").mkdir()
        (repo / "refs" / "main").write_text("abc123", encoding="utf-8")
        resolved = local_models.resolve_faster_whisper_model(
            "base", _sha256(snapshot / "model.bin"), cache_roots=[self.root]
        )
        self.assertEqual(resolved, snapshot.resolve())

    def test_whisper_cpp_digest_match_is_accepted(self) -> None:
        model = self.root / "ggml-base.bin"
        model.write_bytes(b"reviewed-local-artifact")
        resolved = local_models.resolve_whisper_cpp_model(
            "base", _sha256(model), cache_dirs=[self.root]
        )
        self.assertEqual(resolved, model.resolve())

    def test_whisper_cpp_digest_mismatch_fails_closed(self) -> None:
        model = self.root / "ggml-base.bin"
        model.write_bytes(b"reviewed-local-artifact")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "mismatch"):
            local_models.resolve_whisper_cpp_model(
                "base", "f" * 64, cache_dirs=[self.root]
            )

    def test_ambiguous_whisper_cpp_cache_fails_closed(self) -> None:
        first = self.root / "one"
        second = self.root / "two"
        first.mkdir()
        second.mkdir()
        (first / "ggml-base.bin").write_bytes(b"one")
        (second / "base.bin").write_bytes(b"two")
        with self.assertRaises(local_models.LocalModelUnavailable):
            local_models.resolve_whisper_cpp_model(
                "base", "0" * 64, cache_dirs=[first, second]
            )


class OllamaIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ollama = _load_ollama_module()

    def test_tag_and_digest_match(self) -> None:
        self.ollama.require_model_identity(
            "model:1",
            "a" * 64,
            variable_name="MODEL_DIGEST",
            metadata=[{"name": "model:1", "digest": "sha256:" + "a" * 64}],
        )

    def test_ollama_digest_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(self.ollama.OllamaIdentityError, "mismatch"):
            self.ollama.require_model_identity(
                "model:1",
                "a" * 64,
                variable_name="MODEL_DIGEST",
                metadata=[{"name": "model:1", "digest": "sha256:" + "b" * 64}],
            )

    def test_ollama_missing_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(self.ollama.OllamaIdentityError, "required"):
            self.ollama.require_model_identity(
                "model:1",
                "",
                variable_name="MODEL_DIGEST",
                metadata=[{"name": "model:1", "digest": "sha256:" + "a" * 64}],
            )

    def test_ollama_malformed_digest_fails_closed(self) -> None:
        with self.assertRaisesRegex(self.ollama.OllamaIdentityError, "64 hexadecimal"):
            self.ollama.require_model_identity(
                "model:1",
                "bad",
                variable_name="MODEL_DIGEST",
                metadata=[{"name": "model:1", "digest": "sha256:" + "a" * 64}],
            )

    def test_ollama_tag_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(self.ollama.OllamaIdentityError, "not present"):
            self.ollama.require_model_identity(
                "model:2",
                "a" * 64,
                variable_name="MODEL_DIGEST",
                metadata=[{"name": "model:1", "digest": "sha256:" + "a" * 64}],
            )


class AcquisitionSurfaceTests(unittest.TestCase):
    def test_ollama_runtime_has_no_download_or_execution_primitive(self) -> None:
        files = (
            REPO_ROOT / "ai" / "ollama_bootstrap.py",
            REPO_ROOT / "ai" / "ollama_models_registry.py",
            REPO_ROOT / "ui" / "setup_wizard.py",
            REPO_ROOT / "installer.iss",
        )
        banned = (
            "/api/pull",
            "OllamaSetup.exe",
            "Invoke-WebRequest",
            "ExecutionPolicy Bypass",
            "Start-Process",
            "download_ollama_installer",
            "run_ollama_installer",
        )
        combined = "\n".join(path.read_text(encoding="utf-8") for path in files)
        for marker in banned:
            self.assertNotIn(marker, combined)

    def test_companion_cannot_spawn_ollama(self) -> None:
        source = (REPO_ROOT / "companion_manager.py").read_text(encoding="utf-8")
        for marker in (
            "subprocess.Popen",
            "subprocess.run",
            "tasklist",
            '["ollama", "serve"]',
            "_ensure_ollama_running",
        ):
            self.assertNotIn(marker, source)
        self.assertIn("_require_local_ollama()", source)
        self.assertIn("require_configured_model_identities()", source)

    def test_ollama_metadata_transport_is_bounded_and_proxy_free(self) -> None:
        source = (REPO_ROOT / "ai" / "ollama_bootstrap.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("trust_env=False", source)
        self.assertIn("follow_redirects=False", source)
        self.assertIn("client.stream", source)
        self.assertIn("_MAX_TAGS_RESPONSE_BYTES", source)
        self.assertNotIn("response.json()", source)

    def test_ollama_generation_reverifies_identity_before_chat(self) -> None:
        source = (REPO_ROOT / "ai" / "ollama_provider.py").read_text(
            encoding="utf-8"
        )
        verification = source.index("require_model_identity")
        request = source.index('f"{self._base}/api/chat"')
        self.assertLess(verification, request)
        self.assertIn("await asyncio.to_thread", source)
        self.assertIn("trust_env=False", source)

    def test_ollama_chat_stream_is_content_type_and_size_bounded(self) -> None:
        source = (REPO_ROOT / "ai" / "ollama_provider.py").read_text(
            encoding="utf-8"
        )
        for marker in (
            "_ALLOWED_CHAT_CONTENT_TYPES",
            "application/x-ndjson",
            "application/ndjson",
            "application/json",
            "_MAX_CHAT_STREAM_BYTES",
            "_MAX_CHAT_RECORD_BYTES",
            "_MAX_CHAT_DECODED_CHARS",
            "response.aiter_bytes()",
            "raw_total > _MAX_CHAT_STREAM_BYTES",
            "decoded_total > _MAX_CHAT_DECODED_CHARS",
            "content-encoding",
            "ended without a completion marker",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("response.aiter_lines()", source)
        self.assertNotIn("json.loads(line)", source)

    def test_every_speech_load_is_digest_gated(self) -> None:
        faster = (REPO_ROOT / "audio" / "stt" / "faster_whisper_stt.py").read_text(
            encoding="utf-8"
        )
        cpp = (REPO_ROOT / "audio" / "stt" / "whisper_cpp_stt.py").read_text(
            encoding="utf-8"
        )
        ambient = (REPO_ROOT / "audio" / "ambient_listener.py").read_text(
            encoding="utf-8"
        )
        resolver = MODULE_PATH.read_text(encoding="utf-8")
        self.assertIn("local_files_only=True", faster)
        self.assertIn("cfg.whisper_model_sha256", faster)
        self.assertIn("cfg.whispercpp_model_sha256", cpp)
        self.assertIn("cfg.clicky_wake_model_sha256", ambient)
        self.assertNotIn("WhisperModel(", ambient)
        self.assertIn("hmac.compare_digest", resolver)


if __name__ == "__main__":
    unittest.main()
