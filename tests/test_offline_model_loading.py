"""Standard-library tests for fail-closed runtime model acquisition."""

from __future__ import annotations

import ast
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


def _parse_python(relative: str) -> ast.Module:
    path = REPO_ROOT / relative
    return ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))


def _qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _calls(tree: ast.AST, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _qualified_name(node.func) == name
    ]


def _calls_ending_with(tree: ast.AST, name: str) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (_qualified_name(node.func) or "").split(".")[-1] == name
    ]


def _literal_keyword(call: ast.Call, name: str):
    values = [keyword.value for keyword in call.keywords if keyword.arg == name]
    if len(values) != 1:
        raise AssertionError(f"{_qualified_name(call.func)} must set {name} exactly once")
    return ast.literal_eval(values[0])


def _imports_root(tree: ast.AST, module: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name.split(".", 1)[0] == module for alias in node.names):
                return True
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".", 1)[0] == module:
            return True
        if isinstance(node, ast.Call) and _qualified_name(node.func) in {
            "__import__",
            "importlib.import_module",
        }:
            if node.args and isinstance(node.args[0], ast.Constant):
                imported = node.args[0].value
                if isinstance(imported, str) and imported.split(".", 1)[0] == module:
                    return True
    return False


def _string_literals(tree: ast.AST) -> set[str]:
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _defined_names(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def _static_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant):
        value = node.value
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        operand = _static_int(node.operand)
        if operand is None:
            return None
        return operand if isinstance(node.op, ast.UAdd) else -operand
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
        left = _static_int(node.left)
        right = _static_int(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        return left * right
    return None


def _assigned_int(tree: ast.AST, name: str) -> int | None:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not any(isinstance(target, ast.Name) and target.id == name for target in targets):
            continue
        return _static_int(node.value)
    return None


def _has_attribute(tree: ast.AST, qualified: str) -> bool:
    return any(
        _qualified_name(node) == qualified
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    )


def _has_greater_than(tree: ast.AST, left: str, right: str) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1:
            continue
        if not isinstance(node.ops[0], ast.Gt) or len(node.comparators) != 1:
            continue
        if _qualified_name(node.left) == left and _qualified_name(node.comparators[0]) == right:
            return True
    return False


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
            str(model), local_models.faster_whisper_directory_sha256(model)
        )
        self.assertEqual(resolved, model.resolve())

    def test_faster_whisper_digest_mismatch_fails_closed(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "mismatch"):
            local_models.resolve_faster_whisper_model(str(model), "0" * 64)

    def test_every_faster_whisper_file_is_covered_by_digest(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        (model / "vocabulary.txt").write_bytes(b"reviewed vocabulary")
        expected = local_models.faster_whisper_directory_sha256(model)
        for filename in ("config.json", "model.bin", "tokenizer.json", "vocabulary.txt"):
            original = (model / filename).read_bytes()
            (model / filename).write_bytes(original + b" tampered")
            with self.assertRaisesRegex(local_models.LocalModelUnavailable, "mismatch"):
                local_models.resolve_faster_whisper_model(str(model), expected)
            (model / filename).write_bytes(original)

    def test_unlisted_extra_file_changes_faster_whisper_digest(self) -> None:
        model = self._make_faster_model(self.root / "verified-model")
        expected = local_models.faster_whisper_directory_sha256(model)
        (model / "added.json").write_bytes(b"new unreviewed content")
        with self.assertRaisesRegex(local_models.LocalModelUnavailable, "mismatch"):
            local_models.resolve_faster_whisper_model(str(model), expected)

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
            "base",
            local_models.faster_whisper_directory_sha256(snapshot),
            cache_roots=[self.root],
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
        python_files = (
            "ai/ollama_bootstrap.py",
            "ai/ollama_models_registry.py",
            "ui/setup_wizard.py",
        )
        banned_strings = {"/api/pull", "OllamaSetup.exe"}
        banned_names = {"download_ollama_installer", "run_ollama_installer"}
        banned_calls = {"os.system", "subprocess.Popen", "subprocess.run"}
        for relative in python_files:
            with self.subTest(path=relative):
                tree = _parse_python(relative)
                self.assertFalse(_imports_root(tree, "subprocess"))
                self.assertTrue(banned_strings.isdisjoint(_string_literals(tree)))
                self.assertTrue(banned_names.isdisjoint(_defined_names(tree)))
                self.assertFalse(
                    any(_calls(tree, call_name) for call_name in banned_calls)
                )

        installer_lines = [
            line.strip()
            for line in (REPO_ROOT / "installer.iss").read_text(
                encoding="utf-8-sig"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith(";")
        ]
        for marker in ("Invoke-WebRequest", "ExecutionPolicy Bypass", "Start-Process"):
            self.assertFalse(any(marker in line for line in installer_lines))

    def test_companion_cannot_spawn_ollama(self) -> None:
        tree = _parse_python("companion_manager.py")
        self.assertFalse(_imports_root(tree, "subprocess"))
        for call_name in ("os.system", "subprocess.Popen", "subprocess.run"):
            self.assertFalse(_calls(tree, call_name), call_name)
        self.assertNotIn("_ensure_ollama_running", _defined_names(tree))
        self.assertTrue(_calls_ending_with(tree, "_require_local_ollama"))
        self.assertTrue(_calls_ending_with(tree, "require_configured_model_identities"))

    def test_ollama_metadata_transport_is_bounded_and_proxy_free(self) -> None:
        tree = _parse_python("ai/ollama_bootstrap.py")
        clients = _calls(tree, "httpx.Client")
        self.assertEqual(len(clients), 1)
        self.assertIs(_literal_keyword(clients[0], "trust_env"), False)
        self.assertIs(_literal_keyword(clients[0], "follow_redirects"), False)
        self.assertTrue(_calls_ending_with(tree, "stream"))
        self.assertGreater(_assigned_int(tree, "_MAX_TAGS_RESPONSE_BYTES") or 0, 0)
        self.assertFalse(_calls_ending_with(tree, "json"))

    def test_ollama_generation_reverifies_identity_before_chat(self) -> None:
        tree = _parse_python("ai/ollama_provider.py")
        clients = _calls(tree, "httpx.AsyncClient")
        self.assertEqual(len(clients), 1)
        self.assertIs(_literal_keyword(clients[0], "trust_env"), False)
        self.assertIs(_literal_keyword(clients[0], "follow_redirects"), False)
        identity_references = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and node.id == "require_model_identity"
        ]
        request_calls = _calls_ending_with(tree, "stream")
        self.assertEqual(len(identity_references), 1)
        self.assertEqual(len(request_calls), 1)
        self.assertLess(identity_references[0].lineno, request_calls[0].lineno)
        to_thread_calls = _calls(tree, "asyncio.to_thread")
        self.assertTrue(to_thread_calls)
        self.assertTrue(
            any(
                call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == "require_model_identity"
                for call in to_thread_calls
            )
        )

    def test_ollama_chat_stream_is_content_type_and_size_bounded(self) -> None:
        tree = _parse_python("ai/ollama_provider.py")
        for name in (
            "_MAX_CHAT_STREAM_BYTES",
            "_MAX_CHAT_RECORD_BYTES",
            "_MAX_CHAT_DECODED_CHARS",
        ):
            self.assertGreater(_assigned_int(tree, name) or 0, 0, name)
        strings = _string_literals(tree)
        for media_type in (
            "application/x-ndjson",
            "application/ndjson",
            "application/json",
        ):
            self.assertIn(media_type, strings)
        self.assertTrue(_calls_ending_with(tree, "aiter_bytes"))
        self.assertTrue(
            _has_greater_than(tree, "raw_total", "_MAX_CHAT_STREAM_BYTES")
        )
        self.assertTrue(
            _has_greater_than(tree, "decoded_total", "_MAX_CHAT_DECODED_CHARS")
        )
        self.assertIn("content-encoding", strings)
        self.assertTrue(
            any("ended without a completion marker" in value for value in strings)
        )
        self.assertFalse(_calls_ending_with(tree, "aiter_lines"))
        for call in _calls(tree, "json.loads"):
            self.assertFalse(
                call.args
                and isinstance(call.args[0], ast.Name)
                and call.args[0].id == "line"
            )

    def test_every_speech_load_is_digest_gated(self) -> None:
        faster = _parse_python("audio/stt/faster_whisper_stt.py")
        cpp = _parse_python("audio/stt/whisper_cpp_stt.py")
        ambient = _parse_python("audio/ambient_listener.py")
        resolver = _parse_python("audio/stt/local_models.py")

        whisper_loads = _calls_ending_with(faster, "WhisperModel")
        self.assertEqual(len(whisper_loads), 1)
        self.assertIs(_literal_keyword(whisper_loads[0], "local_files_only"), True)
        self.assertTrue(_has_attribute(faster, "cfg.whisper_model_sha256"))
        self.assertTrue(_has_attribute(cpp, "cfg.whispercpp_model_sha256"))
        self.assertTrue(_has_attribute(ambient, "cfg.clicky_wake_model_sha256"))
        self.assertFalse(_calls_ending_with(ambient, "WhisperModel"))
        self.assertTrue(_calls(resolver, "hmac.compare_digest"))


if __name__ == "__main__":
    unittest.main()
