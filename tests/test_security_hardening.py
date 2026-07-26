from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Import security-sensitive modules without importing optional dependencies.
httpx_stub = types.ModuleType("httpx")
httpx_stub.AsyncClient = object
sys.modules.setdefault("httpx", httpx_stub)
config_stub = types.ModuleType("config")
config_stub.cfg = types.SimpleNamespace(tavily_api_key=None, search_provider=lambda: "duckduckgo")
sys.modules.setdefault("config", config_stub)
base_stub = types.ModuleType("ai.base_provider")
base_stub.BaseLLMProvider = object
base_stub.Message = object
ai_stub = types.ModuleType("ai")
ai_stub.__path__ = []
sys.modules.setdefault("ai", ai_stub)
sys.modules.setdefault("ai.base_provider", base_stub)

web_search = load_module("security_test_web_search", "ai/web_search.py")
skills = load_module("security_test_skills", "skills/__init__.py")
github = load_module("security_test_github", "ai/github_copilot_provider.py")
journal = load_module("security_test_journal", "tutor_features/journal.py")


class WebSearchSecurityTests(unittest.TestCase):
    def test_url_syntax_rejects_non_https_credentials_and_local_ips(self):
        rejected = [
            "http://example.com/",
            "https://user:password@example.com/",
            "https://localhost/",
            "https://service.internal/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://[fe80::1]/",
            "https://224.0.0.1/",
            "https://0.0.0.0/",
        ]
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(ValueError):
                web_search._parse_public_https_url(url)

    def test_dns_rejects_mixed_public_private_answers(self):
        mixed = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch.object(web_search.socket, "getaddrinfo", return_value=mixed):
            with self.assertRaises(ValueError):
                asyncio.run(web_search._validate_public_https_url("https://example.test/"))

    def test_dns_accepts_only_global_answers(self):
        public = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with mock.patch.object(web_search.socket, "getaddrinfo", return_value=public):
            asyncio.run(web_search._validate_public_https_url("https://example.test/"))

    def test_redirect_is_validated_before_second_request(self):
        responses = [
            FakeResponse(302, {"location": "https://127.0.0.1/admin"}, []),
            FakeResponse(200, {"content-type": "text/plain"}, [b"should not run"]),
        ]
        client = FakeClient(responses)
        seen = []

        async def validate(url):
            seen.append(url)
            web_search._parse_public_https_url(url)

        with mock.patch.object(web_search, "_validate_public_https_url", side_effect=validate):
            with self.assertRaises(ValueError):
                asyncio.run(web_search._bounded_request(
                    client, "https://public.example/start",
                    allowed_types={"text/plain"}, max_bytes=100,
                ))
        self.assertEqual(client.calls, 1)
        self.assertEqual(seen[-1], "https://127.0.0.1/admin")

    def test_connected_peer_must_be_present_and_public(self):
        private = FakeResponse(200, {"content-type": "text/plain"}, [], peer="127.0.0.1")
        with self.assertRaises(ValueError):
            web_search._validate_connected_peer(private)
        missing = FakeResponse(200, {"content-type": "text/plain"}, [])
        missing.extensions = {}
        with self.assertRaises(ValueError):
            web_search._validate_connected_peer(missing)

    def test_stream_limit_and_content_type_fail_closed(self):
        async def allow(_url):
            return None

        oversized = FakeClient([
            FakeResponse(200, {"content-type": "text/plain"}, [b"123", b"456"]),
        ])
        with mock.patch.object(web_search, "_validate_public_https_url", side_effect=allow):
            with self.assertRaises(ValueError):
                asyncio.run(web_search._bounded_request(
                    oversized, "https://example.test/",
                    allowed_types={"text/plain"}, max_bytes=5,
                ))

        wrong_type = FakeClient([
            FakeResponse(200, {"content-type": "application/octet-stream"}, [b"x"]),
        ])
        with mock.patch.object(web_search, "_validate_public_https_url", side_effect=allow):
            with self.assertRaises(ValueError):
                asyncio.run(web_search._bounded_request(
                    wrong_type, "https://example.test/",
                    allowed_types={"text/plain"}, max_bytes=5,
                ))


class FakeNetworkStream:
    def __init__(self, address="93.184.216.34"):
        self.address = address

    def get_extra_info(self, name):
        return (self.address, 443) if name == "server_addr" else None


class FakeResponse:
    def __init__(self, status, headers, chunks, peer="93.184.216.34"):
        self.status_code = status
        self.headers = headers
        self._chunks = chunks
        self.extensions = {"network_stream": FakeNetworkStream(peer)}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP error")

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def stream(self, *_args, **_kwargs):
        response = self.responses[self.calls]
        self.calls += 1
        return response


class SkillApprovalTests(unittest.TestCase):
    def test_user_skills_require_matching_hash_while_bundled_still_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bundled = base / "bundled"
            user = base / "user"
            bundled.mkdir()
            user.mkdir()
            bundled_source = (
                "async def handle(*args): return 'ok'\n"
                "SKILL={'name':'Bundled','trigger':'bundled','handler':handle}\n"
            ).encode()
            (bundled / "safe.py").write_bytes(bundled_source)
            (bundled / "manifest.json").write_text(
                json.dumps({
                    "version": 1,
                    "files": {
                        "safe.py": hashlib.sha256(bundled_source).hexdigest()
                    },
                }),
                encoding="utf-8",
            )
            marker = base / "executed.txt"
            user_source = (
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "async def handle(*args): return 'ok'\n"
                "SKILL={'name':'User','trigger':'user','handler':handle}\n"
            ).encode()
            (user / "custom.py").write_bytes(user_source)
            original_file = skills.__file__
            skills.__file__ = str(bundled / "__init__.py")
            bundled_digest = hashlib.sha256(bundled_source).hexdigest()
            try:
                with mock.patch.object(skills, "_user_skills_dir", return_value=user), \
                     mock.patch.object(skills, "_user_skill_allowlist_path", return_value=user / "allowlist.json"), \
                     mock.patch.object(skills, "_BUNDLED_SKILL_DIGESTS", {"safe.py": bundled_digest}):
                    loaded = skills.load_all()
                    self.assertEqual([s["name"] for s in loaded], ["Bundled"])
                    self.assertFalse(marker.exists())

                    (user / "allowlist.json").write_text(json.dumps({
                        "version": 1, "approved": {"custom.py": "0" * 64}
                    }))
                    loaded = skills.load_all()
                    self.assertEqual([s["name"] for s in loaded], ["Bundled"])
                    self.assertFalse(marker.exists())

                    digest = hashlib.sha256(user_source).hexdigest()
                    (user / "allowlist.json").write_text(json.dumps({
                        "version": 1, "approved": {"custom.py": digest}
                    }))
                    loaded = skills.load_all()
                    self.assertEqual([s["name"] for s in loaded], ["Bundled", "User"])
                    self.assertTrue(marker.exists())
            finally:
                skills.__file__ = original_file

    def test_bundled_skill_tamper_fails_closed_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "bundled"
            bundled.mkdir()
            marker = Path(tmp) / "executed.txt"
            reviewed = (
                "async def handle(*args): return 'ok'\n"
                "SKILL={'name':'Bundled','trigger':'bundled','handler':handle}\n"
            ).encode()
            tampered = (
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
                "async def handle(*args): return 'bad'\n"
                "SKILL={'name':'Tampered','trigger':'tampered','handler':handle}\n"
            ).encode()
            (bundled / "safe.py").write_bytes(tampered)
            (bundled / "manifest.json").write_text(
                json.dumps({
                    "version": 1,
                    "files": {"safe.py": hashlib.sha256(reviewed).hexdigest()},
                }),
                encoding="utf-8",
            )
            original_file = skills.__file__
            skills.__file__ = str(bundled / "__init__.py")
            try:
                with mock.patch.object(
                    skills, "_user_skills_dir", return_value=Path(tmp) / "user"
                ), mock.patch.object(
                    skills,
                    "_BUNDLED_SKILL_DIGESTS",
                    {"safe.py": hashlib.sha256(reviewed).hexdigest()},
                ):
                    self.assertEqual(skills.load_all(), [])
                    self.assertFalse(marker.exists())
            finally:
                skills.__file__ = original_file

    def test_bundled_manifest_must_cover_every_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "bundled"
            bundled.mkdir()
            source = (
                "async def handle(*args): return 'ok'\n"
                "SKILL={'name':'Bundled','trigger':'bundled','handler':handle}\n"
            ).encode()
            (bundled / "safe.py").write_bytes(source)
            (bundled / "extra.py").write_bytes(source)
            (bundled / "manifest.json").write_text(
                json.dumps({
                    "version": 1,
                    "files": {"safe.py": hashlib.sha256(source).hexdigest()},
                }),
                encoding="utf-8",
            )
            original_file = skills.__file__
            skills.__file__ = str(bundled / "__init__.py")
            try:
                with mock.patch.object(
                    skills, "_user_skills_dir", return_value=Path(tmp) / "user"
                ), mock.patch.object(
                    skills,
                    "_BUNDLED_SKILL_DIGESTS",
                    {"safe.py": hashlib.sha256(source).hexdigest()},
                ):
                    self.assertEqual(skills.load_all(), [])
            finally:
                skills.__file__ = original_file

    def test_replacing_skill_and_manifest_cannot_replace_embedded_trust_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "bundled"
            bundled.mkdir()
            marker = Path(tmp) / "executed.txt"
            tampered = (
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n"
                "async def handle(*args): return 'bad'\n"
                "SKILL={'name':'Tampered','trigger':'tampered','handler':handle}\n"
            ).encode()
            (bundled / "example_self_mode.py").write_bytes(tampered)
            (bundled / "manifest.json").write_text(
                json.dumps({
                    "version": 1,
                    "files": {
                        "example_self_mode.py": hashlib.sha256(tampered).hexdigest()
                    },
                }),
                encoding="utf-8",
            )
            original_file = skills.__file__
            skills.__file__ = str(bundled / "__init__.py")
            try:
                with mock.patch.object(
                    skills, "_user_skills_dir", return_value=Path(tmp) / "user"
                ):
                    self.assertEqual(skills.load_all(), [])
                    self.assertFalse(marker.exists())
            finally:
                skills.__file__ = original_file


class DpapiTokenStoreTests(unittest.TestCase):
    def test_actual_dpapi_round_trip_on_windows(self):
        if os.name != "nt":
            self.skipTest("Windows DPAPI is unavailable")
        sample = b"clicky-dpapi-self-test-not-a-secret"
        protected = github._dpapi_protect(sample)
        self.assertNotEqual(protected, sample)
        self.assertEqual(github._dpapi_unprotect(protected), sample)

    @staticmethod
    def _xor(data: bytes) -> bytes:
        return bytes(value ^ 0xA5 for value in data)

    def test_plaintext_token_is_migrated_then_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            secret = "github-secret-value"
            with mock.patch.object(github, "_data_dir", return_value=data_dir), \
                 mock.patch.object(github, "_is_windows", return_value=True), \
                 mock.patch.object(github, "_dpapi_protect", side_effect=self._xor), \
                 mock.patch.object(github, "_dpapi_unprotect", side_effect=self._xor):
                github._legacy_token_path().write_text(json.dumps({"access_token": secret}))
                self.assertEqual(github.load_github_token(), secret)
                self.assertFalse(github._legacy_token_path().exists())
                encrypted = github._token_path().read_bytes()
                self.assertTrue(encrypted.startswith(github._TOKEN_FILE_MAGIC))
                self.assertNotIn(secret.encode(), encrypted)

    def test_plaintext_token_is_not_loaded_off_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            with mock.patch.object(github, "_data_dir", return_value=data_dir), \
                 mock.patch.object(github, "_is_windows", return_value=False):
                github._legacy_token_path().write_text(json.dumps({"access_token": "secret"}))
                self.assertIsNone(github.load_github_token())
                self.assertTrue(github._legacy_token_path().exists())

    def test_dpapi_failure_keeps_legacy_file_and_returns_no_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            with mock.patch.object(github, "_data_dir", return_value=data_dir), \
                 mock.patch.object(github, "_is_windows", return_value=True), \
                 mock.patch.object(github, "_dpapi_protect", side_effect=OSError("blocked")):
                github._legacy_token_path().write_text(json.dumps({"access_token": "secret"}))
                self.assertIsNone(github.load_github_token())
                self.assertTrue(github._legacy_token_path().exists())


class JournalPrivacyTests(unittest.TestCase):
    def test_config_uses_env_for_secrets_and_json_for_preferences(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": tmp, "OPENAI_API_KEY": "process-only-secret"},
            clear=True,
        ):
            config_source = (ROOT / "config.py").read_text(encoding="utf-8")
            self.assertNotIn("from dotenv", config_source)
            self.assertNotIn("load_dotenv", config_source)
            real_config = load_module("security_test_real_config", "config.py")
            initial = real_config.Config()
            self.assertFalse(initial.journal_enabled)
            self.assertFalse(initial.web_search_enabled)
            self.assertEqual(initial.openai_api_key, "process-only-secret")
            real_config._save_preferences(
                active_llm="openai", journal_enabled=True, web_search_enabled=True
            )
            saved = real_config._preferences_path().read_text(encoding="utf-8")
            self.assertNotIn("process-only-secret", saved)
            reloaded = real_config.Config()
            self.assertEqual(reloaded.active_llm, "openai")
            self.assertTrue(reloaded.journal_enabled)
            self.assertTrue(reloaded.web_search_enabled)

    def test_manager_and_tray_use_persisted_privacy_defaults(self):
        manager_source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        tray_source = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        self.assertIn("self._journal_enabled = bool(cfg.journal_enabled)", manager_source)
        self.assertIn("cfg.set_journal_enabled(self._journal_enabled)", manager_source)
        self.assertIn("self._web_search_enabled = bool(cfg.web_search_enabled)", manager_source)
        self.assertIn("cfg.set_web_search_enabled(self._web_search_enabled)", manager_source)
        self.assertIn("self._journal_enabled = bool(cfg.journal_enabled)", tray_source)
        self.assertIn("self._search_enabled = bool(cfg.web_search_enabled)", tray_source)

    def test_logging_requires_explicit_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.dict(os.environ, {"LOCALAPPDATA": tmp}):
            db = Path(tmp) / "Clicky" / "journal.db"
            self.assertEqual(journal.log_qa("question", "answer"), -1)
            self.assertFalse(db.exists())
            self.assertGreater(
                journal.log_qa("question", "answer", enabled=True), 0
            )
            self.assertTrue(db.exists())


if __name__ == "__main__":
    unittest.main()
