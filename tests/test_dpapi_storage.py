"""Reusable bounded current-user DPAPI storage tests."""

from __future__ import annotations

import ast
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from security import dpapi


ROOT = Path(__file__).resolve().parents[1]
ENTROPY = b"Clicky synthetic DPAPI test v1"
SYNTHETIC = b"clicky-dpapi-test-not-a-secret"


class DpapiBoundaryTests(unittest.TestCase):
    def test_bounds_fail_before_platform_or_native_calls(self):
        with mock.patch.object(
            dpapi,
            "_transform",
            side_effect=AssertionError("native call reached"),
        ):
            invalid_encryptions = (
                b"",
                b"x" * 9,
                bytearray(b"not immutable"),
            )
            for value in invalid_encryptions:
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaises(ValueError):
                        dpapi.encrypt_current_user(
                            value,
                            entropy=ENTROPY,
                            description="Synthetic test",
                            max_plaintext_bytes=8,
                        )
            with self.assertRaises(ValueError):
                dpapi.decrypt_current_user(
                    b"x" * 9,
                    entropy=ENTROPY,
                    max_protected_bytes=8,
                )
            with self.assertRaises(ValueError):
                dpapi.encrypt_current_user(
                    SYNTHETIC,
                    entropy=b"",
                    description="Synthetic test",
                )
            with self.assertRaises(ValueError):
                dpapi.encrypt_current_user(
                    SYNTHETIC,
                    entropy=ENTROPY,
                    description="",
                )
            with self.assertRaises(ValueError):
                dpapi.encrypt_current_user(
                    SYNTHETIC,
                    entropy=ENTROPY,
                    description="Synthetic test",
                    max_protected_bytes=0,
                )
            with self.assertRaises(ValueError):
                dpapi.decrypt_current_user(
                    b"protected",
                    entropy=ENTROPY,
                    max_plaintext_bytes=0,
                )

    @unittest.skipIf(os.name == "nt", "non-Windows boundary only")
    def test_non_windows_fails_with_explicit_unavailable_error(self):
        with self.assertRaises(dpapi.DpapiUnavailableError) as captured:
            dpapi.encrypt_current_user(
                SYNTHETIC,
                entropy=ENTROPY,
                description="Synthetic test",
            )
        self.assertNotIn(
            SYNTHETIC.decode(),
            repr(captured.exception),
        )

    def test_native_outputs_are_bounded_before_return(self):
        with mock.patch.object(
            dpapi,
            "_transform",
            return_value=b"x" * 9,
        ):
            with self.assertRaises(dpapi.DpapiProtectionError):
                dpapi.encrypt_current_user(
                    SYNTHETIC,
                    entropy=ENTROPY,
                    description="Synthetic test",
                    max_protected_bytes=8,
                )
            with self.assertRaises(dpapi.DpapiDecryptionError):
                dpapi.decrypt_current_user(
                    b"protected",
                    entropy=ENTROPY,
                    max_plaintext_bytes=8,
                )

    def test_bounded_delete_wipes_regular_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "legacy.json"
            regular.write_bytes(SYNTHETIC)
            self.assertTrue(
                dpapi.delete_file_bounded(
                    regular,
                    max_file_bytes=1024,
                    overwrite=True,
                )
            )
            self.assertFalse(regular.exists())
            self.assertFalse(
                dpapi.delete_file_bounded(
                    regular,
                    max_file_bytes=1024,
                    overwrite=True,
                )
            )

    def test_bounded_delete_never_follows_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_bytes(SYNTHETIC)
            link = root / "legacy-link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable")
            self.assertTrue(
                dpapi.delete_file_bounded(
                    link,
                    max_file_bytes=1024,
                    overwrite=True,
                )
            )
            self.assertFalse(link.exists())
            self.assertEqual(target.read_bytes(), SYNTHETIC)

    def test_bounded_delete_rejects_oversized_and_non_regular_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * 9)
            with self.assertRaises(dpapi.DpapiDeleteError):
                dpapi.delete_file_bounded(
                    oversized,
                    max_file_bytes=8,
                    overwrite=True,
                )
            self.assertTrue(oversized.exists())
            with self.assertRaises(dpapi.DpapiDeleteError):
                dpapi.delete_file_bounded(
                    root,
                    max_file_bytes=1024,
                )

    def test_bounded_delete_refuses_hard_linked_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.txt"
            target.write_bytes(SYNTHETIC)
            linked = root / "legacy.json"
            try:
                os.link(target, linked)
            except OSError:
                self.skipTest("hard links are unavailable")

            with self.assertRaises(dpapi.DpapiDeleteError):
                dpapi.delete_file_bounded(
                    linked,
                    max_file_bytes=1024,
                    overwrite=True,
                )
            self.assertEqual(linked.read_bytes(), SYNTHETIC)
            self.assertEqual(target.read_bytes(), SYNTHETIC)

    def test_copilot_keeps_existing_location_magic_and_context_wrappers(self):
        source = (
            ROOT / "ai" / "github_copilot_provider.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module == "security.dpapi"
            for alias in node.names
        }
        self.assertEqual(
            imported,
            {
                "decrypt_current_user",
                "delete_file_bounded",
                "encrypt_current_user",
            },
        )
        self.assertIn('b"CLICKY-DPAPI\\x00\\x01"', source)
        self.assertIn('b"Clicky GitHub Copilot token v1"', source)
        self.assertIn('"github_token.dpapi"', source)
        self.assertNotIn("CryptProtectData", source)
        self.assertNotIn("CryptUnprotectData", source)

    def test_dpapi_source_is_current_user_only_and_has_no_logging(self):
        source = (
            ROOT / "security" / "dpapi.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )

        self.assertNotIn("logging", imported)
        self.assertNotIn("CRYPTPROTECT_LOCAL_MACHINE", source)
        self.assertEqual(dpapi._CRYPTPROTECT_UI_FORBIDDEN, 0x1)


@unittest.skipUnless(os.name == "nt", "Windows DPAPI is unavailable")
class DpapiWindowsTests(unittest.TestCase):
    def test_current_user_round_trip_and_context_isolation(self):
        protected = dpapi.encrypt_current_user(
            SYNTHETIC,
            entropy=ENTROPY,
            description="Clicky synthetic test",
            max_plaintext_bytes=1024,
            max_protected_bytes=4096,
        )

        self.assertNotIn(SYNTHETIC, protected)
        self.assertEqual(
            dpapi.decrypt_current_user(
                protected,
                entropy=ENTROPY,
                max_protected_bytes=4096,
                max_plaintext_bytes=1024,
            ),
            SYNTHETIC,
        )
        with self.assertRaises(dpapi.DpapiDecryptionError) as captured:
            dpapi.decrypt_current_user(
                protected,
                entropy=b"Clicky different synthetic context",
                max_protected_bytes=4096,
                max_plaintext_bytes=1024,
            )
        rendered = repr(captured.exception)
        self.assertIn("corrupt or belongs to another Windows user", rendered)
        self.assertNotIn(SYNTHETIC.decode(), rendered)

    def test_corrupt_ciphertext_has_content_free_explicit_error(self):
        protected = dpapi.encrypt_current_user(
            SYNTHETIC,
            entropy=ENTROPY,
            description="Clicky synthetic test",
        )
        corrupted = protected[:-1] + bytes([protected[-1] ^ 0xA5])

        with self.assertRaises(dpapi.DpapiDecryptionError) as captured:
            dpapi.decrypt_current_user(
                corrupted,
                entropy=ENTROPY,
            )
        self.assertNotIn(
            SYNTHETIC.decode(),
            repr(captured.exception),
        )


if __name__ == "__main__":
    unittest.main()
