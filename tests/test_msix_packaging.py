"""MSIX staging, identity, and exact-input gates."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree

from PIL import Image

from tools.build_msix import (
    MsixPackagingError,
    _ASSET_SIZES,
    _validate_output_boundaries,
    prepare_staging,
    render_manifest,
    resolve_identity,
    tree_identity,
    validate_identity,
)


COMMIT = "a" * 40
MAKEAPPX_SHA256 = "b" * 64


class MsixPackagingTests(unittest.TestCase):
    def make_distribution(self, root: Path, *, store: bool = True) -> Path:
        distribution = root / "distribution"
        (distribution / "_internal").mkdir(parents=True)
        (distribution / "Clicky.exe").write_bytes(b"synthetic-executable")
        (distribution / "_internal" / "module.pyc").write_bytes(
            b"synthetic-bytecode"
        )
        (distribution / "SOURCE-COMMIT.txt").write_text(
            COMMIT + "\n",
            encoding="ascii",
        )
        marker = (
            "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
            if store
            else "UNSIGNED-LOCAL-TEST-ONLY.txt"
        )
        (distribution / marker).write_text("unsigned\n", encoding="utf-8")
        return distribution

    def test_manifest_uses_full_trust_desktop_identity_and_brand(self):
        encoded = render_manifest(
            identity_name="Partner.Clicky",
            publisher="CN=Manuel Parra",
            publisher_display_name="Manuel Parra",
            version="1.2.0.0",
        )
        text = encoded.decode("utf-8")
        ElementTree.fromstring(encoded)
        self.assertIn('Name="Partner.Clicky"', text)
        self.assertIn('Publisher="CN=Manuel Parra"', text)
        self.assertIn("<PublisherDisplayName>Manuel Parra", text)
        self.assertIn("developed by th3nolo", text)
        self.assertIn('Name="Windows.Desktop"', text)
        self.assertIn('uap10:RuntimeBehavior="packagedClassicApp"', text)
        self.assertIn('uap10:TrustLevel="mediumIL"', text)
        self.assertIn('<rescap:Capability Name="runFullTrust"', text)
        self.assertIn('Executable="Clicky\\Clicky.exe"', text)

    def test_manifest_identity_is_bounded_and_requires_publisher_dn(self):
        for identity, publisher, version in (
            ("ab", "CN=Manuel Parra", "1.2.0.0"),
            ("bad identity", "CN=Manuel Parra", "1.2.0.0"),
            ("Partner.Clicky", "Manuel Parra", "1.2.0.0"),
            ("Partner.Clicky", "CN=Manuel Parra", "1.2.0"),
            ("Partner.Clicky", "CN=Manuel Parra", "65536.0.0.0"),
        ):
            with self.subTest(identity=identity, publisher=publisher, version=version):
                with self.assertRaises(MsixPackagingError):
                    validate_identity(
                        identity,
                        publisher,
                        "Manuel Parra",
                        version,
                    )

    def test_store_identity_requires_explicit_partner_center_confirmation(self):
        with self.assertRaisesRegex(MsixPackagingError, "Partner Center"):
            resolve_identity(
                validation_only=False,
                partner_center_confirmed=False,
                identity_name="Partner.Clicky",
                publisher="CN=Manuel Parra",
                publisher_display_name="Manuel Parra",
            )
        self.assertEqual(
            resolve_identity(
                validation_only=False,
                partner_center_confirmed=True,
                identity_name="Partner.Clicky",
                publisher="CN=Manuel Parra",
                publisher_display_name="Manuel Parra",
            ),
            ("Partner.Clicky", "CN=Manuel Parra", "Manuel Parra"),
        )

    def test_validation_identity_refuses_store_values(self):
        with self.assertRaisesRegex(MsixPackagingError, "non-Store identity"):
            resolve_identity(
                validation_only=True,
                partner_center_confirmed=True,
                identity_name="Partner.Clicky",
                publisher="CN=Manuel Parra",
                publisher_display_name="Manuel Parra",
            )
        self.assertEqual(
            resolve_identity(
                validation_only=True,
                partner_center_confirmed=False,
                identity_name=None,
                publisher=None,
                publisher_display_name=None,
            ),
            (
                "th3nolo.Clicky.Validation",
                "CN=Clicky Local Validation",
                "Manuel Parra",
            ),
        )

    def test_outputs_cannot_mutate_distribution_or_preserved_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            distribution = root / "distribution"
            distribution.mkdir()
            staging = root / "staging"
            with self.assertRaisesRegex(
                MsixPackagingError,
                "must not contain one another",
            ):
                _validate_output_boundaries(
                    distribution=distribution,
                    staging=staging,
                    output=distribution / "Clicky.msix",
                    report=root / "report.json",
                )
            with self.assertRaisesRegex(
                MsixPackagingError,
                "outside preserved staging",
            ):
                _validate_output_boundaries(
                    distribution=distribution,
                    staging=staging,
                    output=staging / "Clicky.msix",
                    report=root / "report.json",
                )

    def test_validation_staging_preserves_complete_onedir_and_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            distribution = self.make_distribution(root, store=False)
            original = tree_identity(distribution)
            staging = root / "staging"
            metadata = prepare_staging(
                distribution=distribution,
                staging=staging,
                identity_name="th3nolo.Clicky.Validation",
                publisher="CN=Clicky Local Validation",
                publisher_display_name="Manuel Parra",
                version="1.2.0.0",
                source_commit=COMMIT,
                validation_only=True,
                makeappx_sha256=MAKEAPPX_SHA256,
            )
            self.assertEqual(tree_identity(staging / "Clicky"), original)
            self.assertEqual(metadata["application_input"], original)
            self.assertTrue((staging / "UNSIGNED-VALIDATION-ONLY.txt").is_file())
            identity = json.loads(
                (staging / "MSIX-INPUT-IDENTITY.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(identity["legal_publisher"], "Manuel Parra")
            self.assertEqual(identity["brand"], "th3nolo")
            for name, size in _ASSET_SIZES.items():
                with Image.open(staging / "Assets" / name) as image:
                    self.assertEqual(image.size, size)
                    self.assertEqual(image.format, "PNG")

    def test_store_staging_requires_dedicated_marker_and_matching_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local_distribution = self.make_distribution(root, store=False)
            with self.assertRaisesRegex(
                MsixPackagingError,
                "dedicated unsigned Store input",
            ):
                prepare_staging(
                    distribution=local_distribution,
                    staging=root / "local-stage",
                    identity_name="Partner.Clicky",
                    publisher="CN=Manuel Parra",
                    publisher_display_name="Manuel Parra",
                    version="1.2.0.0",
                    source_commit=COMMIT,
                    validation_only=False,
                    makeappx_sha256=MAKEAPPX_SHA256,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            distribution = self.make_distribution(root, store=True)
            with self.assertRaisesRegex(MsixPackagingError, "source commit"):
                prepare_staging(
                    distribution=distribution,
                    staging=root / "commit-stage",
                    identity_name="Partner.Clicky",
                    publisher="CN=Manuel Parra",
                    publisher_display_name="Manuel Parra",
                    version="1.2.0.0",
                    source_commit="c" * 40,
                    validation_only=False,
                    makeappx_sha256=MAKEAPPX_SHA256,
                )

    def test_tree_identity_binds_relative_paths_and_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "one.bin").write_bytes(b"same")
            (second / "two.bin").write_bytes(b"same")
            self.assertNotEqual(
                tree_identity(first)["tree_sha256"],
                tree_identity(second)["tree_sha256"],
            )


if __name__ == "__main__":
    unittest.main()
