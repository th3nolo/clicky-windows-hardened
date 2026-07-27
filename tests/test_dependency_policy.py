"""Standard-library tests for dependency provenance and policy parsing."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "clicky_dependency_policy_test",
    ROOT / "tools" / "check_dependency_policy.py",
)
assert SPEC is not None and SPEC.loader is not None
policy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = policy
SPEC.loader.exec_module(policy)


NOW = datetime(2026, 7, 26, 12, 0, tzinfo=timezone.utc)
ARTIFACT_URL = (
    "https://files.pythonhosted.org/packages/aa/bb/"
    "demo-1.0.0-py3-none-any.whl"
)
ARTIFACT_DIGEST = "a" * 64
ARTIFACT_SIZE = 123

TLS_CONTEXT = object()

def _release() -> policy.LockedRelease:
    return policy.LockedRelease(
        name="demo",
        version="1.0.0",
        artifacts=(
            policy.LockedArtifact(
                url=ARTIFACT_URL,
                sha256=ARTIFACT_DIGEST,
                size=ARTIFACT_SIZE,
            ),
        ),
    )


def _metadata(*, uploaded: datetime | None = None) -> dict:
    timestamp = uploaded or NOW - timedelta(hours=72)
    return {
        "info": {"name": "Demo", "version": "1.0.0", "yanked": False},
        "urls": [
            {
                "url": ARTIFACT_URL,
                "filename": "demo-1.0.0-py3-none-any.whl",
                "digests": {"sha256": ARTIFACT_DIGEST},
                "size": ARTIFACT_SIZE,
                "yanked": False,
                "upload_time_iso_8601": timestamp.isoformat(),
            }
        ],
    }


class PyPIMetadataPolicyTests(unittest.TestCase):
    def test_exact_artifact_at_72_hours_is_accepted(self) -> None:
        checked = policy._check_locked_release_metadata(
            _release(), _metadata(), now=NOW
        )
        self.assertEqual(checked, 1)

    def test_release_identity_must_match(self) -> None:
        for field, value in (("name", "other"), ("version", "2.0.0")):
            with self.subTest(field=field):
                metadata = _metadata()
                metadata["info"][field] = value
                with self.assertRaisesRegex(AssertionError, "identity mismatch"):
                    policy._check_locked_release_metadata(
                        _release(), metadata, now=NOW
                    )

    def test_release_and_artifact_yank_state_fail_closed(self) -> None:
        release_yanked = _metadata()
        release_yanked["info"]["yanked"] = True
        with self.assertRaisesRegex(AssertionError, "release .* yanked"):
            policy._check_locked_release_metadata(
                _release(), release_yanked, now=NOW
            )

        ambiguous_artifact = _metadata()
        del ambiguous_artifact["urls"][0]["yanked"]
        with self.assertRaisesRegex(AssertionError, "artifact is yanked or ambiguous"):
            policy._check_locked_release_metadata(
                _release(), ambiguous_artifact, now=NOW
            )

    def test_missing_locked_artifact_is_rejected(self) -> None:
        metadata = _metadata()
        metadata["urls"][0]["url"] = ARTIFACT_URL + ".different"
        with self.assertRaisesRegex(AssertionError, "missing from PyPI"):
            policy._check_locked_release_metadata(_release(), metadata, now=NOW)

    def test_hash_size_and_filename_must_match(self) -> None:
        cases = (
            ("digests", {"sha256": "b" * 64}, "SHA-256"),
            ("size", ARTIFACT_SIZE + 1, "size"),
            ("filename", "different.whl", "filename"),
        )
        for field, value, expected_error in cases:
            with self.subTest(field=field):
                metadata = _metadata()
                metadata["urls"][0][field] = value
                with self.assertRaisesRegex(AssertionError, expected_error):
                    policy._check_locked_release_metadata(
                        _release(), metadata, now=NOW
                    )

    def test_artifact_younger_than_72_hours_is_rejected(self) -> None:
        metadata = _metadata(uploaded=NOW - timedelta(hours=71, minutes=59))
        with self.assertRaisesRegex(AssertionError, "72 hours are required"):
            policy._check_locked_release_metadata(_release(), metadata, now=NOW)

    def test_missing_malformed_and_future_timestamps_are_rejected(self) -> None:
        for value, expected_error in (
            (None, "no authoritative"),
            ("not-a-date", "malformed"),
            ((NOW + timedelta(seconds=1)).isoformat(), "future"),
        ):
            with self.subTest(value=value):
                metadata = _metadata()
                metadata["urls"][0]["upload_time_iso_8601"] = value
                with self.assertRaisesRegex(AssertionError, expected_error):
                    policy._check_locked_release_metadata(
                        _release(), metadata, now=NOW
                    )

    def test_live_validation_counts_exact_locked_artifacts(self) -> None:
        with mock.patch.object(
            policy, "_fetch_pypi_release", return_value=_metadata()
        ) as fetch:
            checked = policy.check_pypi_releases(
                (_release(),), now=NOW, ssl_context=TLS_CONTEXT
            )
        self.assertEqual(checked, 1)
        fetch.assert_called_once_with(_release(), ssl_context=TLS_CONTEXT)


class ReviewedTrustBundleTests(unittest.TestCase):
    def _fixture(self, root: Path) -> Path:
        trust = root / "tools" / "trust"
        trust.mkdir(parents=True)
        source = policy.ROOT / "tools" / "trust"
        bundle = trust / f"certifi-{policy.REVIEWED_CERTIFI_VERSION}.pem"
        license_path = trust / f"LICENSE.certifi-{policy.REVIEWED_CERTIFI_VERSION}"
        bundle.write_bytes(
            (source / f"certifi-{policy.REVIEWED_CERTIFI_VERSION}.pem").read_bytes()
        )
        license_path.write_bytes(
            (source / f"LICENSE.certifi-{policy.REVIEWED_CERTIFI_VERSION}").read_bytes()
        )
        return bundle

    def test_context_uses_reviewed_bundle_and_secure_defaults(self) -> None:
        bundle = policy.check_trust_bundle()
        context = policy._reviewed_ca_context(bundle)
        self.assertEqual(context.verify_mode, policy.ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertGreaterEqual(context.cert_store_stats()["x509_ca"], 100)

    def test_tampered_linked_and_oversized_bundle_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._fixture(root)
            with mock.patch.object(policy, "ROOT", root):
                bundle.write_bytes(b"tampered")
                with self.assertRaisesRegex(AssertionError, "SHA-256"):
                    policy.check_trust_bundle()

                bundle.write_bytes(b"x" * (policy.MAX_CA_BUNDLE_BYTES + 1))
                with self.assertRaisesRegex(AssertionError, "size limit"):
                    policy.check_trust_bundle()

                with mock.patch.object(Path, "is_symlink", return_value=True):
                    with self.assertRaisesRegex(AssertionError, "linked"):
                        policy.check_trust_bundle()

                reparse = mock.Mock(st_file_attributes=0x400, st_size=1)
                with mock.patch.object(Path, "is_symlink", return_value=False), mock.patch.object(
                    Path, "lstat", return_value=reparse
                ):
                    with self.assertRaisesRegex(AssertionError, "linked"):
                        policy.check_trust_bundle()

    def test_invalid_pem_fails_without_ambient_trust_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle = self._fixture(root)
            invalid = b"not a certificate bundle\n"
            bundle.write_bytes(invalid)
            digest = hashlib.sha256(invalid).hexdigest()
            with mock.patch.object(policy, "ROOT", root), mock.patch.object(
                policy, "REVIEWED_CA_BUNDLE_SHA256", digest
            ), self.assertRaisesRegex(AssertionError, "could not load"):
                policy._reviewed_ca_context(bundle)


    def test_trust_source_is_bound_to_the_exact_locked_wheel(self) -> None:
        url = (
            "https://files.pythonhosted.org/packages/ef/2f/"
            "c5464532e965badff2f4c4c1a3a83f5697f0d7c407ed0cda44aaa99bb451/"
            "certifi-2026.6.17-py3-none-any.whl"
        )
        artifact = policy.LockedArtifact(
            url=url,
            sha256=policy.REVIEWED_CERTIFI_WHEEL_SHA256,
            size=policy.REVIEWED_CERTIFI_WHEEL_SIZE,
        )
        release = policy.LockedRelease(
            name="certifi",
            version=policy.REVIEWED_CERTIFI_VERSION,
            artifacts=(artifact,),
        )
        policy.check_trust_bundle_lock((release,))

        cases = (
            policy.LockedRelease("certifi", "0", (artifact,)),
            policy.LockedRelease(
                "certifi",
                policy.REVIEWED_CERTIFI_VERSION,
                (policy.LockedArtifact(url, "0" * 64, artifact.size),),
            ),
            policy.LockedRelease(
                "certifi",
                policy.REVIEWED_CERTIFI_VERSION,
                (policy.LockedArtifact(url, artifact.sha256, artifact.size + 1),),
            ),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(AssertionError):
                policy.check_trust_bundle_lock((candidate,))

class _FakeResponse:
    def __init__(self, payload: bytes, *, url: str, status: int = 200) -> None:
        self.payload = payload
        self.url = url
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class PyPIFetchBoundaryTests(unittest.TestCase):
    def test_fetch_uses_version_endpoint_and_bounded_response(self) -> None:
        payload = json.dumps(_metadata()).encode("utf-8")
        calls = []

        def opener(request, *, timeout, context):
            calls.append((request, timeout, context))
            return _FakeResponse(
                payload,
                url="https://pypi.org/pypi/demo/1.0.0/json",
            )

        self.assertEqual(
            policy._fetch_pypi_release(
                _release(), opener=opener, ssl_context=TLS_CONTEXT
            ),
            _metadata(),
        )
        self.assertEqual(len(calls), 1)
        request, timeout, context = calls[0]
        self.assertEqual(request.full_url, "https://pypi.org/pypi/demo/1.0.0/json")
        self.assertEqual(timeout, policy.PYPI_METADATA_TIMEOUT_SECONDS)
        self.assertIs(context, TLS_CONTEXT)
        self.assertEqual(request.get_header("Accept"), "application/json")

    def test_fetch_rejects_redirect_outside_pypi(self) -> None:
        def opener(request, *, timeout, context):
            return _FakeResponse(
                json.dumps(_metadata()).encode("utf-8"),
                url="https://attacker.example/metadata.json",
            )

        with self.assertRaisesRegex(AssertionError, "outside pypi.org"):
            policy._fetch_pypi_release(
                _release(), opener=opener, ssl_context=TLS_CONTEXT
            )

    def test_fetch_rejects_invalid_or_oversized_json(self) -> None:
        cases = (
            (b"not-json", "invalid JSON"),
            (b"x" * (policy.MAX_PYPI_METADATA_BYTES + 1), "too large"),
        )
        for payload, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                def opener(request, *, timeout, context):
                    return _FakeResponse(
                        payload,
                        url="https://pypi.org/pypi/demo/1.0.0/json",
                    )

                with self.assertRaisesRegex(AssertionError, expected_error):
                    policy._fetch_pypi_release(
                        _release(), opener=opener, ssl_context=TLS_CONTEXT
                    )


class BundledSkillPolicyTests(unittest.TestCase):
    def _write_fixture(self, root: Path) -> tuple[Path, bytes]:
        directory = root / "skills"
        directory.mkdir()
        source = b"SKILL = {'name': 'safe'}\n"
        digest = hashlib.sha256(source).hexdigest()
        skill = directory / "safe.py"
        skill.write_bytes(source)
        (directory / "manifest.json").write_text(
            json.dumps({
                "version": 1,
                "files": {"safe.py": digest},
            }),
            encoding="utf-8",
        )
        (directory / "__init__.py").write_text(
            "from types import MappingProxyType\n"
            f"_BUNDLED_SKILL_DIGESTS = MappingProxyType({{'safe.py': {digest!r}}})\n",
            encoding="utf-8",
        )
        return skill, source

    def test_exact_bundled_skill_manifest_is_accepted(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)
            with mock.patch.object(policy, "ROOT", root):
                policy.check_bundled_skills()

    def test_tampered_or_unlisted_bundled_skill_fails_closed(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill, _source = self._write_fixture(root)
            skill.write_bytes(b"tampered")
            with mock.patch.object(policy, "ROOT", root), self.assertRaisesRegex(
                AssertionError, "manifest digest"
            ):
                policy.check_bundled_skills()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)
            (root / "skills" / "extra.py").write_bytes(b"unlisted")
            with mock.patch.object(policy, "ROOT", root), self.assertRaisesRegex(
                AssertionError, "cover exactly"
            ):
                policy.check_bundled_skills()


class BundledDeclarativeSkillPolicyTests(unittest.TestCase):
    def _write_fixture(self, root: Path) -> tuple[Path, bytes, str]:
        directory = root / "skills" / "declarative"
        directory.mkdir(parents=True)
        definition = b'{"schema_version":1}\n'
        digest = hashlib.sha256(definition).hexdigest()
        skill = directory / "safe.skill.json"
        skill.write_bytes(definition)
        (directory / "manifest.json").write_text(
            json.dumps(
                {
                    "files": {"safe.skill.json": digest},
                    "version": 1,
                }
            ),
            encoding="utf-8",
        )
        (root / "skills" / "registry.py").write_text(
            "from types import MappingProxyType\n"
            "_BUNDLED_DECLARATIVE_SKILL_DIGESTS = "
            f"MappingProxyType({{'safe.skill.json': {digest!r}}})\n",
            encoding="utf-8",
        )
        return skill, definition, digest

    def test_exact_declarative_manifest_is_accepted(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)
            with mock.patch.object(policy, "ROOT", root):
                policy.check_bundled_declarative_skills()

    def test_tampered_unlisted_or_reanchored_definition_fails(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill, _source, _digest = self._write_fixture(root)
            skill.write_bytes(b"tampered")
            with mock.patch.object(policy, "ROOT", root), self.assertRaisesRegex(
                AssertionError,
                "digest differs",
            ):
                policy.check_bundled_declarative_skills()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._write_fixture(root)
            (root / "skills" / "declarative" / "extra.txt").write_text(
                "unlisted",
                encoding="utf-8",
            )
            with mock.patch.object(policy, "ROOT", root), self.assertRaisesRegex(
                AssertionError,
                "unlisted content",
            ):
                policy.check_bundled_declarative_skills()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skill, _source, _digest = self._write_fixture(root)
            replacement = b'{"schema_version":2}\n'
            replacement_digest = hashlib.sha256(replacement).hexdigest()
            skill.write_bytes(replacement)
            (root / "skills" / "declarative" / "manifest.json").write_text(
                json.dumps(
                    {
                        "files": {
                            "safe.skill.json": replacement_digest
                        },
                        "version": 1,
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(policy, "ROOT", root), self.assertRaisesRegex(
                AssertionError,
                "embedded anchor",
            ):
                policy.check_bundled_declarative_skills()


VALID_BUILD = (ROOT / "build.bat").read_text(encoding="utf-8")
VALID_WORKFLOW = r'''
name: Dependency policy

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  validate:
    runs-on: windows-2022
    timeout-minutes: 5
    steps:
      - name: Check out the reviewed revision
        uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
        with:
          persist-credentials: false

      - name: Set up the pinned Python runtime
        uses: actions/setup-python@e797f83bcb11b83ae66e0230d6156d7c80228e7c # v6.0.0
        with:
          python-version: "3.12.10"
          cache: ""
          check-latest: false

      - name: Validate dependency policy
        shell: pwsh
        run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem
'''


class PackagingPolicyTests(unittest.TestCase):
    def test_packaging_policy_requires_external_python_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "installer.iss").write_bytes((ROOT / "installer.iss").read_bytes())
            (root / "build.bat").write_bytes((ROOT / "build.bat").read_bytes())
            spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
            (root / "clicky.spec").write_text(spec, encoding="utf-8")
            (root / "packaging").mkdir()
            (root / "packaging" / "AppxManifest.xml.in").write_bytes(
                (ROOT / "packaging" / "AppxManifest.xml.in").read_bytes()
            )
            (root / "packaging" / "UNSIGNED-STORE-SUBMISSION-INPUT.txt").write_bytes(
                (
                    ROOT
                    / "packaging"
                    / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
                ).read_bytes()
            )
            (root / "tools").mkdir()
            (root / "tools" / "build_msix.py").write_bytes(
                (ROOT / "tools" / "build_msix.py").read_bytes()
            )
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "msix-validation.yml").write_bytes(
                (
                    ROOT / ".github" / "workflows" / "msix-validation.yml"
                ).read_bytes()
            )

            with mock.patch.object(policy, "ROOT", root):
                policy.check_packaging_policy()
                (root / "clicky.spec").write_text(
                    spec.replace("noarchive=True", "noarchive=False"),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    AssertionError,
                    "keep Python bytecode external and inspectable",
                ):
                    policy.check_packaging_policy()


class BatchAndWorkflowPolicyTests(unittest.TestCase):
    def test_effective_hardened_commands_are_accepted(self) -> None:
        policy.check_build_script(
            build_text=VALID_BUILD,
            workflow_text=VALID_WORKFLOW,
        )

    def test_prefix_like_argument_does_not_satisfy_policy(self) -> None:
        tampered = VALID_BUILD.replace("--group build", "--group buildx")
        with self.assertRaisesRegex(AssertionError, "exact reviewed argument"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_command_boundaries_and_expansions_cannot_supply_arguments(self) -> None:
        insertions = (
            "& rem",
            "&& rem",
            "|| rem",
            "| rem",
            ">nul & rem",
            "%UNREVIEWED_ARGUMENTS%",
            "--no-frozen",
        )
        for insertion in insertions:
            with self.subTest(insertion=insertion):
                tampered = VALID_BUILD.replace(
                    "uv sync --frozen",
                    f"uv sync {insertion} --frozen",
                    1,
                )
                with self.assertRaisesRegex(
                    AssertionError, "exact reviewed argument"
                ):
                    policy.check_build_script(
                        build_text=tampered,
                        workflow_text=VALID_WORKFLOW,
                    )

    def test_required_command_inside_dead_block_is_rejected(self) -> None:
        sync = (
            "uv sync --frozen --group build --no-build "
            "--no-managed-python --no-python-downloads "
            '--python "%EXPECTED_PYTHON_VERSION%" '
            '--default-index "%PYPI_INDEX%" --index-strategy first-index '
            "--keyring-provider disabled --link-mode copy --no-cache"
        )
        nested = "if 1==0 (\n  " + sync.replace("\n", "\n  ") + "\n)"
        tampered = VALID_BUILD.replace(sync, nested)
        with self.assertRaisesRegex(AssertionError, "top-level uv sync"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_early_top_level_goto_is_rejected(self) -> None:
        tampered = VALID_BUILD.replace(
            "uv lock --check", "goto :cleanup\nuv lock --check", 1
        )
        with self.assertRaisesRegex(AssertionError, "top-level transfer"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_uv_failure_block_cannot_mask_failure(self) -> None:
        tampered = VALID_BUILD.replace(
            "    echo [ERROR] uv.lock does not match pyproject.toml.\n"
            "    goto :cleanup",
            "    echo [ERROR] uv.lock does not match pyproject.toml.\n"
            "    exit /b 0\n"
            "    goto :cleanup",
            1,
        )
        self.assertNotEqual(tampered, VALID_BUILD)
        with self.assertRaisesRegex(AssertionError, "exact reviewed fail-closed body"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_unconditional_replacement_for_reviewed_guard_is_rejected(self) -> None:
        tampered = VALID_BUILD.replace(
            'if /I "%~1"=="installer" (',
            "if 1==1 (",
            1,
        )
        with self.assertRaisesRegex(AssertionError, "exact reviewed conditions"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_critical_build_settings_cannot_be_reassigned(self) -> None:
        cases = (
            'set "EXPECTED_UV_VERSION=9.9.9"',
            'set "EXPECTED_PYTHON_VERSION=9.9.9"',
            'set "PYPI_INDEX=https://attacker.example/simple"',
        )
        for reassignment in cases:
            with self.subTest(reassignment=reassignment):
                tampered = VALID_BUILD.replace(
                    "uv lock --check",
                    f"{reassignment}\nuv lock --check",
                    1,
                )
                with self.assertRaisesRegex(
                    AssertionError, "exactly one reviewed assignment"
                ):
                    policy.check_build_script(
                        build_text=tampered,
                        workflow_text=VALID_WORKFLOW,
                    )

    def test_command_name_indirection_is_rejected(self) -> None:
        variants = (
            'set "ASSIGN=set"\n!ASSIGN! "EXPECTED_UV_VERSION=9.9.9"',
            'set "ASSIGN=set"\n%ASSIGN% "EXPECTED_UV_VERSION=9.9.9"',
            'for %%A in (set) do %%A "EXPECTED_UV_VERSION=9.9.9"',
        )
        for commands in variants:
            with self.subTest(commands=commands):
                tampered = VALID_BUILD.replace(
                    "uv lock --check",
                    f"{commands}\nuv lock --check",
                    1,
                )
                with self.assertRaisesRegex(
                    AssertionError, "exact reviewed build script content"
                ):
                    policy.check_build_script(
                        build_text=tampered,
                        workflow_text=VALID_WORKFLOW,
                    )

    def test_caret_obfuscated_build_setting_reassignment_is_rejected(self) -> None:
        variants = (
            's^et "EXPECTED_UV_VERSION=9.9.9"',
            'set^ "EXPECTED_UV_VERSION=9.9.9"',
            '^set "EXPECTED_UV_VERSION=9.9.9"',
        )
        for reassignment in variants:
            with self.subTest(reassignment=reassignment):
                tampered = VALID_BUILD.replace(
                    "uv lock --check",
                    f"{reassignment}\nuv lock --check",
                    1,
                )
                with self.assertRaisesRegex(AssertionError, "unreviewed caret escaping"):
                    policy.check_build_script(
                        build_text=tampered,
                        workflow_text=VALID_WORKFLOW,
                    )

    def test_indirect_build_setting_reassignment_is_rejected(self) -> None:
        tampered = VALID_BUILD.replace(
            "uv lock --check",
            'set "TARGET_SETTING=EXPECTED_UV_VERSION"\n'
            'set "!TARGET_SETTING!=9.9.9"\n'
            "uv lock --check",
            1,
        )
        with self.assertRaisesRegex(AssertionError, "static variable names"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_critical_build_setting_inside_guard_is_rejected(self) -> None:
        assignment = 'set "EXPECTED_UV_VERSION=0.11.19"'
        tampered = VALID_BUILD.replace(f"{assignment}\n", "", 1).replace(
            'if /I "%~1"=="installer" (',
            f'if /I "%~1"=="installer" (\n  {assignment}',
            1,
        )
        with self.assertRaisesRegex(AssertionError, "top-level preamble"):
            policy.check_build_script(
                build_text=tampered,
                workflow_text=VALID_WORKFLOW,
            )

    def test_comments_cannot_satisfy_required_commands(self) -> None:
        commented = "\n".join(f"REM {line}" for line in VALID_BUILD.splitlines())
        with self.assertRaisesRegex(AssertionError, "pinned settings"):
            policy.check_build_script(
                build_text=commented,
                workflow_text=VALID_WORKFLOW,
            )

    def test_pip_executable_variants_and_tabs_are_rejected(self) -> None:
        for command in ("pip.exe install bad", "pip3.exe\tinstall bad", "python -m pip install bad"):
            with self.subTest(command=command):
                with self.assertRaisesRegex(AssertionError, "pip executable"):
                    policy.check_build_script(
                        build_text=VALID_BUILD + "\n" + command,
                        workflow_text=VALID_WORKFLOW,
                    )

    def test_inno_setup_alias_is_rejected(self) -> None:
        with self.assertRaisesRegex(AssertionError, "Inno Setup"):
            policy.check_build_script(
                build_text=VALID_BUILD + '\nset "CLICKY_ISCC=disabled"',
                workflow_text=VALID_WORKFLOW,
            )

    def test_commented_pypi_check_cannot_satisfy_workflow(self) -> None:
        workflow = VALID_WORKFLOW.replace(
            "        run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem",
            "        # run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem\n"
            "        run: python tools/check_dependency_policy.py",
        )
        with self.assertRaisesRegex(AssertionError, "CI dependency-policy step"):
            policy.check_build_script(
                build_text=VALID_BUILD,
                workflow_text=workflow,
            )

    def test_inline_comment_cannot_supply_verify_pypi_flag(self) -> None:
        workflow = VALID_WORKFLOW.replace(
            "        run: python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem",
            "        run: python tools/check_dependency_policy.py # --verify-pypi",
        )
        with self.assertRaisesRegex(AssertionError, "CI dependency-policy step"):
            policy.check_build_script(
                build_text=VALID_BUILD,
                workflow_text=workflow,
            )

    def test_echo_dead_conditional_and_masked_failure_are_rejected(self) -> None:
        command = "python tools/check_dependency_policy.py --verify-pypi --ca-bundle tools/trust/certifi-2026.6.17.pem"
        variants = (
            f"echo {command}",
            f"if ($false) {{ {command} }}",
            f"{command} || exit 0",
            f'Write-Output "{command}"',
        )
        for variant in variants:
            with self.subTest(variant=variant):
                workflow = VALID_WORKFLOW.replace(
                    f"        run: {command}",
                    f"        run: {variant}",
                )
                with self.assertRaisesRegex(
                    AssertionError, "exact unconditional, unmasked"
                ):
                    policy.check_build_script(
                        build_text=VALID_BUILD,
                        workflow_text=workflow,
                    )

    def test_step_or_job_conditions_and_continue_on_error_are_rejected(self) -> None:
        variants = (
            VALID_WORKFLOW.replace(
                "        shell: pwsh",
                "        if: false\n        shell: pwsh",
            ),
            VALID_WORKFLOW.replace(
                "        shell: pwsh",
                "        continue-on-error: true\n        shell: pwsh",
            ),
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                "    if: false\n    runs-on: windows-2022",
            ),
        )
        for workflow in variants:
            with self.subTest(workflow=workflow):
                with self.assertRaisesRegex(
                    AssertionError, "unconditional and unmasked"
                ):
                    policy.check_build_script(
                        build_text=VALID_BUILD,
                        workflow_text=workflow,
                    )

    def test_pre_policy_steps_cannot_tamper_with_checker_or_python(self) -> None:
        policy_step = "      - name: Validate dependency policy"
        variants = (
            "      - name: Rewrite the checker\n"
            "        shell: pwsh\n"
            "        run: Set-Content tools/check_dependency_policy.py pass\n",
            "      - name: Shadow Python\n"
            "        shell: pwsh\n"
            "        run: Add-Content $env:GITHUB_PATH C:\\untrusted\n",
        )
        for prior_step in variants:
            with self.subTest(prior_step=prior_step):
                workflow = VALID_WORKFLOW.replace(
                    policy_step,
                    prior_step + policy_step,
                    1,
                )
                with self.assertRaisesRegex(
                    AssertionError, "must begin with the exact reviewed"
                ):
                    policy.check_build_script(
                        build_text=VALID_BUILD,
                        workflow_text=workflow,
                    )

    def test_validate_job_cannot_be_made_inert(self) -> None:
        variants = (
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                "    needs: gate\n    runs-on: windows-2022",
            )
            + "\n  gate:\n    if: false\n    runs-on: windows-2022\n    steps: []\n",
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                "    runs-on: self-hosted",
            ),
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                '    "if": false\n    runs-on: windows-2022',
            ),
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                "    if : false\n    runs-on: windows-2022",
            ),
            VALID_WORKFLOW.replace(
                "    runs-on: windows-2022",
                "    <<: {if: false}\n    runs-on: windows-2022",
            ),
        )
        for workflow in variants:
            with self.subTest(workflow=workflow):
                with self.assertRaises(AssertionError):
                    policy.check_build_script(
                        build_text=VALID_BUILD,
                        workflow_text=workflow,
                    )

    def test_trigger_filters_cannot_silently_skip_policy(self) -> None:
        workflow = VALID_WORKFLOW.replace(
            "  pull_request:",
            "  pull_request:\n    paths-ignore: ['**']",
        )
        with self.assertRaisesRegex(AssertionError, "exact reviewed workflow envelope"):
            policy.check_build_script(
                build_text=VALID_BUILD,
                workflow_text=workflow,
            )


if __name__ == "__main__":
    unittest.main()
