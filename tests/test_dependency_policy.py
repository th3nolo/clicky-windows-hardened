"""Standard-library tests for dependency provenance and policy parsing."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
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
            checked = policy.check_pypi_releases((_release(),), now=NOW)
        self.assertEqual(checked, 1)
        fetch.assert_called_once_with(_release())


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

        def opener(request, *, timeout):
            calls.append((request, timeout))
            return _FakeResponse(
                payload,
                url="https://pypi.org/pypi/demo/1.0.0/json",
            )

        self.assertEqual(policy._fetch_pypi_release(_release(), opener=opener), _metadata())
        self.assertEqual(len(calls), 1)
        request, timeout = calls[0]
        self.assertEqual(request.full_url, "https://pypi.org/pypi/demo/1.0.0/json")
        self.assertEqual(timeout, policy.PYPI_METADATA_TIMEOUT_SECONDS)
        self.assertEqual(request.get_header("Accept"), "application/json")

    def test_fetch_rejects_redirect_outside_pypi(self) -> None:
        def opener(request, *, timeout):
            return _FakeResponse(
                json.dumps(_metadata()).encode("utf-8"),
                url="https://attacker.example/metadata.json",
            )

        with self.assertRaisesRegex(AssertionError, "outside pypi.org"):
            policy._fetch_pypi_release(_release(), opener=opener)

    def test_fetch_rejects_invalid_or_oversized_json(self) -> None:
        cases = (
            (b"not-json", "invalid JSON"),
            (b"x" * (policy.MAX_PYPI_METADATA_BYTES + 1), "too large"),
        )
        for payload, expected_error in cases:
            with self.subTest(expected_error=expected_error):
                def opener(request, *, timeout):
                    return _FakeResponse(
                        payload,
                        url="https://pypi.org/pypi/demo/1.0.0/json",
                    )

                with self.assertRaisesRegex(AssertionError, expected_error):
                    policy._fetch_pypi_release(_release(), opener=opener)


class BundledSkillPolicyTests(unittest.TestCase):
    def _write_fixture(self, root: Path) -> tuple[Path, bytes]:
        directory = root / "skills"
        directory.mkdir()
        source = b"SKILL = {'name': 'safe'}\n"
        skill = directory / "safe.py"
        skill.write_bytes(source)
        (directory / "manifest.json").write_text(
            json.dumps({
                "version": 1,
                "files": {
                    "safe.py": hashlib.sha256(source).hexdigest()
                },
            }),
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


VALID_BUILD = r'''
@echo off
set "EXPECTED_UV_VERSION=0.11.19"
set "EXPECTED_PYTHON_VERSION=3.12.10"
if /I "%~1"=="installer" (
  echo [ERROR] Installer builds are disabled.
)
uv lock --check --offline --no-build --no-sources --no-python-downloads
uv sync --frozen --group build --no-build ^
  --no-managed-python --no-python-downloads --keyring-provider disabled ^
  --link-mode copy --no-cache
uv export --frozen --no-dev --no-emit-project --format cyclonedx1.5
> "dist\Clicky\UNSIGNED-LOCAL-TEST-ONLY.txt" (
echo LOCAL TEST ONLY - UNSIGNED - DO NOT DISTRIBUTE
'''
VALID_WORKFLOW = r'''
steps:
  - name: Validate
    run: python tools/check_dependency_policy.py --verify-pypi
'''


class BatchAndWorkflowPolicyTests(unittest.TestCase):
    def test_effective_hardened_commands_are_accepted(self) -> None:
        policy.check_build_script(
            build_text=VALID_BUILD,
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
        workflow = r'''
steps:
  # run: python tools/check_dependency_policy.py --verify-pypi
  - run: python tools/check_dependency_policy.py
'''
        with self.assertRaisesRegex(AssertionError, "authoritative PyPI"):
            policy.check_build_script(
                build_text=VALID_BUILD,
                workflow_text=workflow,
            )

    def test_inline_comment_cannot_supply_verify_pypi_flag(self) -> None:
        workflow = r'''
steps:
  - run: python tools/check_dependency_policy.py # --verify-pypi
'''
        with self.assertRaisesRegex(AssertionError, "authoritative PyPI"):
            policy.check_build_script(
                build_text=VALID_BUILD,
                workflow_text=workflow,
            )


if __name__ == "__main__":
    unittest.main()
