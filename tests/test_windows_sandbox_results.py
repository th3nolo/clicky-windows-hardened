"""Tests for bounded host-side Windows Sandbox evidence verification."""

from __future__ import annotations

import contextlib
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import tools.verify_windows_sandbox_results as verifier


class WindowsSandboxResultTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, str, str, str]:
        commit = "1" * 40
        input_directory = root / "input"
        results = root / "results"
        input_directory.mkdir()
        results.mkdir()

        uv_executable = input_directory / "uv.exe"
        uv_executable.write_bytes(b"reviewed uv")
        uv_hash = hashlib.sha256(uv_executable.read_bytes()).hexdigest()
        (input_directory / "uv-sha256.txt").write_text(uv_hash + "\n", encoding="ascii")

        python_archive = input_directory / "python-runtime.zip"
        with zipfile.ZipFile(python_archive, "w") as archive:
            archive.writestr("python.exe", b"python")
            archive.writestr("python312.dll", b"dll")
            archive.writestr("python312.zip", b"stdlib")
            archive.writestr("python312._pth", b"python312.zip\n.\n")
        python_hash = hashlib.sha256(python_archive.read_bytes()).hexdigest()
        (input_directory / "python-runtime-sha256.txt").write_text(
            python_hash + "\n", encoding="ascii"
        )

        validator = b"@echo off\r\nexit /b 0\r\n"
        (input_directory / "windows-sandbox-validate.cmd").write_bytes(validator)
        source_archive = input_directory / "clicky-source.zip"
        with zipfile.ZipFile(source_archive, "w") as archive:
            archive.writestr("tools/windows-sandbox-validate.cmd", validator)
            archive.writestr("pyproject.toml", b"[project]\nname = 'fixture'\n")
        archive_hash = hashlib.sha256(source_archive.read_bytes()).hexdigest()
        (input_directory / "source-commit.txt").write_text(commit + "\n", encoding="ascii")
        (input_directory / "source-archive-sha256.txt").write_text(
            archive_hash + "\n", encoding="ascii"
        )

        wsb = rf"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Default</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{input_directory}</HostFolder>
      <SandboxFolder>C:\ClickyInput</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{results}</HostFolder>
      <SandboxFolder>C:\ValidationOutput</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /d /c C:\ClickyInput\windows-sandbox-validate.cmd</Command>
  </LogonCommand>
</Configuration>
"""
        (root / "clicky-validation.wsb").write_text(wsb, encoding="utf-8")

        cloud = {
            "synthetic_text_only": True,
            "resolved_hosts": ["speech.platform.bing.com"],
            "resolved_public_addresses": ["8.8.8.8"],
            "correlated_tcp_addresses": ["8.8.8.8"],
            "audio_bytes": 100,
        }
        executable_hash = "a" * 64
        scan = {
            "disable_remediation": True,
            "scan_exit_code": 0,
            "distribution_sha256_before": "b" * 64,
            "distribution_sha256_after": "b" * 64,
            "status": {"AntivirusSignatureVersion": "1.2.3.4"},
        }
        report = {
            "audio_crash_cleanup": {"leftover_removed": True},
            "privacy_controls": {
                "microphone_denied_before_consent": True,
                "recording_denied_before_consent": True,
                "microphone_started_after_consent": True,
                "recording_started_after_consent": True,
                "microphone_stopped_after_revocation": True,
                "microphone_recording_cancelled_after_revocation": True,
                "microphone_standby_after_regrant": True,
                "cloud_tts_denied_before_consent": True,
                "screen_denied_before_consent": True,
                "synthetic_screen_content_observed": True,
                "cloud_tts_after_consent": dict(cloud),
            },
            "dpapi": {"round_trip": True, "plaintext_absent": True},
            "unsigned_application": {
                "external_destinations_before_consent": [],
                "authenticode": {"Status": "NotSigned"},
                "sha256": executable_hash,
                "packaged_security_self_test": {
                    "runtime_boundary": {"frozen": True, "executable": r"C:\Clicky\Clicky.exe"},
                    "dpapi_token_persistence": {
                        "magic_present": True,
                        "plaintext_absent": True,
                        "same_process_read": True,
                        "second_process_read": True,
                    },
                    "secure_audio": {"normal_cleanup": True},
                    "bundled_skills": {"verified_files": ["example_self_mode.py"]},
                    "privacy_defaults": {"microphone_allowed": False},
                    "screen_capture": {"synthetic_content_observed": True},
                    "microphone_state": {
                        "cancelled_after_revocation": True,
                        "standby_after_regrant": True,
                    },
                    "cloud_tts": dict(cloud),
                },
            },
            "defender": {
                "pristine_distribution_sha256": "b" * 64,
                "pre_execution": dict(scan),
                "post_execution_tree_sha256": "b" * 64,
                "post_execution": dict(scan),
            },
        }
        (results / "runtime-validation.json").write_text(json.dumps(report), encoding="utf-8")
        (results / "sandbox-validation.log").write_text(
            "[PASS] Windows Sandbox validation completed.\n", encoding="utf-8"
        )
        (results / "PASS.txt").write_text("PASS\n", encoding="ascii")
        (results / "source-commit.txt").write_text(commit + "\n", encoding="ascii")
        (results / "source-archive-sha256.txt").write_text(
            archive_hash + "\n", encoding="ascii"
        )
        (results / "clicky-exe-sha256.txt").write_text(
            f"SHA256 hash of Clicky.exe:\n{executable_hash}\n", encoding="utf-8"
        )
        return root, commit, archive_hash, uv_hash + ":" + python_hash

    @contextlib.contextmanager
    def _reviewed_hashes(self, combined: str):
        uv_hash, python_hash = combined.split(":")
        with mock.patch.object(verifier, "_EXPECTED_UV_SHA256", uv_hash), mock.patch.object(
            verifier, "_EXPECTED_PYTHON_RUNTIME_SHA256", python_hash
        ):
            yield

    def test_accepts_complete_commit_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            with self._reviewed_hashes(hashes):
                summary = verifier.verify(run_root, commit, archive_hash)
            self.assertEqual(summary["commit"], commit)
            self.assertEqual(summary["clicky_exe_sha256"], "a" * 64)

    def test_rejects_any_unexpected_host_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            (run_root / "results" / "unexpected.exe").write_bytes(b"no")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "unexpected sandbox result"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_duplicate_sandbox_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            wsb = next(run_root.glob("*.wsb"))
            text = wsb.read_text(encoding="utf-8")
            duplicate = r"""    <MappedFolder>
      <HostFolder>C:\Untrusted</HostFolder>
      <SandboxFolder>C:\ClickyInput</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
"""
            wsb.write_text(text.replace("  </MappedFolders>", duplicate + "  </MappedFolders>"), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "duplicate SandboxFolder"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_complete_python_archive_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            with (run_root / "input" / "python-runtime.zip").open("ab") as handle:
                handle.write(b"tampered sibling runtime content")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "staged Python runtime hash differs"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_unexpected_cloud_tts_hostname(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            report_path = run_root / "results" / "runtime-validation.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["unsigned_application"]["packaged_security_self_test"]["cloud_tts"][
                "resolved_hosts"
            ] = ["attacker.example"]
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "unexpected hostname"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_oversized_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            (run_root / "results" / "sandbox-validation.log").write_bytes(
                b"x" * (verifier._RESULT_LIMITS["sandbox-validation.log"] + 1)
            )
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "exceeds size limit"
            ):
                verifier.verify(run_root, commit, archive_hash)


if __name__ == "__main__":
    unittest.main()
