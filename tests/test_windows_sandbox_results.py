"""Tests for bounded host-side Windows Sandbox evidence verification."""

from __future__ import annotations

import contextlib
import hashlib
import html
import json
import os
import re
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock
from xml.sax.saxutils import escape

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
        source_archive_hash = hashlib.sha256(source_archive.read_bytes()).hexdigest()
        (input_directory / "source-commit.txt").write_text(commit + "\n", encoding="ascii")
        (input_directory / "source-archive-sha256.txt").write_text(
            source_archive_hash + "\n", encoding="ascii"
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
    <Command>{escape(verifier._EXPECTED_LOGON_COMMAND)}</Command>
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
        members = {
            "Clicky.exe": b"MZ fixture executable",
            "component.dll": b"fixture component",
        }
        executable_hash = hashlib.sha256(members["Clicky.exe"]).hexdigest()
        tree = hashlib.sha256()
        tree.update(b"clicky-dist-tree-v1\0")
        for name, content in sorted(members.items()):
            encoded = name.encode("utf-8")
            tree.update(b"F")
            tree.update(len(encoded).to_bytes(8, "big"))
            tree.update(encoded)
            tree.update(len(content).to_bytes(8, "big"))
            tree.update(content)
        tree_hash = tree.hexdigest()
        distribution_archive = results / "clicky-unsigned-onedir.zip"
        with zipfile.ZipFile(distribution_archive, "w") as archive:
            for name, content in sorted(members.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644) << 16
                archive.writestr(info, content)
        distribution_archive_hash = hashlib.sha256(
            distribution_archive.read_bytes()
        ).hexdigest()
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
            "distribution_integrity": {
                "scheme": "clicky-dist-tree-v1",
                "pristine_tree_sha256": tree_hash,
                "post_execution_tree_sha256": tree_hash,
                "unchanged": True,
                "file_count": len(members),
                "total_bytes": sum(len(content) for content in members.values()),
                "archive_sha256": distribution_archive_hash,
                "archive_bytes": distribution_archive.stat().st_size,
                "clicky_exe_sha256": executable_hash,
            },
        }
        (results / "runtime-validation.json").write_text(json.dumps(report), encoding="utf-8")
        (results / "sandbox-validation.log").write_text(
            "[PASS] Windows Sandbox validation completed.\n", encoding="utf-8"
        )
        (results / "PASS.txt").write_text("PASS\n", encoding="ascii")
        (results / "source-commit.txt").write_text(commit + "\n", encoding="ascii")
        (results / "source-archive-sha256.txt").write_text(
            source_archive_hash + "\n", encoding="ascii"
        )
        (results / "Clicky-unsigned.exe").write_bytes(members["Clicky.exe"])
        (results / "clicky-exe-sha256.txt").write_text(
            f"SHA256 hash of Clicky.exe:\n{executable_hash}\n", encoding="utf-8"
        )
        return root, commit, source_archive_hash, uv_hash + ":" + python_hash

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
            self.assertEqual(
                summary["clicky_exe_sha256"],
                hashlib.sha256(b"MZ fixture executable").hexdigest(),
            )

    def test_rejects_hard_linked_result_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            marker = run_root / "results" / "PASS.txt"
            outside = run_root / "outside-marker.txt"
            outside.write_text("PASS\n", encoding="ascii")
            marker.unlink()
            os.link(outside, marker)
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "hard-linked evidence"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_explicit_authenticated_tool_hardlink_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "reviewed-tool.exe"
            linked = Path(tmp) / "reviewed-tool-hardlink.exe"
            original.write_bytes(b"separately authenticated tool")
            os.link(original, linked)
            verifier._require_regular_file(
                linked, 1024, reject_hardlinks=False
            )

    @unittest.skipUnless(os.name == "nt", "NTFS alternate streams require Windows")
    def test_rejects_result_alternate_data_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            marker = run_root / "results" / "PASS.txt"
            try:
                Path(f"{marker}:payload").write_bytes(b"hidden bytes")
            except OSError as exc:
                self.skipTest(f"alternate data streams are unavailable: {exc}")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "alternate data stream"
            ):
                verifier.verify(run_root, commit, archive_hash)

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

    def test_rejects_exported_executable_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            with (run_root / "results" / "Clicky-unsigned.exe").open("ab") as handle:
                handle.write(b"tampered")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "exported executable"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_unsafe_distribution_archive_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            results = run_root / "results"
            distribution_archive = results / "clicky-unsigned-onedir.zip"
            with zipfile.ZipFile(distribution_archive, "w") as archive:
                info = zipfile.ZipInfo("../Clicky.exe", date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644) << 16
                archive.writestr(info, b"MZ fixture executable")
            report_path = results / "runtime-validation.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["distribution_integrity"]["archive_sha256"] = hashlib.sha256(
                distribution_archive.read_bytes()
            ).hexdigest()
            report["distribution_integrity"]["archive_bytes"] = (
                distribution_archive.stat().st_size
            )
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "unsafe"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_archive_path_normalized_by_pure_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            results = run_root / "results"
            distribution_archive = results / "clicky-unsigned-onedir.zip"
            with zipfile.ZipFile(distribution_archive, "w") as archive:
                for name in ("Clicky.exe", "directory//component.dll"):
                    info = zipfile.ZipInfo(
                        name, date_time=(1980, 1, 1, 0, 0, 0)
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (0o100644) << 16
                    archive.writestr(info, b"MZ fixture executable")
            report_path = results / "runtime-validation.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["distribution_integrity"]["archive_sha256"] = hashlib.sha256(
                distribution_archive.read_bytes()
            ).hexdigest()
            report["distribution_integrity"]["archive_bytes"] = (
                distribution_archive.stat().st_size
            )
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "unsafe"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_excessive_entry_count_before_zipfile_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, _commit, _archive_hash, _hashes = self._fixture(Path(tmp))
            distribution_archive = (
                run_root / "results" / "clicky-unsigned-onedir.zip"
            )
            payload = bytearray(distribution_archive.read_bytes())
            end_record = len(payload) - 22
            struct.pack_into("<H", payload, end_record + 8, verifier._DIST_MAX_FILES + 1)
            struct.pack_into("<H", payload, end_record + 10, verifier._DIST_MAX_FILES + 1)
            distribution_archive.write_bytes(payload)
            with mock.patch.object(
                verifier.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZIP parser must not run"),
            ), self.assertRaisesRegex(AssertionError, "file-count limit"):
                verifier._validate_distribution_archive(distribution_archive)

    def test_rejects_eocd_entry_undercount_before_zipfile_parse(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, _commit, _archive_hash, _hashes = self._fixture(Path(tmp))
            distribution_archive = (
                run_root / "results" / "clicky-unsigned-onedir.zip"
            )
            payload = bytearray(distribution_archive.read_bytes())
            end_record = len(payload) - 22
            struct.pack_into("<H", payload, end_record + 8, 1)
            struct.pack_into("<H", payload, end_record + 10, 1)
            distribution_archive.write_bytes(payload)
            with mock.patch.object(
                verifier.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZIP parser must not run"),
            ), self.assertRaisesRegex(AssertionError, "entry count differs"):
                verifier._validate_distribution_archive(distribution_archive)

    def test_rejects_case_insensitive_distribution_archive_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            results = run_root / "results"
            distribution_archive = results / "clicky-unsigned-onedir.zip"
            with zipfile.ZipFile(distribution_archive, "w") as archive:
                for name in ("Clicky.exe", "clicky.EXE"):
                    info = zipfile.ZipInfo(
                        name, date_time=(1980, 1, 1, 0, 0, 0)
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (0o100644) << 16
                    archive.writestr(info, b"MZ fixture executable")
            report_path = results / "runtime-validation.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["distribution_integrity"]["archive_sha256"] = hashlib.sha256(
                distribution_archive.read_bytes()
            ).hexdigest()
            report["distribution_integrity"]["archive_bytes"] = (
                distribution_archive.stat().st_size
            )
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "case-insensitive duplicate"
            ):
                verifier.verify(run_root, commit, archive_hash)

    def test_rejects_distribution_archive_tree_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root, commit, archive_hash, hashes = self._fixture(Path(tmp))
            results = run_root / "results"
            distribution_archive = results / "clicky-unsigned-onedir.zip"
            members = {
                "Clicky.exe": b"MZ fixture executable",
                "component.dll": b"tampered after runtime",
            }
            with zipfile.ZipFile(distribution_archive, "w") as archive:
                for name, content in sorted(members.items()):
                    info = zipfile.ZipInfo(
                        name, date_time=(1980, 1, 1, 0, 0, 0)
                    )
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = (0o100644) << 16
                    archive.writestr(info, content)
            report_path = results / "runtime-validation.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["distribution_integrity"]["archive_sha256"] = hashlib.sha256(
                distribution_archive.read_bytes()
            ).hexdigest()
            report["distribution_integrity"]["archive_bytes"] = (
                distribution_archive.stat().st_size
            )
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self._reviewed_hashes(hashes), self.assertRaisesRegex(
                AssertionError, "tree differs"
            ):
                verifier.verify(run_root, commit, archive_hash)


class SandboxBootstrapSafetyTests(unittest.TestCase):
    def test_preparer_logon_command_matches_verifier_expectation(self) -> None:
        preparer = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "prepare-windows-sandbox.ps1"
        ).read_text(encoding="utf-8")
        command = re.search(r"<Command>(.*?)</Command>", preparer)
        self.assertIsNotNone(command)
        generated = html.unescape(command.group(1)).replace("`$", "$")
        self.assertEqual(generated, verifier._EXPECTED_LOGON_COMMAND)
        self.assertNotIn(r'\"', verifier._EXPECTED_LOGON_COMMAND)

    def test_host_launchable_validator_never_requests_shutdown(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "windows-sandbox-validate.cmd"
        ).read_text(encoding="utf-8")
        host_guard = 'if /I not "%USERNAME%"=="WDAGUtilityAccount" ('
        self.assertIn(host_guard, script)
        self.assertLess(script.index(host_guard), script.index('set "INPUT='))
        self.assertNotIn("shutdown.exe", script.casefold())
        self.assertIn("PASS.pending", script)
        self.assertNotIn("PASS.txt", script)

    def test_wsb_wrapper_publishes_pass_only_after_shutdown_is_scheduled(self) -> None:
        command = verifier._EXPECTED_LOGON_COMMAND
        shutdown_identity = (
            "$shutdown = [IO.Path]::Combine($env:SystemRoot, "
            "'System32', 'shutdown.exe')"
        )
        shutdown = "& $shutdown /s /t 5"
        publish = (
            "Move-Item -LiteralPath 'C:\\ValidationOutput\\PASS.pending' "
            "-Destination 'C:\\ValidationOutput\\PASS.txt'"
        )
        self.assertIn(shutdown_identity, command)
        self.assertIn(shutdown, command)
        self.assertIn("if ($LASTEXITCODE -ne 0) { exit 90 }", command)
        self.assertIn(publish, command)
        self.assertLess(command.index(shutdown), command.index(publish))

    def test_preparer_pins_reviewed_git_for_windows_version(self) -> None:
        preparer = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "prepare-windows-sandbox.ps1"
        ).read_text(encoding="utf-8")
        hash_check = preparer.index(
            "$GitExe = Assert-ReviewedFile $GitExe $ExpectedGitSha256"
        )
        signature_check = preparer.index(
            "$gitSignature = Get-AuthenticodeSignature -LiteralPath $GitExe"
        )
        version_check = preparer.index(
            "$gitVersionInfo = (Get-Item -LiteralPath $GitExe -Force).VersionInfo"
        )
        self.assertIn(
            '$ExpectedGitProductVersion = "2.55.0.windows.2"', preparer
        )
        self.assertIn(
            "$gitVersionInfo.ProductVersion -cne $ExpectedGitProductVersion",
            preparer,
        )
        self.assertIn(
            "$gitVersionInfo.FileVersion -cne $ExpectedGitProductVersion",
            preparer,
        )
        self.assertLess(hash_check, signature_check)
        self.assertLess(signature_check, version_check)

    def test_preparer_restores_git_environment_in_finally(self) -> None:
        preparer = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "prepare-windows-sandbox.ps1"
        ).read_text(encoding="utf-8")
        set_index = preparer.index('$env:GIT_CONFIG_NOSYSTEM = "1"')
        finally_index = preparer.rindex("} finally {")
        self.assertLess(set_index, finally_index)
        cleanup = preparer[finally_index:]
        for variable in (
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_NO_REPLACE_OBJECTS",
        ):
            self.assertIn(f"Remove-Item Env:{variable}", cleanup)


    def test_sandbox_uses_only_the_reviewed_ca_bundle_for_live_pypi(self) -> None:
        script = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "windows-sandbox-validate.cmd"
        ).read_text(encoding="utf-8")
        expected_hash = (
            "bbc7e9c01d7551bb8a159b5dedd989b8"
            "ee3ce105aff522b68eb1b01bf854cab0"
        )
        bundle = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "trust"
            / "certifi-2026.6.17.pem"
        )
        self.assertEqual(hashlib.sha256(bundle.read_bytes()).hexdigest(), expected_hash)
        policy_call = (
            'tools\\check_dependency_policy.py --verify-pypi '
            '--ca-bundle "%CA_BUNDLE%"'
        )
        hash_check = 'certutil.exe -hashfile "%CA_BUNDLE%" SHA256'
        self.assertIn(
            'set "CA_BUNDLE=%WORK%\\tools\\trust\\certifi-2026.6.17.pem"',
            script,
        )
        self.assertIn(f'set "EXPECTED_CA_BUNDLE_SHA256={expected_hash}"', script)
        self.assertIn(hash_check, script)
        self.assertIn(policy_call, script)
        self.assertLess(script.index(hash_check), script.index(policy_call))
        for variable in (
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "PYTHONHTTPSVERIFY",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
        ):
            clear = f'set "{variable}="'
            self.assertIn(clear, script)
            self.assertLess(script.index(clear), script.index(policy_call))
        for bypass in (
            "PYTHONHTTPSVERIFY=0",
            "_create_unverified_context",
            "--trusted-host",
            "verify=False",
        ):
            self.assertNotIn(bypass, script)

if __name__ == "__main__":
    unittest.main()
