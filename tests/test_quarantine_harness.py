from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "quarantine_harness", ROOT / "tools" / "quarantine_harness.py"
)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)

TARGET = "1" * 40
WORKFLOW = "2" * 40


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _write_distribution(path: Path) -> tuple[dict[str, bytes], dict[str, object]]:
    files = {
        "Clicky.exe": b"MZ" + bytes(range(256)) * 4,
        "UNSIGNED-LOCAL-TEST-ONLY.txt": b"unsigned test only\n",
    }
    with zipfile.ZipFile(
        path,
        "x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        allowZip64=False,
    ) as archive:
        for name, payload in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    tree = hashlib.sha256()
    tree.update(b"clicky-dist-tree-v1\0")
    for name, payload in sorted(files.items()):
        encoded = name.encode("utf-8")
        tree.update(b"F")
        tree.update(len(encoded).to_bytes(8, "big"))
        tree.update(encoded)
        tree.update(len(payload).to_bytes(8, "big"))
        tree.update(payload)
    identity = {
        "scheme": "clicky-dist-tree-v1",
        "pristine_tree_sha256": tree.hexdigest(),
        "post_execution_tree_sha256": tree.hexdigest(),
        "unchanged": True,
        "file_count": len(files),
        "total_bytes": sum(len(payload) for payload in files.values()),
        "archive_sha256": _sha256(path),
        "archive_bytes": path.stat().st_size,
        "clicky_exe_sha256": hashlib.sha256(files["Clicky.exe"]).hexdigest(),
    }
    return files, identity


def _runtime_report(distribution_identity: dict[str, object]) -> dict[str, object]:
    return {
        "python": "3.12.10",
        "executable": "python.exe",
        "runtime_boundary": {
            "kind": "github-hosted-windows",
            "commit": TARGET,
            "workflow_commit": WORKFLOW,
        },
        "audio_crash_cleanup": {
            "leftover_removed": True,
            "crash_exit_code": 73,
            "audio_directory_sddl": "D:P(A;;FA;;;SY)",
            "audio_file_sddl": "D:(A;;FA;;;SY)",
        },
        "dpapi": {"round_trip": True, "plaintext_absent": True, "protected_bytes": 64},
        "privacy_controls": {
            "microphone_device": "synthetic listener; host audio input disabled",
            "microphone_denied_before_consent": True,
            "recording_denied_before_consent": True,
            "microphone_started_after_consent": True,
            "recording_started_after_consent": True,
            "microphone_stopped_after_revocation": True,
            "microphone_recording_cancelled_after_revocation": True,
            "microphone_standby_after_regrant": True,
            "cloud_tts_denied_before_consent": True,
            "cloud_tts_after_consent": {
                "synthetic_text_only": True,
                "resolved_hosts": ["speech.platform.bing.com"],
                "resolved_public_addresses": ["8.8.8.8"],
                "correlated_tcp_addresses": ["8.8.8.8"],
                "audio_bytes": 128,
            },
            "screen_denied_before_consent": True,
            "screen_capture_after_consent": [{"index": 0, "width": 800, "height": 600}],
            "synthetic_screen_content_observed": True,
        },
        "unsigned_application": {
            "external_destinations_before_consent": [],
            "window_titles": ["Clicky Privacy Permissions"],
            "sha256": distribution_identity["clicky_exe_sha256"],
            "authenticode": {"Status": "NotSigned"},
            "packaged_security_self_test": {
                "runtime_boundary": {
                    "kind": "github-hosted-windows",
                    "commit": TARGET,
                    "workflow_commit": WORKFLOW,
                    "frozen": True,
                    "executable": r"C:\Clicky\Clicky.exe",
                },
                "dpapi_token_persistence": {
                    "magic_present": True,
                    "plaintext_absent": True,
                    "same_process_read": True,
                    "second_process_read": True,
                    "encrypted_bytes": 64,
                },
                "secure_audio": {"private_write": True, "normal_cleanup": True},
                "bundled_skills": {
                    "verified_files": ["example.py"],
                    "loaded_names": ["example"],
                },
                "privacy_defaults": {
                    "notice_accepted": False,
                    "microphone_allowed": False,
                    "cloud_tts_allowed": False,
                    "screen_capture_allowed": False,
                },
                "microphone_state": {
                    "cancelled_after_revocation": True,
                    "standby_after_regrant": True,
                },
                "screen_capture": {
                    "synthetic_content_observed": True,
                    "screens": [{"index": 0, "width": 800, "height": 600}],
                },
                "cloud_tts": {
                    "synthetic_text_only": True,
                    "resolved_hosts": ["speech.platform.bing.com"],
                    "resolved_public_addresses": ["8.8.8.8"],
                    "correlated_tcp_addresses": ["8.8.8.8"],
                    "audio_bytes": 128,
                },
            },
        },
        "distribution_integrity": distribution_identity,
    }


class ContextTests(unittest.TestCase):
    def _environment(self) -> dict[str, str]:
        recipient_blob = base64.b64encode(b"x" * 48).decode("ascii")
        return {
            "GITHUB_REPOSITORY": HARNESS.REPOSITORY,
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": HARNESS.WORKFLOW_REF,
            "GITHUB_SHA": WORKFLOW,
            "GITHUB_WORKFLOW_SHA": WORKFLOW,
            "INPUT_TARGET_SHA": TARGET,
            "INPUT_AGE_SSH_PUBLIC_RECIPIENT": f"ssh-ed25519 {recipient_blob}",
        }

    def test_context_distinguishes_workflow_and_target(self) -> None:
        with mock.patch.dict(os.environ, self._environment(), clear=True):
            result = HARNESS.validate_context_from_environment(require_recipient=True)
        self.assertEqual(result["target_sha"], TARGET)
        self.assertEqual(result["workflow_sha"], WORKFLOW)

    def test_context_rejects_target_equal_to_workflow(self) -> None:
        environment = self._environment()
        environment["INPUT_TARGET_SHA"] = WORKFLOW
        with mock.patch.dict(os.environ, environment, clear=True):
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.validate_context_from_environment(require_recipient=True)

    def test_recipient_must_be_one_public_key_line(self) -> None:
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS.validate_ssh_recipient("ssh-ed25519 AAAA\nssh-ed25519 BBBB")

    def test_hosted_git_identity_is_not_version_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            git_executable = Path(temporary) / "git.exe"
            git_executable.write_bytes(b"hosted runner git")
            with mock.patch.dict(
                os.environ,
                {"CLICKY_HOSTED_GIT_EXE": str(git_executable)},
                clear=True,
            ):
                self.assertEqual(HARNESS._hosted_git_executable(), git_executable)


class EvidenceTests(unittest.TestCase):
    def test_small_evidence_binds_three_direct_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            distribution = root / "clicky-full-dist.zip"
            files, identity = _write_distribution(distribution)
            executable = root / "clicky-executable.exe"
            executable.write_bytes(files["Clicky.exe"])
            source = root / "clicky-source.zip"
            with zipfile.ZipFile(source, "x") as archive:
                archive.writestr("README.md", b"reviewed source\n")
            source_sha = _sha256(source)
            runtime = root / "runtime-validation.json"
            runtime.write_text(
                json.dumps(_runtime_report(identity), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            evidence = root / "clicky-runtime-evidence.zip"

            HARNESS.create_evidence_archive(
                source,
                runtime,
                distribution,
                executable,
                evidence,
                TARGET,
                source_sha,
                WORKFLOW,
            )
            with zipfile.ZipFile(evidence, "r") as archive:
                self.assertEqual(
                    tuple(member.filename for member in archive.infolist()),
                    HARNESS.EVIDENCE_MEMBERS,
                )
                self.assertNotIn("clicky-full-dist.zip", archive.namelist())
                self.assertEqual(archive.read("PASS.txt"), b"PASS\n")

            result = HARNESS.verify_evidence_archive(
                evidence,
                source,
                distribution,
                executable,
                root / "verified",
                TARGET,
                source_sha,
                WORKFLOW,
            )
            self.assertEqual(result["hashes"]["source"], source_sha)
            self.assertEqual(result["hashes"]["distribution"], _sha256(distribution))
            self.assertEqual(result["hashes"]["executable"], _sha256(executable))
            self.assertEqual(
                (root / "verified" / "reconstructed" / "Clicky.exe").read_bytes(),
                executable.read_bytes(),
            )

    def test_packaged_runtime_mutations_fail_closed(self) -> None:
        identity = {
            "scheme": "clicky-dist-tree-v1",
            "pristine_tree_sha256": "a" * 64,
            "post_execution_tree_sha256": "a" * 64,
            "unchanged": True,
            "file_count": 1,
            "total_bytes": 2,
            "archive_sha256": "b" * 64,
            "archive_bytes": 22,
            "clicky_exe_sha256": "c" * 64,
        }
        mutations = {
            "workflow": lambda p: p["unsigned_application"]["packaged_security_self_test"]["runtime_boundary"].update(workflow_commit="3" * 40),
            "frozen": lambda p: p["unsigned_application"]["packaged_security_self_test"]["runtime_boundary"].update(frozen=False),
            "executable": lambda p: p["unsigned_application"]["packaged_security_self_test"]["runtime_boundary"].update(executable="python.exe"),
            "dpapi": lambda p: p["unsigned_application"]["packaged_security_self_test"]["dpapi_token_persistence"].update(second_process_read=False),
            "audio": lambda p: p["unsigned_application"]["packaged_security_self_test"]["secure_audio"].update(normal_cleanup=False),
            "skills": lambda p: p["unsigned_application"]["packaged_security_self_test"]["bundled_skills"].update(verified_files=[]),
            "defaults": lambda p: p["unsigned_application"]["packaged_security_self_test"]["privacy_defaults"].update(microphone_allowed=True),
            "screen": lambda p: p["unsigned_application"]["packaged_security_self_test"]["screen_capture"].update(synthetic_content_observed=False),
            "microphone": lambda p: p["unsigned_application"]["packaged_security_self_test"]["microphone_state"].update(standby_after_regrant=False),
            "cloud": lambda p: p["unsigned_application"]["packaged_security_self_test"]["cloud_tts"].update(correlated_tcp_addresses=[]),
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    report = _runtime_report(identity)
                    mutate(report)
                    path.write_text(json.dumps(report), encoding="utf-8")
                    with self.assertRaises(HARNESS.HarnessError):
                        HARNESS.validate_runtime_report(path, TARGET, WORKFLOW)

    def test_runtime_boundary_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            report = _runtime_report(
                {
                    "scheme": "clicky-dist-tree-v1",
                    "pristine_tree_sha256": "a" * 64,
                    "post_execution_tree_sha256": "a" * 64,
                    "unchanged": True,
                    "file_count": 1,
                    "total_bytes": 2,
                    "archive_sha256": "b" * 64,
                    "archive_bytes": 22,
                    "clicky_exe_sha256": "c" * 64,
                }
            )
            report["runtime_boundary"]["workflow_commit"] = "3" * 40
            path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.validate_runtime_report(path, TARGET, WORKFLOW)

    def test_scan_vm_hashes_opaque_inputs_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.zip"
            distribution = root / "dist.zip"
            executable = root / "Clicky.exe"
            source.write_bytes(b"opaque source")
            distribution.write_bytes(b"opaque dist")
            executable.write_bytes(b"opaque executable")
            hashes = HARNESS.verify_scan_inputs(
                source,
                distribution,
                executable,
                _sha256(source),
                _sha256(distribution),
                _sha256(executable),
            )
            self.assertEqual(hashes["distribution"], _sha256(distribution))
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.verify_scan_inputs(
                    source,
                    distribution,
                    executable,
                    "0" * 64,
                    _sha256(distribution),
                    _sha256(executable),
                )


    def test_virustotal_scan_binds_analysis_and_file_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.bin"
            candidate.write_bytes(b"opaque candidate")
            digest = _sha256(candidate)
            engine = {
                "category": "undetected", "engine_name": "Other",
                "engine_version": "1", "result": None, "method": "blacklist",
                "engine_update": "20260726",
            }
            analysis = {
                "data": {
                    "id": "analysis-1",
                    "attributes": {
                        "status": "completed", "date": 100,
                        "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
                        "results": {"Other": engine},
                    },
                }
            }
            file_report = {
                "data": {
                    "id": digest,
                    "attributes": {
                        "last_analysis_date": 100,
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
                        "last_analysis_results": {"Other": engine},
                    },
                }
            }
            with mock.patch.object(
                HARNESS, "_vt_upload_file", return_value={"data": {"id": "analysis-1"}}
            ), mock.patch.object(
                HARNESS, "_vt_request_json", side_effect=[analysis, file_report]
            ):
                archive_result = HARNESS._vt_scan_one(
                    candidate, "x" * 32
                )
            self.assertEqual(archive_result["analysis_id"], "analysis-1")
            self.assertEqual(archive_result["file_id"], digest)
            self.assertIn("Other", archive_result["file_report"]["results"])
    def test_virustotal_file_id_must_match_local_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.bin"
            candidate.write_bytes(b"opaque candidate")
            engine = {"category": "undetected"}
            analysis = {
                "data": {"id": "analysis-1", "attributes": {
                    "status": "completed", "date": 100,
                    "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
                    "results": {"Other": engine},
                }}
            }
            bad_file = {"data": {"id": "0" * 64, "attributes": {}}}
            with mock.patch.object(
                HARNESS, "_vt_upload_file", return_value={"data": {"id": "analysis-1"}}
            ), mock.patch.object(
                HARNESS, "_vt_request_json", side_effect=[analysis, bad_file]
            ):
                with self.assertRaises(HARNESS.HarnessError):
                    HARNESS._vt_scan_one(candidate, "x" * 32)

    def test_virustotal_finishes_all_files_before_failing_clean_gate(self) -> None:
        clean_results = {
            "Other": {"category": "undetected"},
            "Malwarebytes": {"category": "undetected"},
            "Microsoft": {"category": "undetected"},
        }
        clean = {
            "analysis_report": {
                "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
                "results": clean_results,
            },
            "file_report": {
                "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
                "results": clean_results,
            },
        }
        detected = {
            "analysis_report": {
                "stats": {"malicious": 1, "suspicious": 0, "undetected": 60},
                "results": {"Bkav": {"category": "malicious"}},
            },
            "file_report": {
                "stats": {"malicious": 1, "suspicious": 0, "undetected": 60},
                "results": {"Bkav": {"category": "malicious"}},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "report.json"
            with mock.patch.dict(os.environ, {"VT_API_KEY": "x" * 32}, clear=True), \
                    mock.patch.object(
                        HARNESS, "_vt_scan_one", side_effect=[clean, detected, clean]
                    ) as scanned, mock.patch("builtins.print"):
                with self.assertRaises(HARNESS.HarnessError):
                    HARNESS.virus_total_scan(
                        root / "source.zip",
                        root / "distribution.zip",
                        root / "Clicky.exe",
                        output,
                    )
            self.assertEqual(scanned.call_count, 3)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], 2)
            self.assertEqual(report["verdict"], "failed")
            self.assertEqual(
                set(report["files"]),
                {"source_archive", "distribution_archive", "clicky_executable"},
            )
            self.assertTrue(
                any("distribution_archive" in failure for failure in report["failures"])
            )

    def test_virustotal_transport_blocks_proxy_redirect_and_bounds_429(self) -> None:
        proxy_handlers = [
            handler for handler in HARNESS._VT_OPENER.handlers
            if isinstance(handler, urllib.request.ProxyHandler)
        ]
        self.assertEqual(len(proxy_handlers), 1)
        self.assertEqual(proxy_handlers[0].proxies, {})
        redirect = urllib.error.HTTPError(
            HARNESS.VT_LARGE_UPLOAD_URL, 302, "redirect", {"Location": "https://evil.invalid"}, io.BytesIO(b"")
        )
        with mock.patch.object(HARNESS._VT_OPENER, "open", side_effect=redirect) as opened, \
                mock.patch.object(HARNESS, "_pace_vt_request"):
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS._vt_request_json(HARNESS.VT_LARGE_UPLOAD_URL, "x" * 32)
            self.assertEqual(opened.call_count, 1)
        rate_limit = urllib.error.HTTPError(
            HARNESS.VT_LARGE_UPLOAD_URL, 429, "rate", {"Retry-After": "1"}, io.BytesIO(b"")
        )
        response = mock.MagicMock()
        response.status = 200
        response.read.return_value = b'{"data":"https://upload.virustotal.com/path"}'
        response.__enter__.return_value = response
        with mock.patch.object(
            HARNESS._VT_OPENER, "open", side_effect=[rate_limit, response]
        ), mock.patch.object(HARNESS.time, "sleep") as slept, \
                mock.patch.object(HARNESS, "_pace_vt_request"):
            result = HARNESS._vt_request_json(HARNESS.VT_LARGE_UPLOAD_URL, "x" * 32)
        self.assertIn("data", result)
        slept.assert_called_once_with(1)
        with mock.patch.object(HARNESS._VT_OPENER, "open") as opened:
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS._vt_request_json("https://virustotal.com.evil.invalid/api/v3/files/x", "x" * 32)
            opened.assert_not_called()

    def test_virustotal_uses_one_start_to_start_pacer_for_api_and_uploads(self) -> None:
        HARNESS._VT_LAST_REQUEST_STARTED = None
        with mock.patch.object(
            HARNESS.time, "monotonic", side_effect=[100.0, 105.0, 116.0, 132.0]
        ), mock.patch.object(HARNESS.time, "sleep") as slept:
            HARNESS._pace_vt_request()
            HARNESS._pace_vt_request()
            HARNESS._pace_vt_request()
        slept.assert_called_once_with(11.0)
        self.assertEqual(HARNESS._VT_LAST_REQUEST_STARTED, 132.0)

        api_response = mock.MagicMock()
        api_response.status = 200
        api_response.read.return_value = b'{"data":{"id":"analysis-1"}}'
        api_response.__enter__.return_value = api_response
        upload_response = mock.MagicMock()
        upload_response.status = 200
        upload_response.read.return_value = b'{"data":{"id":"analysis-2"}}'
        connection = mock.MagicMock()
        connection.getresponse.return_value = upload_response
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "candidate.zip"
            candidate.write_bytes(b"opaque")
            with mock.patch.object(HARNESS, "_pace_vt_request") as paced, \
                    mock.patch.object(HARNESS._VT_OPENER, "open", return_value=api_response), \
                    mock.patch.object(HARNESS.http.client, "HTTPSConnection", return_value=connection):
                HARNESS._vt_request_json(HARNESS.VT_LARGE_UPLOAD_URL, "x" * 32)
                HARNESS._vt_upload_file(HARNESS.VT_UPLOAD_URL, candidate, "x" * 32)
            self.assertEqual(paced.call_count, 2)

    def test_virustotal_executable_still_requires_vendor_votes(self) -> None:
        report = {
            "stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
            "results": {"Other": {"category": "undetected"}},
        }
        failures = HARNESS._vt_gate_failures(
            {
                "clicky_executable": {
                    "analysis_report": report,
                    "file_report": report,
                }
            }
        )
        self.assertEqual(len(failures), 2)
        self.assertTrue(all("Malwarebytes" in failure for failure in failures))

    def test_virustotal_requires_at_least_fifty_clean_participants(self) -> None:
        with self.assertRaises(HARNESS.HarnessError):
            HARNESS._require_clean_vt_report(
                {"malicious": 0, "suspicious": 0, "undetected": 49},
                {"Other": {"category": "undetected"}},
                "candidate", require_vendor_votes=False,
            )


    def test_github_hash_outputs_allow_sha256_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output.txt"
            output.touch()
            HARNESS._append_github_outputs(output, {"source_sha256": "a" * 64})
            self.assertEqual(output.read_text(encoding="utf-8"), f"source_sha256={'a' * 64}\n")


class CiphertextAndWorkflowTests(unittest.TestCase):
    def test_ciphertext_directory_rejects_plaintext_or_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in HARNESS.CIPHERTEXT_MEMBERS:
                (root / name).write_bytes(b"age-encryption.org/v1\nciphertext")
            result = HARNESS.verify_ciphertext_directory(root)
            self.assertEqual(set(result["hashes"]), set(HARNESS.CIPHERTEXT_MEMBERS))
            (root / "plaintext.zip").write_bytes(b"PK")
            with self.assertRaises(HARNESS.HarnessError):
                HARNESS.verify_ciphertext_directory(root)

    def test_workflow_uses_four_fresh_jobs_and_exact_action_pins(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "ephemeral-windows-security.yml").read_text(
            encoding="utf-8"
        )
        for job in (
            "build-runtime:",
            "verify-evidence:",
            "scan-exact-files:",
            "cleanup-artifact:",
        ):
            self.assertEqual(workflow.count(f"  {job}"), 1)
        expected = {
            "actions/checkout": "08c6903cd8c0fde910a37f88322edcfb5dd907a8",
            "actions/setup-python": "e797f83bcb11b83ae66e0230d6156d7c80228e7c",
            "astral-sh/setup-uv": "08807647e7069bb48b6ef5acd8ec9567f424441b",
            "actions/upload-artifact": "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/download-artifact": "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
        }
        uses = re.findall(r"^\s*uses:\s*([^@\s]+)@([0-9a-f]{40})", workflow, re.MULTILINE)
        self.assertTrue(uses)
        for action, revision in uses:
            self.assertEqual(revision, expected[action])

        build = workflow.split("  build-runtime:", 1)[1].split("  verify-evidence:", 1)[0]
        verifier = workflow.split("  verify-evidence:", 1)[1].split("  scan-exact-files:", 1)[0]
        scanner = workflow.split("  scan-exact-files:", 1)[1].split("  cleanup-artifact:", 1)[0]
        self.assertNotIn("secrets.", build)
        self.assertNotIn("VT_API_KEY", verifier)
        self.assertIn("AGE_SSH_PRIVATE_KEY", verifier)
        self.assertIn("VT_API_KEY", scanner)
        self.assertNotIn(
            '-o "$plain\\clicky-runtime-evidence.zip"',
            scanner,
            "scanner VM must never decrypt the parser-facing evidence ZIP",
        )
        self.assertIn("--verify-pypi", build)
        self.assertIn("--link-mode copy", build)
        self.assertIn("TRUSTED_HARNESS_SHA256", build)
        self.assertIn("CLICKY_HOSTED_GIT_EXE", build)
        self.assertIn("Select-Object -First 1", build)
        self.assertIn("$command.Path", build)
        self.assertNotIn("2.55.0.windows.2", build)
        build_step = build.index("- name: Build the unsigned onedir distribution")
        marker_step = build.index("- name: Materialize fixed unsigned warning")
        runtime_step = build.index("- name: Run target runtime validation")
        self.assertLess(build_step, marker_step)
        self.assertLess(marker_step, runtime_step)
        self.assertEqual(
            build.count("UNSIGNED-LOCAL-TEST-ONLY.txt"),
            1,
        )
        self.assertIn(
            "[System.Text.UTF8Encoding]::new($false)",
            build,
        )
        self.assertIn(
            "unsigned warning marker did not round-trip exactly",
            build,
        )
        self.assertNotIn("expected_source_archive_sha256:", workflow)
        self.assertIn(
            "source_sha256: ${{ steps.bind_source.outputs.source_sha256 }}",
            build,
        )
        self.assertIn(
            "EXPECTED_SOURCE_SHA256: ${{ needs.build-runtime.outputs.source_sha256 }}",
            verifier,
        )

    def test_action_allowlist_matches_workflow(self) -> None:
        policy = (ROOT / "tools" / "check_dependency_policy.py").read_text(encoding="utf-8")
        self.assertIn("043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", policy)
        self.assertIn("3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", policy)
        self.assertEqual(HARNESS.VT_MAX_UPLOAD_BYTES, 650_000_000)
        self.assertEqual(HARNESS.ARTIFACT_MAX_BYTES, 480_000_000)
        documentation = (ROOT / ".github" / "QUARANTINE.md").read_text(encoding="utf-8")
        self.assertIn("remove both `AGE_SSH_PRIVATE_KEY`", documentation)
        self.assertIn("zero retained artifacts", documentation)
        self.assertIn("manual consumer Malwarebytes", documentation)
        self.assertIn("at least 50 clean-participating", documentation)
        self.assertIn("complete per-engine analysis", documentation)
        self.assertIn("returned\nVirusTotal file ID", documentation)


if __name__ == "__main__":
    unittest.main()
