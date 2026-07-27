"""Tests for host-independent Windows runtime validation helpers."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import windows_runtime_validation as runtime


class ReleaseMarkerTests(unittest.TestCase):
    def test_local_release_refuses_store_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            distribution = Path(temporary)
            (distribution / "UNSIGNED-LOCAL-TEST-ONLY.txt").write_text(
                "local\n",
                encoding="utf-8",
            )
            runtime._validate_release_markers(
                distribution,
                release_kind="local",
                source_commit=None,
            )
            (distribution / "SOURCE-COMMIT.txt").write_text(
                "a" * 40 + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(AssertionError, "Store release markers"):
                runtime._validate_release_markers(
                    distribution,
                    release_kind="local",
                    source_commit=None,
                )

    def test_store_release_binds_exact_commit_and_marker(self) -> None:
        commit = "b" * 40
        with tempfile.TemporaryDirectory() as temporary:
            distribution = Path(temporary)
            marker = distribution / "UNSIGNED-STORE-SUBMISSION-INPUT.txt"
            marker.write_bytes(runtime._STORE_MARKER_TEMPLATE.read_bytes())
            (distribution / "SOURCE-COMMIT.txt").write_text(
                commit + "\n",
                encoding="ascii",
            )
            runtime._validate_release_markers(
                distribution,
                release_kind="store",
                source_commit=commit,
            )
            marker.write_text("tampered\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "reviewed text"):
                runtime._validate_release_markers(
                    distribution,
                    release_kind="store",
                    source_commit=commit,
                )


class WindowsPowerShellBoundaryTests(unittest.TestCase):
    def test_acl_probe_ignores_parent_shell_module_path(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout="D:P(A;;FA;;;SY)\n",
            stderr="",
        )
        with mock.patch.dict(
            os.environ,
            {"pSmOdUlEpAtH": r"C:\untrusted-pwsh-modules", "SAFE_MARKER": "kept"},
            clear=True,
        ), mock.patch.object(runtime.subprocess, "run", return_value=completed) as invoked:
            self.assertEqual(
                runtime._security_descriptor_sddl(Path(r"C:\Clicky\audio-temp")),
                "D:P(A;;FA;;;SY)",
            )

        arguments = invoked.call_args.args[0]
        options = invoked.call_args.kwargs
        self.assertTrue(str(arguments[0]).lower().endswith(r"windowspowershell\v1.0\powershell.exe"))
        self.assertIn("Import-Module Microsoft.PowerShell.Security -ErrorAction Stop", arguments[-1])
        self.assertEqual(options["env"]["SAFE_MARKER"], "kept")
        self.assertFalse(any(name.casefold() == "psmodulepath" for name in options["env"]))

    def test_authenticode_probe_ignores_parent_shell_module_path(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["powershell.exe"],
            returncode=0,
            stdout=(
                '{"Status":"NotSigned","StatusMessage":"The file is not digitally signed.",'
                '"SignerSubject":null}\n'
            ),
            stderr="",
        )
        with mock.patch.dict(
            os.environ,
            {"PSModulePath": r"C:\untrusted-pwsh-modules", "SAFE_MARKER": "kept"},
            clear=True,
        ), mock.patch.object(runtime.subprocess, "run", return_value=completed) as invoked:
            payload = runtime._authenticode_status(Path(r"C:\Clicky\Clicky.exe"))

        self.assertEqual(payload["Status"], "NotSigned")
        arguments = invoked.call_args.args[0]
        options = invoked.call_args.kwargs
        self.assertTrue(
            str(arguments[0])
            .lower()
            .endswith(r"windowspowershell\v1.0\powershell.exe")
        )
        self.assertIn(
            "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop",
            arguments[-1],
        )
        self.assertIn("Get-AuthenticodeSignature", arguments[-1])
        self.assertEqual(options["env"]["SAFE_MARKER"], "kept")
        self.assertFalse(
            any(name.casefold() == "psmodulepath" for name in options["env"])
        )

if __name__ == "__main__":
    unittest.main()
