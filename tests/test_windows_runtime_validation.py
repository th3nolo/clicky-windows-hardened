"""Tests for host-independent Windows runtime validation helpers."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tools import windows_runtime_validation as runtime


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


if __name__ == "__main__":
    unittest.main()
