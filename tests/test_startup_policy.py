"""Default-off startup parity for classic and MSIX installs."""

from __future__ import annotations

import unittest
from pathlib import Path
from xml.etree import ElementTree

from tools.build_msix import render_manifest


ROOT = Path(__file__).resolve().parents[1]
DESKTOP = "http://schemas.microsoft.com/appx/manifest/desktop/windows10"
FOUNDATION = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"


class StartupPolicyTests(unittest.TestCase):
    def test_classic_installer_startup_task_is_default_off_and_removable(self):
        source = (ROOT / "installer.iss").read_text(encoding="utf-8")
        task = next(
            line
            for line in source.splitlines()
            if line.startswith('Name: "startupicon"')
        )
        shortcut = next(
            line
            for line in source.splitlines()
            if 'Name: "{userstartup}\\{#MyAppName}"' in line
        )
        self.assertIn("Flags: unchecked", task)
        self.assertIn("Tasks: startupicon", shortcut)
        self.assertNotIn("uninsneveruninstall", shortcut.casefold())

    def test_msix_declares_one_default_off_full_trust_startup_task(self):
        manifest = render_manifest(
            identity_name="Partner.Clicky",
            publisher="CN=Manuel Parra",
            publisher_display_name="Manuel Parra",
            version="1.2.0.0",
        )
        root = ElementTree.fromstring(manifest)
        application = root.find(f".//{{{FOUNDATION}}}Application")
        self.assertIsNotNone(application)
        extensions = application.findall(
            f"./{{{FOUNDATION}}}Extensions/{{{DESKTOP}}}Extension",
        )
        self.assertEqual(len(extensions), 1)
        extension = extensions[0]
        self.assertEqual(
            extension.attrib,
            {
                "Category": "windows.startupTask",
                "Executable": r"Clicky\Clicky.exe",
                "EntryPoint": "Windows.FullTrustApplication",
            },
        )
        task = extension.find(f"{{{DESKTOP}}}StartupTask")
        self.assertIsNotNone(task)
        self.assertEqual(task.attrib["TaskId"], "ClickyStartup")
        self.assertEqual(task.attrib["Enabled"], "false")
        self.assertEqual(task.attrib["DisplayName"], "Clicky")

    def test_in_app_control_opens_only_fixed_windows_startup_settings(self):
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        tray = (ROOT / "ui" / "tray.py").read_text(encoding="utf-8")
        self.assertIn("Windows startup settings…", tray)
        self.assertIn("on_open_startup_settings", tray)
        self.assertIn('os.startfile("ms-settings:startupapps")', main)
        self.assertNotIn(
            "CurrentVersion\\Run",
            main + tray,
        )


if __name__ == "__main__":
    unittest.main()
