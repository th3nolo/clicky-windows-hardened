"""Local app suggestions preserve an explicit, non-retaining boundary."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from onboarding.app_suggestions import (
    MAX_SUGGESTIONS,
    discover_local_app_suggestions,
)


ROOT = Path(__file__).resolve().parents[1]


class _Source:
    def __init__(self, names):
        self.names = tuple(names)
        self.calls = 0

    def list_app_names(self):
        self.calls += 1
        return self.names


class AppSuggestionTests(unittest.TestCase):
    def test_consent_is_required_before_enumeration(self):
        source = _Source(("Visual Studio Code",))
        with self.assertRaises(PermissionError):
            discover_local_app_suggestions(
                consent=False,
                disabled=False,
                source=source,
            )
        self.assertEqual(source.calls, 0)

    def test_disabled_state_blocks_enumeration_even_with_consent(self):
        source = _Source(("Visual Studio Code",))
        with self.assertRaises(PermissionError):
            discover_local_app_suggestions(
                consent=True,
                disabled=True,
                source=source,
            )
        self.assertEqual(source.calls, 0)

    def test_results_are_sanitized_deduplicated_sorted_and_bounded(self):
        source = _Source((
            "Visual Studio Code",
            "visual studio code",
            "Microsoft Edge WebView2 Runtime",
            "Bad\nName",
            "Zoom",
            "Notion",
            "Microsoft Word",
            "Microsoft Excel",
            "Firefox",
            "Obsidian",
        ))
        result = discover_local_app_suggestions(
            consent=True,
            disabled=False,
            source=source,
        )
        self.assertEqual(source.calls, 1)
        self.assertEqual(len(result), MAX_SUGGESTIONS)
        self.assertEqual(
            [suggestion.app_name for suggestion in result],
            sorted(
                [suggestion.app_name for suggestion in result],
                key=str.casefold,
            ),
        )
        self.assertEqual(
            len({suggestion.app_name.casefold() for suggestion in result}),
            len(result),
        )
        self.assertNotIn(
            "Microsoft Edge WebView2 Runtime",
            [suggestion.app_name for suggestion in result],
        )

    def test_known_apps_receive_bounded_non_actioning_use_cases(self):
        result = discover_local_app_suggestions(
            consent=True,
            disabled=False,
            source=_Source(("Microsoft Outlook", "Visual Studio Code")),
        )
        text = " ".join(suggestion.use_case for suggestion in result)
        self.assertIn("sending remains a separate user action", text)
        self.assertIn("reviewed workspace change", text)

    def test_preferences_store_flags_but_not_inventory(self):
        import config

        instance = config.Config(
            app_suggestions_consent=False,
            app_suggestions_disabled=False,
        )
        with mock.patch.object(config, "_save_preferences") as save:
            instance.set_app_suggestions_preferences(
                consent=True,
                disabled=False,
            )
        save.assert_called_once_with(
            app_suggestions_consent=True,
            app_suggestions_disabled=False,
        )
        self.assertFalse(
            any(
                "app" in key and "name" in key
                for key in save.call_args.kwargs
            )
        )
        with self.assertRaises(ValueError):
            instance.set_app_suggestions_preferences(
                consent=True,
                disabled=True,
            )

    def test_scanner_has_no_network_process_or_persistence_path(self):
        source = (
            ROOT / "onboarding" / "app_suggestions.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "httpx",
            "requests",
            "aiohttp",
            "urlopen",
            "subprocess",
            "Popen",
            "write_text",
            "Start-Process",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
