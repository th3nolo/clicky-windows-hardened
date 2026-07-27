"""Fail-closed boundaries for unfinished action capabilities."""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import feature_gates
import privacy_controls


ROOT = Path(__file__).resolve().parents[1]


def load_config(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "config.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def configured(**overrides):
    values = {
        "privacy_consent_version": privacy_controls.PRIVACY_NOTICE_VERSION,
        "action_permission_schema_version": (
            feature_gates.ACTION_PERMISSION_SCHEMA_VERSION
        ),
        "global_dictation_permission": False,
        "screen_compose_permission": False,
        "task_agent_permission": False,
        "connector_read_permission": False,
        "connector_write_permission": False,
        "workspace_coding_permission": False,
        "desktop_automation_permission": False,
    }
    values.update(overrides)
    return types.SimpleNamespace(**values)


def build_flags(*available):
    flags = {
        capability: feature_gates.BuildFeatureFlag()
        for capability in feature_gates.ActionCapability
    }
    for capability in available:
        flags[capability] = feature_gates.BuildFeatureFlag(
            available=True,
            permission_schema_version=(
                feature_gates.ACTION_PERMISSION_SCHEMA_VERSION
            ),
        )
    return flags


class ActionFeatureGateTests(unittest.TestCase):
    def test_baseline_build_flags_are_complete_and_disabled(self):
        flags = feature_gates.DEFAULT_BUILD_FEATURE_FLAGS
        self.assertEqual(set(flags), set(feature_gates.ActionCapability))
        self.assertTrue(all(not flag.available for flag in flags.values()))

    def test_build_user_and_run_layers_are_independent(self):
        global_dictation = feature_gates.ActionCapability.GLOBAL_DICTATION
        compose = feature_gates.ActionCapability.SCREEN_AWARE_COMPOSE
        flags = build_flags(global_dictation, compose)
        config = configured(global_dictation_permission=True)
        grant = feature_gates.RunCapabilityGrant(
            run_id="dictation-run-1",
            capabilities=frozenset({global_dictation}),
        )

        self.assertTrue(
            feature_gates.action_capability_allowed(
                config,
                global_dictation,
                grant=grant,
                run_id="dictation-run-1",
                build_flags=flags,
            )
        )
        self.assertFalse(
            feature_gates.action_capability_allowed(
                config,
                compose,
                grant=grant,
                run_id="dictation-run-1",
                build_flags=flags,
            )
        )
        self.assertFalse(
            feature_gates.action_capability_allowed(
                config,
                global_dictation,
                grant=grant,
                run_id="superseding-run",
                build_flags=flags,
            )
        )
        self.assertFalse(
            feature_gates.action_capability_allowed(
                config,
                global_dictation,
                grant=grant,
                run_id="dictation-run-1",
            )
        )

    def test_startup_rejects_available_flag_without_current_schema(self):
        flags = build_flags()
        flags[feature_gates.ActionCapability.TASK_AGENT] = (
            feature_gates.BuildFeatureFlag(available=True)
        )
        with self.assertRaisesRegex(RuntimeError, "current permission schema"):
            feature_gates.validate_action_capability_startup(
                configured(),
                flags,
            )

    def test_stale_permission_cannot_authorize_and_refuses_startup(self):
        config = configured(
            action_permission_schema_version=0,
            connector_read_permission=True,
        )
        self.assertFalse(
            feature_gates.user_permission_allowed(
                config,
                feature_gates.ActionCapability.CONNECTOR_READ,
            )
        )
        with self.assertRaisesRegex(RuntimeError, "without the current schema"):
            feature_gates.validate_action_capability_startup(config)

    def test_run_grant_rejects_invalid_identity_and_capabilities(self):
        with self.assertRaises(ValueError):
            feature_gates.RunCapabilityGrant(
                run_id=" changed ",
                capabilities=frozenset(
                    {feature_gates.ActionCapability.GLOBAL_DICTATION}
                ),
            )
        with self.assertRaises(TypeError):
            feature_gates.RunCapabilityGrant(
                run_id="run-1",
                capabilities=frozenset({"global_dictation"}),
            )

    def test_permissions_default_off_and_persist_atomically(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("action_feature_gate_config")
            initial = config.Config()
            self.assertEqual(initial.action_permission_schema_version, 0)
            for capability in feature_gates.ActionCapability:
                self.assertFalse(
                    feature_gates.user_permission_allowed(initial, capability)
                )

            initial.set_action_permissions(
                global_dictation=True,
                screen_compose=False,
                task_agent=False,
                connector_read=False,
                connector_write=False,
                workspace_coding=False,
                desktop_automation=False,
                permission_schema_version=(
                    feature_gates.ACTION_PERMISSION_SCHEMA_VERSION
                ),
            )
            restored = config.Config()
            self.assertTrue(restored.global_dictation_permission)
            self.assertFalse(restored.screen_compose_permission)
            self.assertEqual(
                restored.action_permission_schema_version,
                feature_gates.ACTION_PERMISSION_SCHEMA_VERSION,
            )
            payload = json.loads(
                config._preferences_path().read_text(encoding="utf-8")
            )
            self.assertEqual(
                payload["preferences"]["global_dictation_permission"],
                True,
            )

    def test_exposed_dictation_permission_persists_with_privacy_notice(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("dictation_privacy_permission_config")
            initial = config.Config()

            initial.set_privacy_permissions(
                microphone=True,
                cloud_stt=False,
                cloud_tts=False,
                screen_capture=False,
                coding_agent=False,
                notice_version=privacy_controls.PRIVACY_NOTICE_VERSION,
                global_dictation=True,
            )

            restored = config.Config()
            self.assertEqual(
                restored.privacy_consent_version,
                privacy_controls.PRIVACY_NOTICE_VERSION,
            )
            self.assertEqual(
                restored.action_permission_schema_version,
                feature_gates.ACTION_PERMISSION_SCHEMA_VERSION,
            )
            self.assertTrue(restored.microphone_consent)
            self.assertTrue(restored.global_dictation_permission)
            self.assertTrue(
                feature_gates.user_permission_allowed(
                    restored,
                    feature_gates.ActionCapability.GLOBAL_DICTATION,
                )
            )

    def test_permission_storage_failure_changes_no_in_memory_state(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            config = load_config("action_feature_gate_storage_failure")
            initial = config.Config()
            with mock.patch.object(
                config,
                "_save_preferences",
                side_effect=OSError("storage blocked"),
            ), self.assertRaisesRegex(OSError, "storage blocked"):
                initial.set_action_permissions(
                    global_dictation=True,
                    screen_compose=True,
                    task_agent=True,
                    connector_read=True,
                    connector_write=True,
                    workspace_coding=True,
                    desktop_automation=True,
                    permission_schema_version=(
                        feature_gates.ACTION_PERMISSION_SCHEMA_VERSION
                    ),
                )
            self.assertEqual(initial.action_permission_schema_version, 0)
            self.assertFalse(initial.global_dictation_permission)
            self.assertFalse(initial.desktop_automation_permission)

    def test_valid_permission_without_schema_never_opts_in(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            directory = Path(temporary) / "Clicky"
            directory.mkdir()
            (directory / "preferences.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "preferences": {
                            "privacy_consent_version": (
                                privacy_controls.PRIVACY_NOTICE_VERSION
                            ),
                            "global_dictation_permission": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_config("stale_action_feature_gate_config")
            restored = config.Config()
            self.assertTrue(restored.global_dictation_permission)
            self.assertFalse(
                feature_gates.user_permission_allowed(
                    restored,
                    feature_gates.ActionCapability.GLOBAL_DICTATION,
                )
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "without the current schema",
            ):
                feature_gates.validate_action_capability_startup(restored)

    def test_old_or_tampered_preferences_do_not_opt_in(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(
            os.environ,
            {"LOCALAPPDATA": temporary},
            clear=True,
        ):
            directory = Path(temporary) / "Clicky"
            directory.mkdir()
            (directory / "preferences.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "preferences": {
                            "privacy_consent_version": (
                                privacy_controls.PRIVACY_NOTICE_VERSION
                            ),
                            "global_dictation_permission": "yes",
                            "screen_compose_permission": 1,
                            "task_agent_permission": [],
                            "connector_read_permission": {},
                            "connector_write_permission": None,
                            "workspace_coding_permission": "true",
                            "desktop_automation_permission": 1.0,
                        },
                    }
                ),
                encoding="utf-8",
            )
            config = load_config("tampered_action_feature_gate_config")
            restored = config.Config()
            self.assertEqual(restored.action_permission_schema_version, 0)
            for capability in feature_gates.ActionCapability:
                self.assertFalse(
                    feature_gates.user_permission_allowed(restored, capability)
                )

    def test_main_validates_action_configuration_before_qt_startup(self):
        tree = ast.parse((ROOT / "main.py").read_text(encoding="utf-8"))
        main = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        calls = {
            (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
            ): node.lineno
            for node in ast.walk(main)
            if isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Name, ast.Attribute))
            and (
                isinstance(node.func, ast.Name)
                or node.func.attr in {"QApplication", "CompanionManager"}
            )
        }
        self.assertLess(
            calls["validate_action_capability_startup"],
            calls["QApplication"],
        )
        self.assertLess(
            calls["validate_action_capability_startup"],
            calls["CompanionManager"],
        )


if __name__ == "__main__":
    unittest.main()
