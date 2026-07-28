"""Integrity, provenance, and compatibility tests for the Skill registry."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import skills
from capability_registry import CapabilityId
from skills.registry import (
    DEVELOPER_PYTHON_WARNING,
    SIGNED_EXTERNAL_SKILL_SUPPORT,
    SkillDefinitionIntegrityError,
    SkillEnablementStore,
    SkillKind,
    SkillManifestIntegrityError,
    SkillOrigin,
    SkillRegistrationStatus,
    catalog_developer_python_skills,
    combined_skill_catalog,
    declarative_skill_invocation_allowed,
    load_bundled_declarative_skills,
    permission_review_digest,
)
from skills.schema import (
    declarative_skill_source_digest,
    parse_declarative_skill_definition,
)


ROOT = Path(__file__).resolve().parents[1]


def _definition(
    *,
    skill_id: str = "clicky.test_summary",
    minimum_clicky_version: str = "1.2.0",
    invocation_mode: str = "explicit",
    invocation_phrases: list[str] | None = None,
) -> dict:
    candidate = {
        "schema_version": 1,
        "skill_id": skill_id,
        "version": "1.0.0",
        "name": "Bounded summary",
        "description": "Create one bounded, verified text result.",
        "invocation": {
            "mode": invocation_mode,
            "phrases": invocation_phrases or [],
        },
        "inputs": [
            {
                "input_id": "request",
                "input_type": "text",
                "description": "The explicit user request.",
                "required": True,
                "sensitive": False,
                "max_chars": 2_000,
                "max_bytes": None,
                "minimum": None,
                "maximum": None,
            }
        ],
        "output": {
            "output_type": "text",
            "media_type": "text/plain",
            "fields": [],
        },
        "prompt_template": "Summarize {{input.request}}.",
        "steps": [
            {
                "step_id": "verify",
                "tool": "verify.output",
                "capability": CapabilityId.TASK_AGENT_RUN.value,
                "depends_on": [],
                "arguments": [
                    {
                        "argument_id": "request",
                        "source": "input",
                        "reference": "request",
                        "value": None,
                    }
                ],
                "output_id": "verified_text",
                "connector": None,
                "approval_id": None,
            }
        ],
        "capabilities": [CapabilityId.TASK_AGENT_RUN.value],
        "connectors": [],
        "approvals": [],
        "limits": {
            "runtime_seconds": 60,
            "max_tool_calls": 1,
            "max_network_requests": 0,
            "max_output_bytes": 64 * 1024,
        },
        "publisher": {
            "publisher_id": "clicky.official",
            "display_name": "Clicky",
        },
        "source_digest": "0" * 64,
        "minimum_clicky_version": minimum_clicky_version,
    }
    provisional = parse_declarative_skill_definition(
        json.dumps(candidate).encode("utf-8")
    )
    candidate["source_digest"] = declarative_skill_source_digest(
        provisional
    )
    return candidate


def _write_bundle(
    root: Path,
    definitions: dict[str, dict | bytes],
) -> tuple[Path, dict[str, str]]:
    directory = root / "declarative"
    directory.mkdir(parents=True)
    digests: dict[str, str] = {}
    for filename, definition in definitions.items():
        payload = (
            definition
            if isinstance(definition, bytes)
            else json.dumps(
                definition,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
        )
        (directory / filename).write_bytes(payload)
        digests[filename] = hashlib.sha256(payload).hexdigest()
    (directory / "manifest.json").write_text(
        json.dumps(
            {"files": digests, "version": 1},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return directory, digests


class DeclarativeSkillRegistryTests(unittest.TestCase):
    def test_valid_bundled_definition_is_atomic_and_resolvable(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {"summary.skill.json": _definition()},
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )

        entry = snapshot.catalog_entries[0]
        self.assertEqual(entry.kind, SkillKind.DECLARATIVE)
        self.assertEqual(entry.origin, SkillOrigin.BUNDLED)
        self.assertEqual(
            entry.status,
            SkillRegistrationStatus.AVAILABLE,
        )
        self.assertIs(
            snapshot.resolve("clicky.test_summary"),
            entry.definition,
        )
        with self.assertRaises(TypeError):
            snapshot.registered_definitions["other"] = entry.definition

    def test_editing_a_definition_invalidates_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {"summary.skill.json": _definition()},
            )
            path = directory / "summary.skill.json"
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(
                SkillDefinitionIntegrityError,
                "digest differs",
            ):
                load_bundled_declarative_skills(
                    directory=directory,
                    embedded_digests=anchor,
                )

    def test_replacing_definition_and_manifest_cannot_replace_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {"summary.skill.json": _definition()},
            )
            changed = _definition(skill_id="clicky.changed")
            changed_payload = json.dumps(changed).encode("utf-8")
            (directory / "summary.skill.json").write_bytes(
                changed_payload
            )
            replacement_digest = hashlib.sha256(
                changed_payload
            ).hexdigest()
            (directory / "manifest.json").write_text(
                json.dumps(
                    {
                        "files": {
                            "summary.skill.json": replacement_digest
                        },
                        "version": 1,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SkillManifestIntegrityError,
                "embedded trust anchor",
            ):
                load_bundled_declarative_skills(
                    directory=directory,
                    embedded_digests=anchor,
                )

    def test_semantic_source_digest_is_independent_of_package_hash(self):
        candidate = _definition()
        candidate["source_digest"] = "f" * 64
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {"summary.skill.json": candidate},
            )
            with self.assertRaisesRegex(
                SkillDefinitionIntegrityError,
                "source digest differs",
            ):
                load_bundled_declarative_skills(
                    directory=directory,
                    embedded_digests=anchor,
                )

    def test_incompatible_skill_is_visible_but_never_registered(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {
                    "future.skill.json": _definition(
                        minimum_clicky_version="2.0.0"
                    )
                },
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )

        self.assertEqual(
            snapshot.catalog_entries[0].status,
            SkillRegistrationStatus.DISABLED_INCOMPATIBLE,
        )
        self.assertIsNone(snapshot.resolve("clicky.test_summary"))

    def test_malformed_overprivileged_and_duplicate_json_fail_before_snapshot(self):
        cases: list[dict | bytes] = []
        overprivileged = _definition()
        overprivileged["capabilities"].append(
            CapabilityId.WORKSPACE_COMMAND.value
        )
        cases.append(overprivileged)

        unknown_field = _definition()
        unknown_field["entrypoint"] = "module:handler"
        cases.append(unknown_field)

        valid_bytes = json.dumps(_definition()).encode("utf-8")
        cases.append(
            valid_bytes.replace(
                b'{"schema_version": 1,',
                b'{"schema_version": 1, "schema_version": 1,',
                1,
            )
        )

        for index, candidate in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                directory, anchor = _write_bundle(
                    Path(tmp),
                    {"invalid.skill.json": candidate},
                )
                with self.assertRaises(SkillDefinitionIntegrityError):
                    load_bundled_declarative_skills(
                        directory=directory,
                        embedded_digests=anchor,
                    )

    def test_unlisted_files_and_duplicate_skill_ids_abort_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory, anchor = _write_bundle(
                Path(tmp),
                {"summary.skill.json": _definition()},
            )
            (directory / "unlisted.txt").write_text(
                "not authorized",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                SkillManifestIntegrityError,
                "cover the directory",
            ):
                load_bundled_declarative_skills(
                    directory=directory,
                    embedded_digests=anchor,
                )

        with tempfile.TemporaryDirectory() as tmp:
            definition = _definition()
            directory, anchor = _write_bundle(
                Path(tmp),
                {
                    "one.skill.json": definition,
                    "two.skill.json": copy.deepcopy(definition),
                },
            )
            with self.assertRaisesRegex(
                SkillDefinitionIntegrityError,
                "IDs must be unique",
            ):
                load_bundled_declarative_skills(
                    directory=directory,
                    embedded_digests=anchor,
                )

    def test_developer_python_skills_are_visibly_separate_and_not_safe_labeled(self):
        loaded = skills.load_all()
        entries = catalog_developer_python_skills(loaded)

        self.assertTrue(entries)
        self.assertTrue(
            all(entry.kind is SkillKind.DEVELOPER_PYTHON for entry in entries)
        )
        self.assertTrue(
            all(
                entry.origin
                is SkillOrigin.BUNDLED_DEVELOPER_PYTHON
                for entry in entries
            )
        )
        self.assertTrue(
            all(entry.warning == DEVELOPER_PYTHON_WARNING for entry in entries)
        )
        self.assertIn("arbitrary Python", DEVELOPER_PYTHON_WARNING)
        self.assertIn(
            "identity, not code safety",
            DEVELOPER_PYTHON_WARNING,
        )

        snapshot = load_bundled_declarative_skills()
        combined = combined_skill_catalog(snapshot, loaded)
        self.assertEqual(
            len(combined),
            len(entries) + len(snapshot.catalog_entries),
        )
        self.assertIn(
            "clicky.research_to_csv",
            {entry.skill_id for entry in combined},
        )

    def test_future_signed_external_and_remote_installation_remain_disabled(self):
        self.assertEqual(
            SIGNED_EXTERNAL_SKILL_SUPPORT.origin,
            SkillOrigin.FUTURE_SIGNED_EXTERNAL,
        )
        self.assertFalse(
            SIGNED_EXTERNAL_SKILL_SUPPORT.registration_enabled
        )
        self.assertFalse(
            SIGNED_EXTERNAL_SKILL_SUPPORT.remote_installation_enabled
        )
        self.assertIn(
            "Remote skill installation is disabled",
            SIGNED_EXTERNAL_SKILL_SUPPORT.reason,
        )

    def test_registry_has_no_dynamic_code_loading_boundary(self):
        source = (ROOT / "skills" / "registry.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        called_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
        }
        self.assertNotIn("importlib", imported)
        self.assertTrue(
            {"compile", "eval", "exec", "__import__"}.isdisjoint(
                called_names
            )
        )

    def test_enablement_requires_the_exact_reviewed_permission_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory, anchor = _write_bundle(
                root / "bundle",
                {"summary.skill.json": _definition()},
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )
            entry = snapshot.catalog_entries[0]
            state_path = root / "state" / "skills.json"
            store = SkillEnablementStore(state_path)

            with self.assertRaisesRegex(
                ValueError,
                "must be reviewed",
            ):
                store.enable(
                    entry,
                    reviewed_permission_digest="f" * 64,
                )
            self.assertFalse(store.is_enabled(entry))

            review = permission_review_digest(entry)
            store.enable(
                entry,
                reviewed_permission_digest=review,
            )
            self.assertTrue(store.is_enabled(entry))
            restored = SkillEnablementStore(state_path)
            self.assertTrue(restored.is_enabled(entry))

            changed = _definition()
            changed["description"] = "A changed reviewed definition."
            provisional = parse_declarative_skill_definition(
                json.dumps(changed).encode("utf-8")
            )
            changed["source_digest"] = (
                declarative_skill_source_digest(provisional)
            )
            changed_directory, changed_anchor = _write_bundle(
                root / "changed",
                {"summary.skill.json": changed},
            )
            changed_snapshot = load_bundled_declarative_skills(
                directory=changed_directory,
                embedded_digests=changed_anchor,
            )
            self.assertFalse(
                restored.is_enabled(
                    changed_snapshot.catalog_entries[0]
                )
            )

    def test_disable_immediately_blocks_explicit_and_exact_phrase_invocation(self):
        definition = _definition(
            invocation_mode="deterministic_phrases",
            invocation_phrases=["run safe summary"],
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory, anchor = _write_bundle(
                root / "bundle",
                {"summary.skill.json": definition},
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )
            entry = snapshot.catalog_entries[0]
            state_path = root / "skills.json"
            store = SkillEnablementStore(state_path)
            store.enable(
                entry,
                reviewed_permission_digest=permission_review_digest(
                    entry
                ),
            )

            self.assertTrue(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=False,
                    utterance="  RUN   safe SUMMARY ",
                )
            )
            self.assertFalse(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=False,
                    utterance="please run safe summary now",
                )
            )
            self.assertTrue(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=True,
                )
            )

            self.assertTrue(store.disable(entry.skill_id))
            self.assertFalse(store.is_enabled(entry))
            self.assertFalse(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=True,
                )
            )
            self.assertFalse(
                SkillEnablementStore(state_path).is_enabled(entry)
            )

    def test_explicit_only_skill_never_uses_an_utterance_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory, anchor = _write_bundle(
                root / "bundle",
                {"summary.skill.json": _definition()},
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )
            entry = snapshot.catalog_entries[0]
            store = SkillEnablementStore(root / "skills.json")
            store.enable(
                entry,
                reviewed_permission_digest=permission_review_digest(
                    entry
                ),
            )
            self.assertFalse(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=False,
                    utterance=entry.name,
                )
            )
            self.assertTrue(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=True,
                )
            )

    def test_disable_is_a_session_deny_even_if_persistence_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory, anchor = _write_bundle(
                root / "bundle",
                {"summary.skill.json": _definition()},
            )
            snapshot = load_bundled_declarative_skills(
                directory=directory,
                embedded_digests=anchor,
            )
            entry = snapshot.catalog_entries[0]
            store = SkillEnablementStore(root / "skills.json")
            store.enable(
                entry,
                reviewed_permission_digest=permission_review_digest(
                    entry
                ),
            )
            with mock.patch.object(
                store,
                "_save",
                side_effect=OSError("synthetic storage failure"),
            ), self.assertRaises(OSError):
                store.disable(entry.skill_id)

            self.assertFalse(store.is_enabled(entry))
            self.assertFalse(
                declarative_skill_invocation_allowed(
                    snapshot,
                    store,
                    entry.skill_id,
                    explicit_selection=True,
                )
            )


if __name__ == "__main__":
    unittest.main()
