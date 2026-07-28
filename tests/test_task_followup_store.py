"""Immutable parent/child task linkage and retention tests."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import (
    Artifact,
    FollowupArtifactReference,
    TaskFollowupLink,
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
)
from tasks.store import (
    TASK_DATABASE_VERSION,
    TASK_EXPORT_VERSION,
    TaskStore,
    TaskStoreConflictError,
    TaskStoreCorruptError,
)


PRIVATE_FOLLOWUP = "PRIVATE FOLLOW-UP CONTENT must not enter SQLite"


class Clock:
    def __init__(self, value: float = 1_900_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


def run_fixture(
    run_id: str,
    *,
    input_digest: str,
    read: bool = False,
) -> TaskRun:
    capabilities = {CapabilityId.TASK_AGENT_RUN}
    if read:
        capabilities.add(CapabilityId.LOCAL_ARTIFACT_READ)
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.task-followup",
            skill_version="1.0.0",
            goal=PRIVATE_FOLLOWUP,
            input_digest=input_digest,
            requested_result="One bounded follow-up.",
            verifier_step_id="verify-followup-delivery",
            verifier_id="followup-text-delivery-v1",
            limits=TaskLimits(
                runtime_seconds=120,
                max_tool_calls=2 if read else 1,
                max_network_requests=1,
                max_output_bytes=64 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(capabilities),
        ),
    )


def parent_and_artifact(store: TaskStore):
    parent = run_fixture(
        "parent-run",
        input_digest="a" * 64,
    )
    store.create_task(parent)
    parent.start()
    store.sync_run(parent)
    content = b"verified source"
    artifact = Artifact(
        artifact_id="parent-artifact",
        run_id=parent.run_id,
        source_call_id="parent-source-call",
        name="source.txt",
        media_type="text/plain",
        byte_count=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        verification_result_id="parent-verifier-result",
        verification_evidence_digest="e" * 64,
    )
    store.record_artifact(artifact)
    parent.fail("synthetic_parent_terminal")
    parent_record = store.sync_run(parent)
    return parent_record, artifact


def link_fixture(parent, artifact):
    return TaskFollowupLink(
        child_run_id="child-run",
        parent_run_id=parent.run_id,
        parent_updated_at=parent.updated_at,
        request_digest="b" * 64,
        review_digest="c" * 64,
        selected_artifacts=(
            FollowupArtifactReference.from_artifact(artifact),
        ),
    )


class TaskFollowupStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = Clock()
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3",
            _clock=self.clock,
        )

    def test_link_export_and_deletion_preserve_parent_evidence(self) -> None:
        parent, artifact = parent_and_artifact(self.store)
        link = link_fixture(parent, artifact)
        child = run_fixture(
            link.child_run_id,
            input_digest=link.request_digest,
            read=True,
        )

        self.store.create_followup(child, link)

        self.assertEqual(self.store.get_followup(child.run_id), link)
        self.assertEqual(
            tuple(item.run_id for item in self.store.list_children(parent.run_id)),
            (child.run_id,),
        )
        exported = json.loads(self.store.export_task(child.run_id))
        self.assertEqual(exported["version"], TASK_EXPORT_VERSION)
        self.assertEqual(
            exported["followup"]["parent_run_id"],
            parent.run_id,
        )
        self.assertEqual(
            exported["followup"]["selected_artifacts"][0]["sha256"],
            artifact.sha256,
        )
        self.assertNotIn(
            PRIVATE_FOLLOWUP,
            self.store.database_path.read_bytes().decode(
                "utf-8",
                errors="ignore",
            ),
        )
        with self.assertRaisesRegex(
            TaskStoreConflictError,
            "prevents deletion",
        ):
            self.store.delete_task(parent.run_id)
        self.assertTrue(self.store.delete_task(child.run_id))
        self.assertTrue(self.store.delete_task(parent.run_id))

    def test_stale_parent_and_changed_artifact_fail_atomically(self) -> None:
        parent, artifact = parent_and_artifact(self.store)
        original = link_fixture(parent, artifact)
        cases = (
            replace(original, parent_updated_at=parent.updated_at - 1),
            replace(
                original,
                selected_artifacts=(
                    replace(
                        original.selected_artifacts[0],
                        sha256="f" * 64,
                    ),
                ),
            ),
        )
        for index, link in enumerate(cases):
            with self.subTest(index=index):
                child = run_fixture(
                    link.child_run_id,
                    input_digest=link.request_digest,
                    read=True,
                )
                with self.assertRaises(TaskStoreConflictError):
                    self.store.create_followup(child, link)
                self.assertIsNone(self.store.get_task(child.run_id))
                self.assertIsNone(self.store.get_followup(child.run_id))

    def test_old_parent_is_retained_until_terminal_child_is_purged(self) -> None:
        parent, artifact = parent_and_artifact(self.store)
        link = link_fixture(parent, artifact)
        child = run_fixture(
            link.child_run_id,
            input_digest=link.request_digest,
            read=True,
        )
        self.store.create_followup(child, link)
        child.fail("synthetic_child_terminal")
        child_record = self.store.sync_run(child)

        purged = self.store.purge_expired(
            retention_seconds=3_600,
            now=child_record.updated_at + 3_601,
        )
        self.assertEqual(purged, (child.run_id,))
        self.assertIsNotNone(self.store.get_task(parent.run_id))
        self.assertIsNone(self.store.get_task(child.run_id))

        purged = self.store.purge_expired(
            retention_seconds=3_600,
            now=child_record.updated_at + 3_602,
        )
        self.assertEqual(purged, (parent.run_id,))

    def test_fresh_grant_must_exactly_match_selected_sources(self) -> None:
        parent, artifact = parent_and_artifact(self.store)
        link = link_fixture(parent, artifact)
        no_read = run_fixture(
            link.child_run_id,
            input_digest=link.request_digest,
            read=False,
        )
        with self.assertRaisesRegex(ValueError, "fresh grant"):
            self.store.create_followup(no_read, link)
        changed_request = run_fixture(
            link.child_run_id,
            input_digest="d" * 64,
            read=True,
        )
        with self.assertRaisesRegex(ValueError, "identity"):
            self.store.create_followup(changed_request, link)
        self.assertIsNone(self.store.get_task(link.child_run_id))

    def test_persisted_parent_or_artifact_corruption_is_not_displayed(self):
        parent, artifact = parent_and_artifact(self.store)
        link = link_fixture(parent, artifact)
        child = run_fixture(
            link.child_run_id,
            input_digest=link.request_digest,
            read=True,
        )
        self.store.create_followup(child, link)

        with closing(sqlite3.connect(self.store.database_path)) as connection:
            connection.execute(
                "UPDATE task_runs SET interrupted = 1 WHERE run_id = ?",
                (parent.run_id,),
            )
            connection.commit()
        with self.assertRaisesRegex(
            TaskStoreCorruptError,
            "linkage metadata",
        ):
            self.store.get_followup(child.run_id)

        with closing(sqlite3.connect(self.store.database_path)) as connection:
            connection.execute(
                "UPDATE task_runs SET interrupted = 0 WHERE run_id = ?",
                (parent.run_id,),
            )
            connection.execute(
                "UPDATE task_followup_artifacts SET sha256 = ? "
                "WHERE child_run_id = ?",
                ("f" * 64, child.run_id),
            )
            connection.commit()
        with self.assertRaisesRegex(
            TaskStoreCorruptError,
            "linkage metadata",
        ):
            self.store.get_followup(child.run_id)

    def test_v2_database_migrates_to_immutable_link_schema(self) -> None:
        database = Path(self.temporary.name) / "legacy-v2.sqlite3"
        connection = sqlite3.connect(database)
        try:
            from tasks.store import _migration_0_to_1, _migration_1_to_2

            _migration_0_to_1(connection)
            _migration_1_to_2(connection)
            connection.execute("PRAGMA user_version = 2")
            connection.commit()
        finally:
            connection.close()

        TaskStore(database, _clock=self.clock)
        with closing(sqlite3.connect(database)) as connection:
            version = connection.execute(
                "PRAGMA user_version"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
        self.assertEqual(version, TASK_DATABASE_VERSION)
        self.assertIn("task_followups", tables)
        self.assertIn("task_followup_artifacts", tables)
        self.assertEqual(integrity, "ok")


if __name__ == "__main__":
    unittest.main()
