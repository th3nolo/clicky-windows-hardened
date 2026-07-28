"""Content-free Task Agent metadata persistence tests."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from capability_registry import CapabilityGrant, CapabilityId
import tasks.store as task_store
from tasks.models import (
    ApprovalRequest,
    Artifact,
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)
from tasks.store import (
    INTERRUPTED_RESULT_CODE,
    TASK_DATABASE_VERSION,
    TASK_EXPORT_VERSION,
    TaskStore,
    TaskStoreError,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
PRIVATE_GOAL = "PRIVATE_GOAL do not persist this task content"
PRIVATE_RESULT_REQUEST = "PRIVATE_RESULT_REQUEST with sensitive wording"
PRIVATE_APPROVAL_REASON = "PRIVATE_APPROVAL_REASON contains private context"
PRIVATE_ARGUMENT = "PRIVATE_ARGUMENT must never enter the metadata database"


class Clock:
    def __init__(self, value: float = 1_800_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


def run_fixture(
    run_id: str = "task-run-1",
    *,
    write: bool = True,
) -> TaskRun:
    capabilities = {CapabilityId.TASK_AGENT_RUN}
    if write:
        capabilities.add(CapabilityId.LOCAL_ARTIFACT_WRITE)
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.research",
            skill_version="1.0.0",
            goal=PRIVATE_GOAL,
            input_digest=DIGEST_A,
            requested_result=PRIVATE_RESULT_REQUEST,
            verifier_step_id="verify-output",
            verifier_id="table-postcondition-v1",
            limits=TaskLimits(
                runtime_seconds=300,
                max_tool_calls=8,
                max_network_requests=4,
                max_output_bytes=4 * 1024 * 1024,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(capabilities),
        ),
    )


def write_call(run_id: str = "task-run-1") -> ToolCall:
    return ToolCall(
        call_id="write-call-1",
        run_id=run_id,
        step_id="write-output",
        tool_name="artifact.write",
        capability=CapabilityId.LOCAL_ARTIFACT_WRITE,
        arguments_digest=DIGEST_B,
        action_digest=DIGEST_C,
    )


def approval(call: ToolCall) -> ApprovalRequest:
    return ApprovalRequest(
        approval_id=f"approval-{call.run_id}",
        run_id=call.run_id,
        call_id=call.call_id,
        capability=call.capability,
        action_digest=call.action_digest or DIGEST_C,
        reason=PRIVATE_APPROVAL_REASON,
        preview_digests=(DIGEST_A, DIGEST_B),
        expires_at=1_900_000_000.0,
    )


def verifier_result(run_id: str = "task-run-1") -> ToolResult:
    return ToolResult(
        result_id="verifier-result-1",
        call_id="verifier-call-1",
        run_id=run_id,
        step_id="verify-output",
        status=ToolResultStatus.SUCCEEDED,
        output_digest=DIGEST_B,
        output_bytes=512,
        verifier_id="table-postcondition-v1",
        postcondition_met=True,
        evidence_digest=DIGEST_C,
    )


class TaskStoreTests(unittest.TestCase):
    def test_empty_reads_and_export_do_not_create_a_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            store = TaskStore(database, _clock=Clock())
            self.assertEqual(store.list_tasks(), ())
            self.assertEqual(store.list_events("missing-run"), ())
            self.assertEqual(store.list_artifacts("missing-run"), ())
            self.assertEqual(store.list_approvals("missing-run"), ())
            self.assertFalse(database.exists())

    def test_lifecycle_grants_limits_approval_artifact_and_evidence_persist(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            store = TaskStore(database, _clock=Clock())
            run = run_fixture()
            queued = store.create_task(run)
            self.assertEqual(queued.state, TaskState.QUEUED)
            self.assertEqual(
                queued.grant.capabilities,
                run.grant.capabilities,
            )
            self.assertEqual(queued.limits, run.spec.limits)

            run.start()
            store.sync_run(run)
            call = write_call()
            request = approval(call)
            run.request_approval(
                call,
                request,
                now=1_800_000_010.0,
            )
            store.sync_run(run)
            self.assertEqual(store.list_approvals(run.run_id)[0].status, "pending")

            run.approve(
                request.approval_id,
                request.action_digest,
                now=1_800_000_020.0,
            )
            store.sync_run(run)
            self.assertEqual(store.list_approvals(run.run_id)[0].status, "granted")
            run.authorize_tool_call(call)

            provider_result = ToolResult(
                result_id="provider-result-1",
                call_id="provider-call-1",
                run_id=run.run_id,
                step_id="calendar",
                status=ToolResultStatus.SUCCEEDED,
                output_digest=DIGEST_A,
                output_bytes=64,
                provider_response_digest=DIGEST_B,
                provider_response_bytes=128,
                provider_request_id="provider-request-1",
            )
            provider_event = store.record_tool_result(provider_result)
            provider_metadata = dict(provider_event.metadata)
            self.assertEqual(
                provider_metadata["provider_response_digest"],
                DIGEST_B,
            )
            self.assertEqual(
                provider_metadata["provider_response_bytes"],
                128,
            )
            self.assertEqual(
                provider_metadata["provider_request_id"],
                "provider-request-1",
            )

            artifact = Artifact(
                artifact_id="artifact-1",
                run_id=run.run_id,
                source_call_id=call.call_id,
                name="research.csv",
                media_type="text/csv",
                byte_count=128,
                sha256=DIGEST_A,
                verification_result_id="verifier-result-1",
                verification_evidence_digest=DIGEST_C,
            )
            store.record_artifact(artifact)
            self.assertEqual(store.list_artifacts(run.run_id), (artifact,))

            result = verifier_result()
            event = store.record_tool_result(result)
            self.assertEqual(event.event_type, "tool_result")
            self.assertTrue(dict(event.metadata)["postcondition_met"])
            run.complete(result)
            completed = store.sync_run(run)
            self.assertEqual(completed.state, TaskState.COMPLETED)
            self.assertEqual(
                completed.verifier_evidence_digest,
                DIGEST_C,
            )
            self.assertIsNone(completed.result_code)

            exported = json.loads(store.export_task(run.run_id))
            self.assertEqual(exported["format"], "clicky-task-metadata")
            self.assertEqual(exported["version"], TASK_EXPORT_VERSION)
            self.assertEqual(
                exported["task"]["state"],
                TaskState.COMPLETED.value,
            )
            self.assertEqual(
                exported["task"]["limits"]["max_tool_calls"],
                8,
            )
            self.assertEqual(
                exported["artifacts"][0]["verification_result_id"],
                "verifier-result-1",
            )
            self.assertEqual(
                exported["artifacts"][0][
                    "verification_evidence_digest"
                ],
                DIGEST_C,
            )
            self.assertGreaterEqual(len(exported["events"]), 7)

            raw = database.read_bytes()
            for private in (
                PRIVATE_GOAL,
                PRIVATE_RESULT_REQUEST,
                PRIVATE_APPROVAL_REASON,
                PRIVATE_ARGUMENT,
            ):
                self.assertNotIn(private.encode("utf-8"), raw)
                self.assertNotIn(
                    private,
                    json.dumps(exported, sort_keys=True),
                )

    def test_restart_fails_every_nonterminal_task_and_never_resumes(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            first = TaskStore(database, _clock=Clock())

            queued = run_fixture("queued-run", write=False)
            first.create_task(queued)

            running = run_fixture("running-run", write=False)
            first.create_task(running)
            running.start()
            first.sync_run(running)

            waiting = run_fixture("waiting-run")
            first.create_task(waiting)
            waiting.start()
            first.sync_run(waiting)
            call = write_call("waiting-run")
            waiting.request_approval(
                call,
                approval(call),
                now=1_800_000_010.0,
            )
            first.sync_run(waiting)

            second = TaskStore(database, _clock=Clock(1_810_000_000.0))
            self.assertEqual(
                second.recovered_run_ids,
                ("queued-run", "running-run", "waiting-run"),
            )
            for run_id in second.recovered_run_ids:
                record = second.get_task(run_id)
                assert record is not None
                self.assertEqual(record.state, TaskState.FAILED)
                self.assertEqual(
                    record.result_code,
                    INTERRUPTED_RESULT_CODE,
                )
                self.assertTrue(record.interrupted)
                self.assertEqual(
                    second.list_events(run_id)[-1].event_type,
                    "interrupted_on_restart",
                )
            self.assertEqual(
                second.list_approvals("waiting-run")[0].status,
                "interrupted",
            )

            third = TaskStore(database, _clock=Clock(1_820_000_000.0))
            self.assertEqual(third.recovered_run_ids, ())

    def test_rejected_and_expired_approval_decisions_are_truthful(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            store = TaskStore(database, _clock=Clock())

            rejected = run_fixture("rejected-run")
            store.create_task(rejected)
            rejected.start()
            store.sync_run(rejected)
            rejected_call = write_call("rejected-run")
            rejected_request = approval(rejected_call)
            rejected.request_approval(
                rejected_call,
                rejected_request,
                now=1_800_000_010.0,
            )
            store.sync_run(rejected)
            rejected.reject_approval(
                rejected_request.approval_id,
                rejected_request.action_digest,
                now=1_800_000_020.0,
            )
            rejected_record = store.sync_run(rejected)
            self.assertEqual(rejected_record.state, TaskState.FAILED)
            self.assertEqual(
                rejected_record.result_code,
                "approval_rejected",
            )
            self.assertEqual(
                store.list_approvals("rejected-run")[0].status,
                "rejected",
            )

            expired = run_fixture("expired-run")
            store.create_task(expired)
            expired.start()
            store.sync_run(expired)
            expired_call = write_call("expired-run")
            expired_request = approval(expired_call)
            expired.request_approval(
                expired_call,
                expired_request,
                now=1_800_000_010.0,
            )
            store.sync_run(expired)
            expired.expire_approval(now=1_900_000_001.0)
            expired_record = store.sync_run(expired)
            self.assertEqual(expired_record.state, TaskState.EXPIRED)
            self.assertEqual(
                expired_record.result_code,
                "approval_expired",
            )
            self.assertEqual(
                store.list_approvals("expired-run")[0].status,
                "expired",
            )

    def test_version_one_store_migrates_adoption_and_decision_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                task_store._migration_0_to_1(connection)
                connection.execute(
                    "INSERT INTO task_runs ("
                    "run_id, created_at, updated_at, state, skill_id, "
                    "skill_version, input_digest, goal_digest, "
                    "requested_result_digest, verifier_step_id, verifier_id, "
                    "grant_schema_version, capabilities_json, runtime_seconds, "
                    "max_tool_calls, max_network_requests, max_output_bytes, "
                    "result_code, verifier_result_id, "
                    "verifier_evidence_digest, interrupted"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                    "?, ?, ?, ?, ?, ?)",
                    (
                        "legacy-run",
                        1.0,
                        2.0,
                        TaskState.FAILED.value,
                        "clicky.legacy",
                        "1.0.0",
                        DIGEST_A,
                        DIGEST_B,
                        DIGEST_C,
                        "verify",
                        "verify-v1",
                        1,
                        json.dumps([CapabilityId.TASK_AGENT_RUN.value]),
                        60,
                        4,
                        0,
                        1024,
                        "legacy_failure",
                        None,
                        None,
                        0,
                    ),
                )
                connection.execute(
                    "INSERT INTO task_approvals ("
                    "approval_id, run_id, call_id, capability, action_digest, "
                    "reason_digest, preview_digests_json, expires_at, status"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "legacy-approval",
                        "legacy-run",
                        "legacy-call",
                        CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                        DIGEST_A,
                        DIGEST_B,
                        json.dumps([DIGEST_A]),
                        100.0,
                        "granted",
                    ),
                )
                connection.execute(
                    "INSERT INTO task_artifacts ("
                    "artifact_id, run_id, source_call_id, name, media_type, "
                    "byte_count, sha256, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        "legacy-artifact",
                        "legacy-run",
                        "legacy-call",
                        "legacy.txt",
                        "text/plain",
                        4,
                        DIGEST_C,
                        3.0,
                    ),
                )
                connection.execute("PRAGMA user_version = 1")
                connection.commit()

            migrated = TaskStore(database, _clock=Clock())
            with closing(sqlite3.connect(database)) as connection:
                version = connection.execute(
                    "PRAGMA user_version"
                ).fetchone()[0]
                artifact_columns = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(task_artifacts)"
                    )
                }
                approval_sql = connection.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'task_approvals'"
                ).fetchone()[0]
                integrity = connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0]
                foreign_key_violations = list(
                    connection.execute("PRAGMA foreign_key_check")
                )
            self.assertEqual(version, TASK_DATABASE_VERSION)
            self.assertEqual(integrity, "ok")
            self.assertEqual(foreign_key_violations, [])
            self.assertIn("verification_result_id", artifact_columns)
            self.assertIn(
                "verification_evidence_digest",
                artifact_columns,
            )
            self.assertIn("'rejected'", approval_sql)
            self.assertIn("'expired'", approval_sql)
            self.assertEqual(
                migrated.list_approvals("legacy-run")[0].status,
                "granted",
            )
            legacy_artifact = migrated.list_artifacts("legacy-run")[0]
            self.assertFalse(legacy_artifact.adopted)
            self.assertIsNone(legacy_artifact.verification_result_id)

    def test_retention_delete_and_export_are_explicit_and_cascade(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "task_metadata.db"
            clock = Clock()
            store = TaskStore(database, _clock=clock)
            old = run_fixture("old-run", write=False)
            store.create_task(old)
            old.start()
            store.sync_run(old)
            old.fail("synthetic_failure")
            record = store.sync_run(old)

            keep = run_fixture("keep-run", write=False)
            store.create_task(keep)
            keep.start()
            store.sync_run(keep)
            keep.fail("synthetic_failure")
            store.sync_run(keep)

            purged = store.purge_expired(
                retention_seconds=3_600,
                now=record.updated_at + 3_601,
            )
            self.assertEqual(purged, ("old-run",))
            self.assertIsNone(store.get_task("old-run"))
            self.assertIsNotNone(store.get_task("keep-run"))

            self.assertTrue(store.delete_task("keep-run"))
            self.assertFalse(store.delete_task("keep-run"))
            self.assertEqual(store.list_events("keep-run"), ())
            self.assertEqual(store.list_tasks(), ())
            with self.assertRaisesRegex(ValueError, "retention"):
                store.purge_expired(retention_seconds=1)

    def test_event_bound_is_enforced_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = TaskStore(
                Path(temporary) / "task_metadata.db",
                _clock=Clock(),
            )
            run = run_fixture(write=False)
            with mock.patch.object(
                task_store,
                "MAX_EVENTS_PER_TASK",
                2,
            ):
                store.create_task(run)
                run.start()
                store.sync_run(run)
                with self.assertRaisesRegex(TaskStoreError, "event"):
                    store.record_tool_result(verifier_result())
                self.assertEqual(len(store.list_events(run.run_id)), 2)

                reopened = TaskStore(
                    store.database_path,
                    _clock=Clock(1_810_000_000.0),
                )
                self.assertEqual(
                    reopened.recovered_run_ids,
                    (run.run_id,),
                )
                self.assertEqual(len(reopened.list_events(run.run_id)), 3)
                recovered = reopened.get_task(run.run_id)
                assert recovered is not None
                self.assertEqual(recovered.state, TaskState.FAILED)

    def test_late_results_and_artifacts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = TaskStore(
                Path(temporary) / "task_metadata.db",
                _clock=Clock(),
            )
            run = run_fixture(write=False)
            store.create_task(run)
            run.start()
            store.sync_run(run)
            run.cancel()
            store.sync_run(run)

            with self.assertRaisesRegex(ValueError, "persisted state"):
                store.record_tool_result(verifier_result())
            with self.assertRaisesRegex(ValueError, "running tasks"):
                store.record_artifact(
                    Artifact(
                        artifact_id="late-artifact",
                        run_id=run.run_id,
                        source_call_id="late-call",
                        name="late.txt",
                        media_type="text/plain",
                        byte_count=4,
                        sha256=DIGEST_A,
                        verification_result_id="late-verifier-result",
                        verification_evidence_digest=DIGEST_C,
                    )
                )

    def test_unknown_schema_and_linked_database_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "task_metadata.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA user_version = 99")
                connection.commit()
            with self.assertRaisesRegex(TaskStoreError, "unsupported"):
                TaskStore(database, _clock=Clock())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.db"
            target.write_bytes(b"do not modify")
            link = root / "task_metadata.db"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are unavailable")
            with self.assertRaisesRegex(TaskStoreError, "linked"):
                TaskStore(link, _clock=Clock())
            self.assertEqual(target.read_bytes(), b"do not modify")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.db"
            target.write_bytes(b"do not modify")
            linked = root / "task_metadata.db"
            try:
                os.link(target, linked)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaisesRegex(TaskStoreError, "linked"):
                TaskStore(linked, _clock=Clock())
            self.assertEqual(target.read_bytes(), b"do not modify")

    def test_schema_version_and_default_path_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {"LOCALAPPDATA": temporary},
                clear=False,
            ):
                store = TaskStore(_clock=Clock())
                self.assertEqual(
                    store.database_path,
                    Path(temporary) / "Clicky" / "task_metadata.db",
                )
                store.create_task(run_fixture(write=False))
                with closing(
                    sqlite3.connect(store.database_path)
                ) as connection:
                    version = connection.execute(
                        "PRAGMA user_version"
                    ).fetchone()[0]
                self.assertEqual(version, TASK_DATABASE_VERSION)


if __name__ == "__main__":
    unittest.main()
