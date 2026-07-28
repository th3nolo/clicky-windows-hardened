"""Fail-closed Task Agent model and lifecycle tests."""

from __future__ import annotations

import unittest

from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import (
    ApprovalRequest,
    Artifact,
    TaskRun,
    TaskLimits,
    TaskSpec,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


def spec(run_id: str = "task-run-1") -> TaskSpec:
    return TaskSpec(
        run_id=run_id,
        skill_id="clicky.research",
        skill_version="1.0.0",
        goal="Research public sources and create an evidence table.",
        input_digest=DIGEST_A,
        requested_result="A source-backed table.",
        verifier_step_id="verify-output",
        verifier_id="table-postcondition-v1",
        limits=TaskLimits(
            runtime_seconds=300,
            max_tool_calls=8,
            max_network_requests=4,
            max_output_bytes=4 * 1024 * 1024,
        ),
    )


def grant(
    run_id: str = "task-run-1",
    *extra: CapabilityId,
) -> CapabilityGrant:
    return CapabilityGrant(
        run_id=run_id,
        capabilities=frozenset(
            {CapabilityId.TASK_AGENT_RUN, *extra}
        ),
    )


def call(
    capability: CapabilityId,
    *,
    run_id: str = "task-run-1",
    call_id: str = "call-1",
    action_digest: str | None = None,
) -> ToolCall:
    return ToolCall(
        call_id=call_id,
        run_id=run_id,
        step_id="write-output",
        tool_name="artifact.write",
        capability=capability,
        arguments_digest=DIGEST_B,
        action_digest=action_digest,
    )


def approval(tool_call: ToolCall) -> ApprovalRequest:
    assert tool_call.action_digest is not None
    return ApprovalRequest(
        approval_id="approval-1",
        run_id=tool_call.run_id,
        call_id=tool_call.call_id,
        capability=tool_call.capability,
        action_digest=tool_call.action_digest,
        reason="Review the exact destination and content digest.",
        preview_digests=(DIGEST_C,),
        expires_at=100.0,
    )


def verification(
    *,
    run_id: str = "task-run-1",
    step_id: str = "verify-output",
    verifier_id: str | None = "table-postcondition-v1",
    met: bool | None = True,
    status: ToolResultStatus = ToolResultStatus.SUCCEEDED,
) -> ToolResult:
    return ToolResult(
        result_id="result-1",
        call_id="verify-call-1",
        run_id=run_id,
        step_id=step_id,
        status=status,
        output_digest=DIGEST_A,
        output_bytes=80,
        error_code=(
            None if status is ToolResultStatus.SUCCEEDED else "verify_failed"
        ),
        verifier_id=verifier_id,
        postcondition_met=met,
        evidence_digest=DIGEST_B if verifier_id is not None else None,
    )


class TaskModelTests(unittest.TestCase):
    def test_models_are_typed_bounded_and_do_not_repr_sensitive_goal(self):
        task_spec = spec()
        self.assertNotIn(task_spec.goal, repr(task_spec))
        request = approval(
            call(
                CapabilityId.LOCAL_ARTIFACT_WRITE,
                action_digest=DIGEST_C,
            )
        )
        self.assertNotIn(request.reason, repr(request))
        artifact = Artifact(
            artifact_id="artifact-1",
            run_id=task_spec.run_id,
            source_call_id="call-1",
            name="research.csv",
            media_type="text/csv",
            byte_count=128,
            sha256=DIGEST_A,
            verification_result_id="result-1",
            verification_evidence_digest=DIGEST_B,
        )
        self.assertEqual(artifact.sha256, DIGEST_A)
        self.assertTrue(artifact.adopted)

        with self.assertRaisesRegex(ValueError, "Task goal"):
            TaskSpec(
                run_id="task-run-1",
                skill_id="clicky.research",
                skill_version="1.0.0",
                goal="x" * 8_193,
                input_digest=DIGEST_A,
                requested_result="table",
                verifier_step_id="verify",
                verifier_id="verify-v1",
                limits=TaskLimits(
                    runtime_seconds=60,
                    max_tool_calls=2,
                    max_network_requests=0,
                    max_output_bytes=1024,
                ),
            )
        with self.assertRaisesRegex(ValueError, "Artifact digest"):
            Artifact(
                artifact_id="artifact-1",
                run_id="task-run-1",
                source_call_id="call-1",
                name="report.csv",
                media_type="text/csv",
                byte_count=1,
                sha256="not-a-digest",
            )
        with self.assertRaisesRegex(ValueError, "filesystem path"):
            Artifact(
                artifact_id="artifact-1",
                run_id="task-run-1",
                source_call_id="call-1",
                name="../report.csv",
                media_type="text/csv",
                byte_count=1,
                sha256=DIGEST_A,
            )

    def test_new_run_requires_matching_task_agent_grant(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            TaskRun(spec(), grant("another-run"))
        with self.assertRaisesRegex(ValueError, "task-agent run"):
            TaskRun(
                spec(),
                CapabilityGrant(
                    run_id="task-run-1",
                    capabilities=frozenset(
                        {CapabilityId.WEB_SEARCH_BOUNDED}
                    ),
                ),
            )

    def test_happy_path_uses_declared_lifecycle_and_verifier(self):
        task = TaskRun(
            spec(),
            grant(
                "task-run-1",
                CapabilityId.WEB_SEARCH_BOUNDED,
                CapabilityId.LOCAL_ARTIFACT_WRITE,
            ),
        )
        task.start()
        self.assertEqual(task.state, TaskState.RUNNING)

        read_call = call(
            CapabilityId.WEB_SEARCH_BOUNDED,
            call_id="search-call",
        )
        task.authorize_tool_call(read_call)

        write_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            call_id="write-call",
            action_digest=DIGEST_C,
        )
        request = approval(write_call)
        task.request_approval(write_call, request, now=10.0)
        self.assertEqual(task.state, TaskState.WAITING_FOR_APPROVAL)
        task.approve(
            request.approval_id,
            request.action_digest,
            now=20.0,
        )
        self.assertEqual(task.state, TaskState.RUNNING)
        task.authorize_tool_call(write_call)

        result = verification()
        task.complete(result)
        self.assertEqual(task.state, TaskState.COMPLETED)
        self.assertIs(task.verifier_result, result)
        self.assertTrue(task.terminal)

    def test_illegal_state_transitions_fail(self):
        task = TaskRun(spec(), grant())
        with self.assertRaises((AttributeError, TypeError)):
            task.state = TaskState.COMPLETED
        with self.assertRaisesRegex(ValueError, "queued"):
            task.complete(verification())
        task.start()
        with self.assertRaisesRegex(ValueError, "running"):
            task.start()
        task.cancel()
        with self.assertRaisesRegex(ValueError, "Terminal"):
            task.fail("late_failure")

    def test_completion_requires_matching_successful_declared_verifier(self):
        cases = (
            verification(step_id="another-step"),
            verification(verifier_id="another-verifier"),
            verification(met=False),
            verification(status=ToolResultStatus.FAILED),
            verification(run_id="another-run"),
        )
        for result in cases:
            with self.subTest(result=result):
                task = TaskRun(spec(), grant())
                task.start()
                with self.assertRaisesRegex(
                    ValueError,
                    "declared verifier",
                ):
                    task.complete(result)
                self.assertEqual(task.state, TaskState.RUNNING)

    def test_external_write_cannot_skip_waiting_for_approval(self):
        write_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            action_digest=DIGEST_C,
        )
        task = TaskRun(
            spec(),
            grant("task-run-1", CapabilityId.LOCAL_ARTIFACT_WRITE),
        )
        task.start()
        with self.assertRaisesRegex(
            ValueError,
            "waiting_for_approval",
        ):
            task.authorize_tool_call(write_call)

        request = approval(write_call)
        task.request_approval(write_call, request, now=10.0)
        with self.assertRaisesRegex(ValueError, "waiting_for_approval"):
            task.authorize_tool_call(write_call)

    def test_approval_is_exact_expiring_and_one_use(self):
        write_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            action_digest=DIGEST_C,
        )
        task = TaskRun(
            spec(),
            grant("task-run-1", CapabilityId.LOCAL_ARTIFACT_WRITE),
        )
        task.start()
        request = approval(write_call)
        task.request_approval(write_call, request, now=10.0)
        with self.assertRaisesRegex(ValueError, "match or has expired"):
            task.approve(
                "another-approval",
                request.action_digest,
                now=20.0,
            )
        task.approve(
            request.approval_id,
            request.action_digest,
            now=20.0,
        )
        task.authorize_tool_call(write_call)
        with self.assertRaisesRegex(
            ValueError,
            "waiting_for_approval",
        ):
            task.authorize_tool_call(write_call)

        expired = TaskRun(
            spec("task-run-2"),
            grant(
                "task-run-2",
                CapabilityId.LOCAL_ARTIFACT_WRITE,
            ),
        )
        expired.start()
        expired_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            run_id="task-run-2",
            action_digest=DIGEST_C,
        )
        expired_request = ApprovalRequest(
            approval_id="approval-expiring",
            run_id="task-run-2",
            call_id=expired_call.call_id,
            capability=expired_call.capability,
            action_digest=DIGEST_C,
            reason="Review this action.",
            preview_digests=(DIGEST_A,),
            expires_at=50.0,
        )
        expired.request_approval(
            expired_call,
            expired_request,
            now=10.0,
        )
        with self.assertRaisesRegex(ValueError, "expired"):
            expired.approve(
                expired_request.approval_id,
                expired_request.action_digest,
                now=51.0,
            )

    def test_completion_rejects_unused_action_approval(self):
        write_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            action_digest=DIGEST_C,
        )
        task = TaskRun(
            spec(),
            grant("task-run-1", CapabilityId.LOCAL_ARTIFACT_WRITE),
        )
        task.start()
        request = approval(write_call)
        task.request_approval(write_call, request, now=10.0)
        task.approve(
            request.approval_id,
            request.action_digest,
            now=20.0,
        )
        with self.assertRaisesRegex(ValueError, "unused"):
            task.complete(verification())

    def test_approval_and_call_require_matching_grant_and_digest(self):
        write_call = call(
            CapabilityId.LOCAL_ARTIFACT_WRITE,
            action_digest=DIGEST_C,
        )
        without_write = TaskRun(spec(), grant())
        without_write.start()
        with self.assertRaisesRegex(ValueError, "does not allow"):
            without_write.request_approval(
                write_call,
                approval(write_call),
                now=10.0,
            )

        with_write = TaskRun(
            spec(),
            grant("task-run-1", CapabilityId.LOCAL_ARTIFACT_WRITE),
        )
        with_write.start()
        wrong = ApprovalRequest(
            approval_id="approval-2",
            run_id=write_call.run_id,
            call_id=write_call.call_id,
            capability=write_call.capability,
            action_digest="d" * 64,
            reason="Wrong action.",
            preview_digests=(DIGEST_A,),
            expires_at=100.0,
        )
        with self.assertRaisesRegex(ValueError, "exact tool call"):
            with_write.request_approval(write_call, wrong, now=10.0)

    def test_tool_result_verifier_evidence_is_all_or_nothing(self):
        with self.assertRaisesRegex(ValueError, "must be complete"):
            ToolResult(
                result_id="result-1",
                call_id="call-1",
                run_id="task-run-1",
                step_id="verify",
                status=ToolResultStatus.SUCCEEDED,
                output_digest=DIGEST_A,
                output_bytes=1,
                verifier_id="verify-v1",
            )
        with self.assertRaisesRegex(
            ValueError,
            "Successful tool results cannot have errors",
        ):
            ToolResult(
                result_id="result-1",
                call_id="call-1",
                run_id="task-run-1",
                step_id="step-1",
                status=ToolResultStatus.SUCCEEDED,
                output_digest=DIGEST_A,
                output_bytes=1,
                error_code="unexpected",
            )

        partial = ToolResult(
            result_id="partial-result",
            call_id="partial-call",
            run_id="task-run-1",
            step_id="write-output",
            status=ToolResultStatus.PARTIAL,
            output_digest=DIGEST_A,
            output_bytes=40,
            error_code="partial_output",
        )
        self.assertEqual(partial.status, ToolResultStatus.PARTIAL)
        self.assertFalse(partial.is_successful_verification)


if __name__ == "__main__":
    unittest.main()
