"""End-to-end Task Center and adversarial desktop-action lifecycle tests."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from automation.action_models import (
    DesktopActionEvidence,
    DesktopActionReceipt,
    DesktopActionStatus,
    InvokePostcondition,
)
from automation.action_protocol import (
    decode_worker_command,
    encode_worker_receipt,
)
from automation.models import (
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)
from automation.review import DesktopTargetReviewController
from automation.stop import AutomationStopController
from automation.targeting import DesktopObservation, DesktopTargetGuard
from automation.task_center import DesktopAutomationTaskController
from capability_registry import CapabilityGrant, CapabilityId
from tasks.models import TaskLimits, TaskRun, TaskSpec, TaskState
from tasks.store import TaskStore
from tasks.task_center import (
    TaskActionStatus,
    TaskCenterActionRegistry,
    TaskDisplayContent,
)


APP_DIGEST = hashlib.sha256(b"synthetic-editor").hexdigest()


def target(**overrides: object) -> DesktopTarget:
    values: dict[str, object] = {
        "process_id": 42,
        "process_start_time_ns": 123_456,
        "application_name": "Synthetic editor",
        "application_identity": APP_DIGEST,
        "top_level_hwnd": 100,
        "foreground_hwnd": 100,
        "runtime_id": (42, 7, 3),
        "control_type": "ButtonControl",
        "framework_id": "Win32",
        "automation_id": "save",
        "control_name": "Save",
        "bounds": DesktopBounds(20, 30, 120, 40),
        "supported_patterns": frozenset({AutomationPattern.INVOKE}),
        "enabled": True,
        "offscreen": False,
        "control_element": True,
        "password": False,
        "protected": False,
        "clicky_process_id": 99,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
    }
    values.update(overrides)
    return DesktopTarget(**values)  # type: ignore[arg-type]


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class Inspector:
    def __init__(self) -> None:
        self.current: DesktopTarget | Exception = target()

    def observe(self) -> DesktopObservation:
        if isinstance(self.current, Exception):
            raise self.current
        return DesktopObservation(
            self.current,
            (self.current.control_name, self.current.application_name),
        )


class Highlighter:
    def __init__(self) -> None:
        self.active: set[str] = set()

    def show(self, request) -> None:
        self.active.add(request.review_id)

    def clear(self, review_id: str) -> None:
        self.active.discard(review_id)

    def is_active(self, review_id: str) -> bool:
        return review_id in self.active


class WorkerHandle:
    def __init__(self, *, transport_failure: bool = False) -> None:
        self.transport_failure = transport_failure
        self.frames: list[bytes] = []
        self.cancelled = 0
        self.closed = 0
        self._request_sent = False

    @property
    def request_sent(self) -> bool:
        return self._request_sent

    def exchange(self, frame: bytes) -> bytes:
        self.frames.append(frame)
        self._request_sent = True
        if self.transport_failure:
            raise RuntimeError("synthetic post-send transport failure")
        command = decode_worker_command(frame)
        receipt = DesktopActionReceipt(
            status=DesktopActionStatus.VERIFIED_SUCCEEDED,
            result_code="uia_postcondition_verified",
            action_started=True,
            target_identity_digest=command.target.identity_digest,
            evidence=DesktopActionEvidence(
                "invoke.target_disabled",
                "true",
                "false",
            ),
        )
        return encode_worker_receipt(
            nonce=command.nonce,
            authentication_key=command.authentication_key,
            receipt=receipt,
        )

    def cancel(self) -> None:
        self.cancelled += 1

    def close(self) -> None:
        self.closed += 1


class Launcher:
    def __init__(self, handle: WorkerHandle | None = None) -> None:
        self.handle = handle or WorkerHandle()
        self.calls = 0

    def start(self) -> WorkerHandle:
        self.calls += 1
        return self.handle


def task_run(
    run_id: str,
    *,
    capabilities: frozenset[CapabilityId] | None = None,
) -> TaskRun:
    return TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id="clicky.desktop",
            skill_version="1.0.0",
            goal="Perform one exact reviewed desktop action.",
            input_digest="a" * 64,
            requested_result="A verified desktop action receipt.",
            verifier_step_id="verify-action",
            verifier_id="desktop-postcondition-v1",
            limits=TaskLimits(
                runtime_seconds=30,
                max_tool_calls=2,
                max_network_requests=0,
                max_output_bytes=4_096,
            ),
        ),
        CapabilityGrant(
            run_id=run_id,
            capabilities=capabilities
            or frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.DESKTOP_UIA_ACTION,
                }
            ),
        ),
    )


class DesktopAutomationTaskCenterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.clock = Clock()
        self.store = TaskStore(
            Path(self.temporary.name) / "tasks.sqlite3",
            _clock=self.clock,
        )
        self.inspector = Inspector()
        self.highlighter = Highlighter()
        self.stops = AutomationStopController()
        self.actions = TaskCenterActionRegistry()
        self.launcher = Launcher()
        self.run = task_run("desktop-task")
        self.store.create_task(self.run)
        self.run.start()
        self.store.sync_run(self.run)
        self.lease = self.stops.begin(self.run.run_id)
        self.reviews = DesktopTargetReviewController(
            DesktopTargetGuard(self.inspector),
            self.highlighter,
            self.stops,
            clock=self.clock,
        )
        self.controller = DesktopAutomationTaskController(
            self.run,
            self.store,
            self.lease,
            self.reviews,
            self.stops,
            self.actions,
            TaskDisplayContent(
                run_id=self.run.run_id,
                goal=self.run.spec.goal,
                requested_result=self.run.spec.requested_result,
            ),
            launcher=self.launcher,
            clock=self.clock,
        )

    def prepare(self) -> None:
        self.assertTrue(
            self.controller.prepare_action(
                call_id="call-invoke",
                action=DesktopActionKind.INVOKE,
                approval_id="approval-invoke",
                reason="Invoke this exact highlighted control.",
                ttl_seconds=10,
                invoke_postcondition=(
                    InvokePostcondition.TARGET_DISABLED
                ),
            )
        )

    def approve(self) -> None:
        prepared = self.controller.prepared
        assert prepared is not None
        request = prepared.approval.request
        self.assertTrue(
            self.actions.approve(
                self.run.run_id,
                request.approval_id,
                request.action_digest,
            )
        )

    def test_verified_action_closes_task_from_worker_evidence(self):
        self.prepare()
        pending = self.actions.desktop_action(self.run.run_id)
        assert pending is not None
        self.assertEqual(
            pending.status,
            TaskActionStatus.AWAITING_APPROVAL,
        )
        self.assertEqual(pending.target_label, "invoke: Synthetic editor — Save")
        self.assertEqual(
            pending.capability,
            CapabilityId.DESKTOP_UIA_ACTION,
        )

        self.approve()
        result = self.controller.execute_approved(now=1_001.0)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result.is_successful_verification)
        self.assertEqual(self.run.state, TaskState.COMPLETED)
        self.assertEqual(self.launcher.calls, 1)
        final = self.actions.desktop_action(self.run.run_id)
        assert final is not None
        self.assertEqual(
            final.status,
            TaskActionStatus.VERIFIED_SUCCEEDED,
        )
        self.assertEqual(final.observed_property, "invoke.target_disabled")
        self.assertEqual(
            final.verifier_evidence_digest,
            result.evidence_digest,
        )
        self.assertFalse(self.actions.controllable(self.run.run_id))
        self.assertIsNotNone(self.actions.display_content(self.run.run_id))
        record = self.store.get_task(self.run.run_id)
        assert record is not None
        self.assertEqual(record.state, TaskState.COMPLETED)
        self.assertEqual(
            record.verifier_evidence_digest,
            result.evidence_digest,
        )

    def test_non_desktop_permissions_cannot_substitute_for_authority(self):
        substitutions = (
            CapabilityId.TASK_AGENT_RUN,
            CapabilityId.DICTATION_INSERT_TEXT,
            CapabilityId.COMPOSE_SCREEN_CONTEXT,
            CapabilityId.STYLE_PROFILE_USE,
            CapabilityId.WORKSPACE_COMMAND,
        )
        for index, substituted in enumerate(substitutions):
            with self.subTest(capability=substituted.value):
                run_id = f"substitute-{index}"
                granted = {CapabilityId.TASK_AGENT_RUN}
                granted.add(substituted)
                run = task_run(
                    run_id,
                    capabilities=frozenset(granted),
                )
                store = TaskStore(
                    Path(self.temporary.name)
                    / f"substitute-{index}.sqlite3",
                    _clock=self.clock,
                )
                store.create_task(run)
                run.start()
                store.sync_run(run)
                stops = AutomationStopController()
                lease = stops.begin(run_id)
                reviews = DesktopTargetReviewController(
                    DesktopTargetGuard(Inspector()),
                    Highlighter(),
                    stops,
                    clock=self.clock,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "lacks desktop UI Automation authority",
                ):
                    DesktopAutomationTaskController(
                        run,
                        store,
                        lease,
                        reviews,
                        stops,
                        TaskCenterActionRegistry(),
                        TaskDisplayContent(
                            run_id=run_id,
                            goal=run.spec.goal,
                            requested_result=run.spec.requested_result,
                        ),
                        launcher=Launcher(),
                        clock=self.clock,
                    )

    def test_target_swap_focus_theft_disappearance_and_policy_changes_block(self):
        cases: tuple[tuple[str, DesktopTarget | Exception], ...] = (
            ("target_swap", target(runtime_id=(42, 7, 4))),
            ("focus_theft", target(foreground_hwnd=101)),
            ("disappeared", RuntimeError("control disappeared")),
            ("misleading_label", target(control_name="Place order")),
            ("elevation", target(target_integrity=0x3000)),
            ("secure_surface", target(desktop_name="Winlogon")),
        )
        for name, changed in cases:
            with self.subTest(case=name):
                self.setUp()
                self.prepare()
                self.approve()
                self.inspector.current = changed

                result = self.controller.execute_approved(now=1_001.0)

                self.assertIsNotNone(result)
                assert result is not None
                self.assertFalse(result.is_successful_verification)
                self.assertEqual(self.run.state, TaskState.FAILED)
                self.assertEqual(self.launcher.calls, 0)
                final = self.actions.desktop_action(self.run.run_id)
                assert final is not None
                self.assertEqual(
                    final.status,
                    TaskActionStatus.FAILED_BEFORE_ACTION,
                )
                self.assertNotEqual(
                    final.result_code,
                    "uia_postcondition_verified",
                )

    def test_stop_suppresses_an_approved_but_queued_action(self):
        self.prepare()
        self.approve()

        self.assertTrue(self.actions.cancel(self.run.run_id))
        result = self.controller.execute_approved(now=1_001.0)

        self.assertIsNone(result)
        self.assertEqual(self.launcher.calls, 0)
        self.assertEqual(self.run.state, TaskState.CANCELLED)
        final = self.actions.desktop_action(self.run.run_id)
        assert final is not None
        self.assertEqual(
            final.status,
            TaskActionStatus.CANCELLED_BEFORE_ACTION,
        )

    def test_pending_approval_timeout_never_launches(self):
        self.prepare()
        self.clock.value = 1_011.0

        self.assertTrue(self.controller.expire_pending())
        self.assertIsNone(self.controller.execute_approved())

        self.assertEqual(self.launcher.calls, 0)
        self.assertEqual(self.run.state, TaskState.EXPIRED)
        final = self.actions.desktop_action(self.run.run_id)
        assert final is not None
        self.assertEqual(
            final.status,
            TaskActionStatus.FAILED_BEFORE_ACTION,
        )
        self.assertEqual(final.result_code, "approval_expired")

    def test_post_send_transport_failure_is_unknown_not_success(self):
        self.launcher.handle = WorkerHandle(transport_failure=True)
        self.prepare()
        self.approve()

        result = self.controller.execute_approved(now=1_001.0)

        self.assertIsNotNone(result)
        assert result is not None
        self.assertFalse(result.is_successful_verification)
        self.assertEqual(self.run.state, TaskState.FAILED)
        final = self.actions.desktop_action(self.run.run_id)
        assert final is not None
        self.assertEqual(
            final.status,
            TaskActionStatus.OUTCOME_UNKNOWN,
        )
        self.assertEqual(final.result_code, "uia_worker_outcome_unknown")
        self.assertEqual(self.launcher.calls, 1)
        self.assertEqual(len(self.launcher.handle.frames), 1)

    def test_rejection_terminates_without_execution(self):
        self.prepare()
        prepared = self.controller.prepared
        assert prepared is not None
        request = prepared.approval.request

        self.assertTrue(
            self.actions.reject(
                self.run.run_id,
                request.approval_id,
                request.action_digest,
            )
        )

        self.assertEqual(self.run.state, TaskState.FAILED)
        self.assertEqual(self.run.result_code, "approval_rejected")
        self.assertEqual(self.launcher.calls, 0)
        final = self.actions.desktop_action(self.run.run_id)
        assert final is not None
        self.assertEqual(final.status, TaskActionStatus.REJECTED)


if __name__ == "__main__":
    unittest.main()
