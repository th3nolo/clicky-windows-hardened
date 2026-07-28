from __future__ import annotations

import hashlib
import unittest

from automation.action_approval import build_desktop_action_approval
from automation.action_broker import DesktopActionBroker
from automation.action_models import (
    DesktopActionEvidence,
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
    InvokePostcondition,
)
from automation.action_process import UiaWorkerError
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
from automation.targeting import (
    DesktopObservation,
    DesktopTargetGuard,
)
from capability_registry import CapabilityGrant, CapabilityId
from tasks.approvals import ApprovalTarget, build_approval_payload
from tasks.models import (
    TaskLimits,
    TaskRun,
    TaskSpec,
    ToolCall,
)


APP_DIGEST = hashlib.sha256(b"synthetic-app").hexdigest()


def target(**overrides) -> DesktopTarget:
    values = {
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
    return DesktopTarget(**values)


class Inspector:
    def __init__(self) -> None:
        self.current = target()

    def observe(self):
        return DesktopObservation(
            self.current,
            (self.current.control_name, self.current.application_name),
        )


class Highlighter:
    def __init__(self) -> None:
        self.active = set()
        self.cleared = []

    def show(self, request) -> None:
        self.active.add(request.review_id)

    def clear(self, review_id: str) -> None:
        self.active.discard(review_id)
        self.cleared.append(review_id)

    def is_active(self, review_id: str) -> bool:
        return review_id in self.active


class Clock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self):
        return self.value


class Handle:
    def __init__(self, mode: str = "success", callback=None) -> None:
        self.mode = mode
        self.callback = callback
        self.frames = []
        self.cancelled = 0
        self.closed = 0
        self._request_sent = False

    @property
    def request_sent(self) -> bool:
        return self._request_sent

    def exchange(self, frame: bytes) -> bytes:
        self.frames.append(frame)
        self._request_sent = True
        command = decode_worker_command(frame)
        if self.callback is not None:
            self.callback()
        if self.mode == "transport":
            raise UiaWorkerError("synthetic transport failure")
        exact = DesktopActionReceipt(
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
        response = encode_worker_receipt(
            nonce=command.nonce,
            authentication_key=command.authentication_key,
            receipt=exact,
        )
        if self.mode == "tamper":
            return response.replace(
                b"uia_postcondition_verified",
                b"forged_result____________",
            )
        return response

    def cancel(self) -> None:
        self.cancelled += 1

    def close(self) -> None:
        self.closed += 1


class Launcher:
    def __init__(self, handle: Handle | None = None, *, fail=False) -> None:
        self.handle = handle or Handle()
        self.fail = fail
        self.calls = 0

    def start(self):
        self.calls += 1
        if self.fail:
            raise UiaWorkerError("synthetic launch failure")
        return self.handle


def task_run(run_id: str = "desktop-run") -> TaskRun:
    spec = TaskSpec(
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
    )
    task = TaskRun(
        spec,
        CapabilityGrant(
            run_id=run_id,
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.DESKTOP_UIA_ACTION,
                }
            ),
        ),
    )
    task.start()
    return task


class DesktopActionBrokerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        self.inspector = Inspector()
        self.highlighter = Highlighter()
        self.stops = AutomationStopController()
        self.run = self.stops.begin("desktop-run")
        self.reviews = DesktopTargetReviewController(
            DesktopTargetGuard(self.inspector),
            self.highlighter,
            self.stops,
            clock=self.clock,
        )
        reviewed = self.reviews.preview(
            self.run,
            action=DesktopActionKind.INVOKE,
            ttl_seconds=10,
        )
        assert reviewed.lease is not None
        self.review = reviewed.lease
        self.request = DesktopActionRequest(
            run_id=self.run.run_id,
            call_id="call-invoke",
            review_id=self.review.request.review_id,
            target_identity_digest=(
                self.review.request.target_identity_digest
            ),
            target_review_digest=self.review.request.target_review_digest,
            action=DesktopActionKind.INVOKE,
            invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
        )
        self.call = ToolCall(
            call_id=self.request.call_id,
            run_id=self.request.run_id,
            step_id="invoke-reviewed-control",
            tool_name=self.request.tool_name,
            capability=CapabilityId.DESKTOP_UIA_ACTION,
            arguments_digest=self.request.arguments_digest,
            action_digest=self.request.action_digest,
        )
        self.approval = build_desktop_action_approval(
            self.call,
            self.request,
            self.review,
            approval_id="approval-invoke",
            reason="Invoke this exact highlighted control.",
            expires_at=1_009.0,
        )
        self.task = task_run()
        self.task.request_approval(
            self.call,
            self.approval.request,
            now=1_000.0,
        )
        self.task.approve(
            self.approval.request.approval_id,
            self.approval.request.action_digest,
            now=1_001.0,
        )

    def broker(self, launcher: Launcher) -> DesktopActionBroker:
        return DesktopActionBroker(
            self.task,
            self.run,
            self.reviews,
            self.stops,
            launcher=launcher,
        )

    def execute(self, launcher: Launcher):
        return self.broker(launcher).execute(
            self.call,
            self.request,
            self.review,
            self.approval,
            now=1_001.0,
        )

    def test_exact_approval_executes_once_and_clears_review(self):
        launcher = Launcher()
        receipt = self.execute(launcher)
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.VERIFIED_SUCCEEDED,
        )
        self.assertEqual(launcher.calls, 1)
        self.assertEqual(len(launcher.handle.frames), 1)
        self.assertEqual(launcher.handle.closed, 1)
        self.assertNotIn(
            self.review.request.review_id,
            self.highlighter.active,
        )

    def test_changed_target_fails_before_worker_and_consumes_no_side_effect(self):
        self.inspector.current = target(runtime_id=(42, 7, 4))
        launcher = Launcher()
        receipt = self.execute(launcher)
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
        )
        self.assertFalse(receipt.action_started)
        self.assertEqual(launcher.calls, 0)
        self.assertIn(
            self.review.request.review_id,
            self.highlighter.cleared,
        )

    def test_launch_failure_is_pre_action_and_clears_review(self):
        launcher = Launcher(fail=True)
        receipt = self.execute(launcher)
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
        )
        self.assertEqual(receipt.result_code, "uia_worker_launch_failed")
        self.assertIn(
            self.review.request.review_id,
            self.highlighter.cleared,
        )

    def test_transport_or_authenticated_response_failure_is_unknown(self):
        for mode in ("transport", "tamper"):
            with self.subTest(mode=mode):
                self.setUp()
                launcher = Launcher(Handle(mode))
                receipt = self.execute(launcher)
                self.assertEqual(
                    receipt.status,
                    DesktopActionStatus.OUTCOME_UNKNOWN,
                )
                self.assertTrue(receipt.action_started)
                self.assertEqual(launcher.handle.closed, 1)

    def test_stop_during_exchange_cancels_worker_and_never_retries(self):
        handle = Handle("transport", callback=self.stops.stop)
        launcher = Launcher(handle)
        receipt = self.execute(launcher)
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.OUTCOME_UNKNOWN,
        )
        self.assertEqual(handle.cancelled, 1)
        self.assertEqual(len(handle.frames), 1)
        self.assertEqual(launcher.calls, 1)

    def test_stop_before_execution_is_cancelled_without_worker(self):
        self.stops.stop()
        launcher = Launcher()
        receipt = self.execute(launcher)
        self.assertEqual(
            receipt.status,
            DesktopActionStatus.CANCELLED_BEFORE_ACTION,
        )
        self.assertFalse(receipt.action_started)
        self.assertEqual(launcher.calls, 0)

    def test_wrong_exact_approval_never_reaches_launcher(self):
        launcher = Launcher()
        exact = build_desktop_action_approval(
            self.call,
            self.request,
            self.review,
            approval_id="approval-wrong",
            reason="A separately reviewed approval.",
            expires_at=1_009.0,
        )
        wrong_target = ApprovalTarget(
            kind=exact.target.kind,
            reference=exact.target.reference,
            label=exact.target.label,
            target_digest="f" * 64,
        )
        wrong = build_approval_payload(
            self.call,
            approval_id="approval-wrong",
            reason="A separately reviewed approval.",
            expires_at=1_009.0,
            target=wrong_target,
            preview=exact.preview,
        )
        with self.assertRaisesRegex(ValueError, "exact review"):
            self.broker(launcher).execute(
                self.call,
                self.request,
                self.review,
                wrong,
                now=1_001.0,
            )
        self.assertEqual(launcher.calls, 0)

    def test_one_use_call_is_not_replayed(self):
        launcher = Launcher()
        broker = self.broker(launcher)
        first = broker.execute(
            self.call,
            self.request,
            self.review,
            self.approval,
            now=1_001.0,
        )
        second = broker.execute(
            self.call,
            self.request,
            self.review,
            self.approval,
            now=1_001.0,
        )
        self.assertTrue(first.verified)
        self.assertEqual(
            second.status,
            DesktopActionStatus.FAILED_BEFORE_ACTION,
        )
        self.assertEqual(launcher.calls, 1)

    def test_long_call_id_still_uses_bounded_cancellation_identity(self):
        long_id = "c" * 128
        exact = DesktopActionRequest(
            run_id=self.request.run_id,
            call_id=long_id,
            review_id=self.request.review_id,
            target_identity_digest=self.request.target_identity_digest,
            target_review_digest=self.request.target_review_digest,
            action=DesktopActionKind.INVOKE,
            invoke_postcondition=InvokePostcondition.TARGET_DISABLED,
        )
        call = ToolCall(
            call_id=long_id,
            run_id=exact.run_id,
            step_id="invoke-reviewed-control",
            tool_name=exact.tool_name,
            capability=CapabilityId.DESKTOP_UIA_ACTION,
            arguments_digest=exact.arguments_digest,
            action_digest=exact.action_digest,
        )
        approval = build_desktop_action_approval(
            call,
            exact,
            self.review,
            approval_id="approval-long-call",
            reason="Invoke this exact highlighted control.",
            expires_at=1_009.0,
        )
        task = task_run()
        task.request_approval(call, approval.request, now=1_000.0)
        task.approve(
            approval.request.approval_id,
            approval.request.action_digest,
            now=1_001.0,
        )
        launcher = Launcher()
        receipt = DesktopActionBroker(
            task,
            self.run,
            self.reviews,
            self.stops,
            launcher=launcher,
        ).execute(
            call,
            exact,
            self.review,
            approval,
            now=1_001.0,
        )
        self.assertTrue(receipt.verified)

    def test_set_value_preview_is_exact_but_sensitive_reprs_are_redacted(self):
        self.inspector.current = target(
            control_type="EditControl",
            automation_id="editor",
            control_name="Editor",
            supported_patterns=frozenset({AutomationPattern.VALUE}),
        )
        reviewed = self.reviews.preview(
            self.run,
            action=DesktopActionKind.SET_VALUE,
            ttl_seconds=10,
        )
        self.assertTrue(reviewed.ready)
        assert reviewed.lease is not None
        raw = "private content"
        exact = DesktopActionRequest(
            run_id="desktop-run",
            call_id="call-private",
            review_id=reviewed.lease.request.review_id,
            target_identity_digest=(
                reviewed.lease.request.target_identity_digest
            ),
            target_review_digest=(
                reviewed.lease.request.target_review_digest
            ),
            action=DesktopActionKind.SET_VALUE,
            value=raw,
        )
        call = ToolCall(
            call_id=exact.call_id,
            run_id=exact.run_id,
            step_id="set-reviewed-value",
            tool_name=exact.tool_name,
            capability=CapabilityId.DESKTOP_UIA_ACTION,
            arguments_digest=exact.arguments_digest,
            action_digest=exact.action_digest,
        )
        approval = build_desktop_action_approval(
            call,
            exact,
            reviewed.lease,
            approval_id="approval-private",
            reason="Set this exact reviewed value.",
            expires_at=1_009.0,
        )
        self.assertIn(raw, approval.preview.excerpt)
        self.assertNotIn(raw, repr(exact))
        self.assertNotIn(raw, repr(approval.preview))


if __name__ == "__main__":
    unittest.main()
