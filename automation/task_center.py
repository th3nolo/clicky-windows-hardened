"""Bind one reviewed desktop action to a truthful Task Center lifecycle."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field, replace

from automation.action_approval import build_desktop_action_approval
from automation.action_broker import DesktopActionBroker
from automation.action_models import (
    DesktopActionReceipt,
    DesktopActionRequest,
    DesktopActionStatus,
    InvokePostcondition,
    ScrollAmount,
    ToggleGoal,
)
from automation.action_process import UiaWorkerLauncherProtocol
from automation.models import DesktopActionKind
from automation.review import (
    DesktopReviewLease,
    DesktopTargetReviewController,
)
from automation.stop import AutomationRunLease, AutomationStopController
from capability_registry import CapabilityId
from tasks.approvals import ApprovalPayload
from tasks.models import (
    TaskRun,
    TaskState,
    ToolCall,
    ToolResult,
    ToolResultStatus,
)
from tasks.store import TaskStore
from tasks.task_center import (
    ActiveTaskHandle,
    DesktopActionPresentation,
    TaskActionStatus,
    TaskCenterActionRegistry,
    TaskDisplayContent,
)


@dataclass(frozen=True, slots=True)
class PreparedDesktopAction:
    """Exact reviewed objects retained only for this live process."""

    call: ToolCall
    request: DesktopActionRequest = field(repr=False)
    review: DesktopReviewLease = field(repr=False)
    approval: ApprovalPayload = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.call, ToolCall):
            raise TypeError("Prepared desktop tool call is invalid")
        if not isinstance(self.request, DesktopActionRequest):
            raise TypeError("Prepared desktop request is invalid")
        if not isinstance(self.review, DesktopReviewLease):
            raise TypeError("Prepared desktop review is invalid")
        if not isinstance(self.approval, ApprovalPayload):
            raise TypeError("Prepared desktop approval is invalid")
        if (
            self.call.run_id != self.request.run_id
            or self.call.call_id != self.request.call_id
            or self.approval.request.call_id != self.call.call_id
        ):
            raise ValueError("Prepared desktop identities do not match")


class DesktopAutomationTaskController:
    """Own approval, execution, evidence, stop, and terminal task state."""

    def __init__(
        self,
        task_run: TaskRun,
        task_store: TaskStore,
        automation_run: AutomationRunLease,
        reviews: DesktopTargetReviewController,
        stops: AutomationStopController,
        actions: TaskCenterActionRegistry,
        content: TaskDisplayContent,
        *,
        launcher: UiaWorkerLauncherProtocol | None = None,
        clock=time.time,
    ) -> None:
        if not isinstance(task_run, TaskRun):
            raise TypeError("Desktop Task Center requires a TaskRun")
        if not isinstance(task_store, TaskStore):
            raise TypeError("Desktop Task Center requires a TaskStore")
        if not isinstance(automation_run, AutomationRunLease):
            raise TypeError("Desktop automation run lease is invalid")
        if not isinstance(reviews, DesktopTargetReviewController):
            raise TypeError("Desktop review controller is invalid")
        if not isinstance(stops, AutomationStopController):
            raise TypeError("Desktop stop controller is invalid")
        if not isinstance(actions, TaskCenterActionRegistry):
            raise TypeError("Task Center action registry is invalid")
        if not isinstance(content, TaskDisplayContent):
            raise TypeError("Task Center display content is invalid")
        if not callable(clock):
            raise TypeError("Desktop Task Center clock is invalid")
        if (
            task_run.run_id != automation_run.run_id
            or task_run.run_id != content.run_id
        ):
            raise ValueError("Desktop Task Center run identities differ")
        if task_run.state is not TaskState.RUNNING:
            raise ValueError("Desktop task must already be running")
        if not task_run.grant.allows(CapabilityId.DESKTOP_UIA_ACTION):
            raise ValueError(
                "Desktop task lacks desktop UI Automation authority"
            )
        record = task_store.get_task(task_run.run_id)
        if (
            record is None
            or record.state is not TaskState.RUNNING
            or not record.grant.allows(CapabilityId.DESKTOP_UIA_ACTION)
        ):
            raise ValueError(
                "Persisted task lacks running desktop authority"
            )
        self._task_run = task_run
        self._task_store = task_store
        self._automation_run = automation_run
        self._reviews = reviews
        self._stops = stops
        self._actions = actions
        self._content = content
        self._clock = clock
        self._broker = DesktopActionBroker(
            task_run,
            automation_run,
            reviews,
            stops,
            launcher=launcher,
        )
        self._lock = threading.RLock()
        self._prepared: PreparedDesktopAction | None = None
        self._approved = False
        self._executing = False
        self._executed = False
        actions.register(
            ActiveTaskHandle(
                content=content,
                cancel_callback=self.cancel,
            )
        )

    @property
    def prepared(self) -> PreparedDesktopAction | None:
        with self._lock:
            return self._prepared

    def prepare_action(
        self,
        *,
        call_id: str,
        action: DesktopActionKind,
        approval_id: str,
        reason: str,
        ttl_seconds: float = 10.0,
        invoke_postcondition: InvokePostcondition | None = None,
        toggle_goal: ToggleGoal | None = None,
        horizontal_scroll: ScrollAmount | None = None,
        vertical_scroll: ScrollAmount | None = None,
        value: str | None = None,
    ) -> bool:
        """Capture and expose one exact action without granting authority."""

        with self._lock:
            if (
                self._prepared is not None
                or self._executed
                or self._task_run.state is not TaskState.RUNNING
                or not self._stops.is_active(self._automation_run)
            ):
                return False
        reviewed = self._reviews.preview(
            self._automation_run,
            action=action,
            ttl_seconds=ttl_seconds,
        )
        if not reviewed.ready or reviewed.lease is None:
            result_code = "desktop_review_" + reviewed.status.value
            self._finish_without_action(result_code)
            return False
        review = reviewed.lease
        request = DesktopActionRequest(
            run_id=self._task_run.run_id,
            call_id=call_id,
            review_id=review.request.review_id,
            target_identity_digest=review.request.target_identity_digest,
            target_review_digest=review.request.target_review_digest,
            action=action,
            invoke_postcondition=invoke_postcondition,
            toggle_goal=toggle_goal,
            horizontal_scroll=horizontal_scroll,
            vertical_scroll=vertical_scroll,
            value=value,
        )
        call = ToolCall(
            call_id=request.call_id,
            run_id=request.run_id,
            step_id=self._task_run.spec.verifier_step_id,
            tool_name=request.tool_name,
            capability=CapabilityId.DESKTOP_UIA_ACTION,
            arguments_digest=request.arguments_digest,
            action_digest=request.action_digest,
        )
        now = float(self._clock())
        approval = build_desktop_action_approval(
            call,
            request,
            review,
            approval_id=approval_id,
            reason=reason,
            expires_at=min(
                review.request.expires_at,
                now + float(ttl_seconds),
            ),
        )
        prepared = PreparedDesktopAction(
            call=call,
            request=request,
            review=review,
            approval=approval,
        )
        presentation = _pending_presentation(prepared)
        try:
            self._task_store.record_tool_call(call)
            self._task_run.request_approval(
                call,
                approval.request,
                now=now,
            )
            self._task_store.sync_run(self._task_run)
            with self._lock:
                self._prepared = prepared
            self._actions.replace(
                ActiveTaskHandle(
                    content=self._content,
                    cancel_callback=self.cancel,
                    approve_callback=self._approve,
                    reject_callback=self._reject,
                    approval=approval,
                )
            )
            self._actions.update_desktop_action(presentation)
        except Exception:
            self._reviews.clear(review)
            self._stops.stop()
            if not self._task_run.terminal:
                self._task_run.fail("desktop_task_integration_failed")
                _best_effort_sync(self._task_store, self._task_run)
            self._actions.unregister(self._task_run.run_id)
            raise
        return True

    def expire_pending(self, *, now: float | None = None) -> bool:
        """Expire an unapproved action and preserve an explicit failure."""

        when = float(self._clock()) if now is None else float(now)
        with self._lock:
            prepared = self._prepared
            if (
                prepared is None
                or self._approved
                or self._task_run.state
                is not TaskState.WAITING_FOR_APPROVAL
                or when <= prepared.approval.request.expires_at
            ):
                return False
            self._stops.stop()
            self._reviews.clear(prepared.review)
            self._task_run.expire_approval(now=when)
            self._task_store.sync_run(self._task_run)
            terminal = _terminal_presentation(
                prepared,
                status=TaskActionStatus.FAILED_BEFORE_ACTION,
                result_code="approval_expired",
                evidence_digest=_event_digest(
                    {
                        "action_digest": prepared.call.action_digest,
                        "result_code": "approval_expired",
                    }
                ),
            )
            self._actions.update_desktop_action(terminal, finish=True)
            return True

    def execute_approved(self, *, now: float | None = None) -> ToolResult | None:
        """Execute exactly once after approval and close from real evidence."""

        when = float(self._clock()) if now is None else float(now)
        with self._lock:
            prepared = self._prepared
            if (
                prepared is None
                or not self._approved
                or self._executing
                or self._executed
                or self._task_run.state is not TaskState.RUNNING
            ):
                return None
            if not self._stops.is_active(self._automation_run):
                self._executed = True
                receipt = _cancelled_receipt(prepared.request)
                return self._record_receipt(prepared, receipt)
            self._executing = True
            self._executed = True
        try:
            try:
                receipt = self._broker.execute(
                    prepared.call,
                    prepared.request,
                    prepared.review,
                    prepared.approval,
                    now=when,
                )
            except (TypeError, ValueError):
                receipt = DesktopActionReceipt(
                    status=DesktopActionStatus.FAILED_BEFORE_ACTION,
                    result_code="desktop_action_not_authorized",
                    action_started=False,
                    target_identity_digest=(
                        prepared.request.target_identity_digest
                    ),
                )
            return self._record_receipt(prepared, receipt)
        finally:
            with self._lock:
                self._executing = False

    def cancel(self) -> bool:
        """Invalidate authority first; queued work cannot start afterward."""

        self._stops.stop()
        with self._lock:
            if self._task_run.terminal:
                return False
            if self._executing:
                return True
            prepared = self._prepared
            if prepared is not None:
                self._reviews.clear(prepared.review)
            self._task_run.cancel()
            self._task_store.sync_run(self._task_run)
            if prepared is not None:
                terminal = _terminal_presentation(
                    prepared,
                    status=TaskActionStatus.CANCELLED_BEFORE_ACTION,
                    result_code="user_cancelled",
                    evidence_digest=_event_digest(
                        {
                            "action_digest": prepared.call.action_digest,
                            "result_code": "user_cancelled",
                        }
                    ),
                )
                self._actions.update_desktop_action(
                    terminal,
                    finish=True,
                )
            return True

    def _approve(self) -> bool:
        with self._lock:
            prepared = self._prepared
            if (
                prepared is None
                or self._approved
                or self._task_run.state
                is not TaskState.WAITING_FOR_APPROVAL
            ):
                return False
            now = float(self._clock())
            if now > prepared.approval.request.expires_at:
                return self.expire_pending(now=now) and False
            self._task_run.approve(
                prepared.approval.request.approval_id,
                prepared.approval.request.action_digest,
                now=now,
            )
            try:
                self._task_store.sync_run(self._task_run)
            except Exception:
                self._fail_approved_action(
                    prepared,
                    "task_store_sync_failed",
                )
                return False
            self._approved = True
            current = self._actions.desktop_action(
                self._task_run.run_id
            )
            if current is None:
                self._fail_approved_action(
                    prepared,
                    "desktop_action_evidence_missing",
                )
                return False
            try:
                self._actions.update_desktop_action(
                    replace(current, status=TaskActionStatus.APPROVED)
                )
            except Exception:
                self._fail_approved_action(
                    prepared,
                    "desktop_action_evidence_failed",
                )
                return False
            return True

    def _reject(self) -> bool:
        self._stops.stop()
        with self._lock:
            prepared = self._prepared
            if (
                prepared is None
                or self._approved
                or self._task_run.state
                is not TaskState.WAITING_FOR_APPROVAL
            ):
                return False
            now = float(self._clock())
            if now > prepared.approval.request.expires_at:
                return self.expire_pending(now=now) and False
            self._reviews.clear(prepared.review)
            self._task_run.reject_approval(
                prepared.approval.request.approval_id,
                prepared.approval.request.action_digest,
                now=now,
            )
            self._task_store.sync_run(self._task_run)
            terminal = _terminal_presentation(
                prepared,
                status=TaskActionStatus.REJECTED,
                result_code="approval_rejected",
                evidence_digest=_event_digest(
                    {
                        "action_digest": prepared.call.action_digest,
                        "result_code": "approval_rejected",
                    }
                ),
            )
            self._actions.update_desktop_action(terminal, finish=True)
            return True

    def _record_receipt(
        self,
        prepared: PreparedDesktopAction,
        receipt: DesktopActionReceipt,
    ) -> ToolResult:
        payload = _canonical_json(receipt.to_payload())
        output_digest = hashlib.sha256(payload).hexdigest()
        evidence_digest = _event_digest(
            {
                "action_digest": prepared.call.action_digest,
                "call_id": prepared.call.call_id,
                "receipt_sha256": output_digest,
                "run_id": prepared.call.run_id,
                "schema": "clicky.desktop-action-evidence.v1",
            }
        )
        successful = receipt.verified
        result = ToolResult(
            result_id=_event_digest(
                {
                    "call_id": prepared.call.call_id,
                    "evidence_digest": evidence_digest,
                    "run_id": prepared.call.run_id,
                    "schema": "clicky.desktop-action-result.v1",
                }
            ),
            call_id=prepared.call.call_id,
            run_id=prepared.call.run_id,
            step_id=prepared.call.step_id,
            status=(
                ToolResultStatus.SUCCEEDED
                if successful
                else ToolResultStatus.FAILED
            ),
            output_digest=output_digest,
            output_bytes=len(payload),
            error_code=None if successful else receipt.result_code,
            verifier_id=self._task_run.spec.verifier_id,
            postcondition_met=successful,
            evidence_digest=evidence_digest,
        )
        with self._lock:
            if self._task_run.terminal:
                return result
            self._task_store.record_tool_result(result)
            if successful:
                self._task_run.complete(result)
            elif (
                receipt.status
                is DesktopActionStatus.CANCELLED_BEFORE_ACTION
            ):
                self._task_run.cancel(receipt.result_code)
            else:
                self._task_run.fail(receipt.result_code)
            self._task_store.sync_run(self._task_run)
            self._stops.finish(self._automation_run)
            terminal = _receipt_presentation(
                prepared,
                receipt,
                evidence_digest=evidence_digest,
            )
            self._actions.update_desktop_action(terminal, finish=True)
        return result

    def _finish_without_action(self, result_code: str) -> None:
        self._stops.stop()
        with self._lock:
            if not self._task_run.terminal:
                self._task_run.fail(result_code)
                self._task_store.sync_run(self._task_run)
            self._actions.finish(self._task_run.run_id)

    def _fail_approved_action(
        self,
        prepared: PreparedDesktopAction,
        result_code: str,
    ) -> None:
        self._stops.stop()
        if not self._task_run.terminal:
            self._task_run.fail(result_code)
            _best_effort_sync(self._task_store, self._task_run)
        current = self._actions.desktop_action(self._task_run.run_id)
        if current is None:
            try:
                self._actions.finish(self._task_run.run_id)
            except ValueError:
                pass
            return
        terminal = _terminal_presentation(
            prepared,
            status=TaskActionStatus.FAILED_BEFORE_ACTION,
            result_code=result_code,
            evidence_digest=_event_digest(
                {
                    "action_digest": prepared.call.action_digest,
                    "result_code": result_code,
                }
            ),
        )
        try:
            self._actions.update_desktop_action(terminal, finish=True)
        except (TypeError, ValueError):
            try:
                self._actions.finish(self._task_run.run_id)
            except ValueError:
                pass


def _pending_presentation(
    prepared: PreparedDesktopAction,
) -> DesktopActionPresentation:
    approval = prepared.approval
    return DesktopActionPresentation(
        run_id=prepared.call.run_id,
        call_id=prepared.call.call_id,
        capability=prepared.call.capability,
        action_label=prepared.request.action.value,
        target_label=approval.target.label,
        target_reference=approval.target.reference,
        target_digest=approval.target.target_digest,
        action_digest=prepared.request.action_digest,
        approval_id=approval.request.approval_id,
        status=TaskActionStatus.AWAITING_APPROVAL,
    )


def _terminal_presentation(
    prepared: PreparedDesktopAction,
    *,
    status: TaskActionStatus,
    result_code: str,
    evidence_digest: str,
) -> DesktopActionPresentation:
    return replace(
        _pending_presentation(prepared),
        status=status,
        result_code=result_code,
        verifier_evidence_digest=evidence_digest,
    )


def _receipt_presentation(
    prepared: PreparedDesktopAction,
    receipt: DesktopActionReceipt,
    *,
    evidence_digest: str,
) -> DesktopActionPresentation:
    status = TaskActionStatus(receipt.status.value)
    values: dict[str, object] = {}
    if receipt.evidence is not None:
        values = {
            "observed_property": receipt.evidence.property_name,
            "observed_before": receipt.evidence.before,
            "observed_after": receipt.evidence.after,
        }
    return replace(
        _pending_presentation(prepared),
        status=status,
        result_code=receipt.result_code,
        verifier_evidence_digest=evidence_digest,
        **values,
    )


def _cancelled_receipt(
    request: DesktopActionRequest,
) -> DesktopActionReceipt:
    return DesktopActionReceipt(
        status=DesktopActionStatus.CANCELLED_BEFORE_ACTION,
        result_code="desktop_action_cancelled",
        action_started=False,
        target_identity_digest=request.target_identity_digest,
    )


def _event_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _best_effort_sync(store: TaskStore, run: TaskRun) -> None:
    try:
        store.sync_run(run)
    except Exception:
        pass


__all__ = [
    "DesktopAutomationTaskController",
    "PreparedDesktopAction",
]
